import base64
import random

import cherrypy
import requests
from mako.template import Template

import sys
sys.path.append('..')

from managers import Master_Password_Manager, Password_Manager
from utils.utils import ZKP, overlap_intervals, \
    Cipher_Authentication, asymmetric_upload_derivation_key, create_nonce, \
    create_get_url

MIN_ITERATIONS_ALLOWED = 200
MAX_ITERATIONS_ALLOWED = 500


class HelperApp(object):
    def __init__(self):
        self.iterations = 0
        self.idp = None
        self.saml_id: str = ''
        self.cipher_auth: Cipher_Authentication = None
        self.password_manager: Password_Manager = None
        self.master_password_manager: Master_Password_Manager = None

    @staticmethod
    def static_contents(path):
        return open(f"static/{path}", 'r').read()

    @cherrypy.expose
    def index(self):
        raise cherrypy.HTTPRedirect('/register')

    @cherrypy.expose
    def error(self, error_id: str):
        errors = {
            'asymmetric_challenge': "The response to the challenge sent to the IdP to authentication with "
                                    "asymmetric keys is not valid. A possible cause for this is the IdP we "
                                    "are contacting is not a trusted one!",
            'zkp_idp_error': "Received error from IdP!",
            'idp_iterations': "The range of allowed iterations received from the IdP is incompatible with the range "
                              "allowed by the local app. A possible cause for this is the IdP we are contacting is not "
                              "a trusted one!",
            'zkp_auth_error': "There was an error on ZKP authentication. This could mean that or the introduced "
                              "password or username are incorrect, or the IdP we are contacting is not a trusted one!"
                              "<br>"
                              "You can access the page '<a href=\"/update_idp_user\">/update_idp_user</a>' to update "
                              "this user's credentials.",
            'load_pass_error': "There was an error on loading the selected user credentials. Access the page "
                               "'<a href=\"/update_idp_credentials\">update_idp_credentials</a>' to update this user's "
                               "local credentials."
        }
        return Template(filename='static/error.html').render(message=errors[error_id])

    def asymmetric_auth(self):
        nonce_to_send = create_nonce()
        ciphered_params = self.cipher_auth.create_response({
            'user_id': self.password_manager.user_id,
            'nonce': nonce_to_send.decode(),
            'username': self.password_manager.idp_username
        })
        response = requests.get(f"{self.idp}/authenticate_asymmetric",
                                params={
                                    'saml_id': self.saml_id,
                                    **ciphered_params
                                })
        if response.status_code != 200:
            print(f"Error status: {response.status_code}")
            self.zkp_auth()
        else:
            response_dict = self.cipher_auth.decipher_response(response.json())

            # verify the authenticity of the IdP
            if ('response' not in response_dict
                    or nonce_to_send != self.password_manager.decrypt(base64.urlsafe_b64decode(response_dict['response']))):
                raise cherrypy.HTTPRedirect(create_get_url(f"http://zkp_helper_app:1080/error",
                                                           params={'error_id': 'asymmetric_challenge'}), 301)
            else:
                nonce = response_dict['nonce'].encode()
                challenge_response = self.password_manager.sign(nonce)
                response = requests.get(f"{self.idp}/authenticate_asymmetric",
                                        params={
                                            'saml_id': self.saml_id,
                                            **self.cipher_auth.create_response({
                                                'response': base64.urlsafe_b64encode(challenge_response).decode()
                                            })
                                        })
                if response.status_code != 200:
                    print(f"Error status: {response.status_code}")
                    self.zkp_auth()

    def zkp_auth(self, restart=False):
        zkp = ZKP(self.password_manager.password)
        data_send = {
            'nonce': '',
        }
        for i in range(self.iterations):
            if i == 0 and restart:
                data_send['restart'] = restart
            else:
                data_send['restart'] = False

            data_send['nonce'] = zkp.create_challenge()
            ciphered_params = self.cipher_auth.create_response({
                **data_send,
                **({
                       'username': self.password_manager.idp_username,
                       'iterations': self.iterations
                   } if zkp.iteration < 2 else {})
            })
            response = requests.get(f"{self.idp}/authenticate", params={
                'saml_id': self.saml_id,
                **ciphered_params
            })

            if response.status_code == 200:
                # verify if response to challenge is correct
                response_dict = self.cipher_auth.decipher_response(response.json())
                idp_response = int(response_dict['response'])
                zkp.verify_challenge_response(idp_response)

                # create both response to the IdP challenge and new challenge to the IdP
                challenge = response_dict['nonce'].encode()
                challenge_response = zkp.response(challenge)
                data_send['response'] = challenge_response
            else:
                print(f"Error received from idp: <{response.status_code}: {response.reason}>")
                raise cherrypy.HTTPRedirect(create_get_url(f"http://zkp_helper_app:1080/error",
                                                           params={'error_id': 'zkp_idp_error'}), 301)

        if zkp.all_ok:
            # save the password locally
            self.password_manager.save_password()

            # create asymmetric credentials
            key = asymmetric_upload_derivation_key(zkp.responses, zkp.iteration, 32)
            asymmetric_cipher_auth = Cipher_Authentication(key=key)

            # generate asymmetric keys
            self.password_manager.generate_keys()
            response = requests.post(f"{self.idp}/save_asymmetric", data={
                'saml_id': self.saml_id,
                **self.cipher_auth.create_response(asymmetric_cipher_auth.create_response({
                    'key': self.password_manager.get_public_key_str()
                }))
            })

            response = asymmetric_cipher_auth.decipher_response(self.cipher_auth.decipher_response(response.json()))
            if 'status' in response and bool(response['status']):
                self.password_manager.save_private_key(user_id=response['user_id'], time_to_live=float(response['ttl']))
        else:
            raise cherrypy.HTTPRedirect(create_get_url(f"http://zkp_helper_app:1080/error",
                                                       params={'error_id': 'zkp_auth_error'}), 301)

    @cherrypy.expose
    def authenticate(self, **kwargs):
        if cherrypy.request.method != 'GET':
            raise cherrypy.HTTPError(405)

        self.idp = base64.urlsafe_b64decode(kwargs['idp']).decode()

        max_iterations = int(kwargs['max_iterations'])
        min_iterations = int(kwargs['min_iterations'])
        if overlap_intervals(MIN_ITERATIONS_ALLOWED, MAX_ITERATIONS_ALLOWED, min_iterations, max_iterations):
            self.iterations = random.randint(max(MIN_ITERATIONS_ALLOWED, min_iterations),
                                             min(MAX_ITERATIONS_ALLOWED, max_iterations))
        else:
            raise cherrypy.HTTPRedirect(create_get_url(f"http://zkp_helper_app:1080/error",
                                                       params={'error_id': 'idp_iterations'}), 301)

        self.saml_id = kwargs['saml_id']

        key = base64.urlsafe_b64decode(kwargs['key'])
        self.cipher_auth = Cipher_Authentication(key=key)

        return Template(filename='static/login.html').render(idp=self.idp)

    @cherrypy.expose
    def login(self, **kwargs):
        if 'deny' in kwargs:
            return Template(filename='static/auth_refused.html').render()
        elif 'allow' in kwargs:
            return Template(filename='static/keychain.html').render(action='auth')

    @cherrypy.expose
    def keychain(self, username: str, password: str, action: str = 'auth'):
        if cherrypy.request.method != 'POST':
            raise cherrypy.HTTPError(405)

        password = password.encode()

        # verify master password
        self.master_password_manager = Master_Password_Manager(username=username, master_password=password)
        if not self.master_password_manager.login():
            return Template(filename='static/keychain.html').render(message='Error: Unsuccessful login!', action=action)

        if action == 'update':
            return Template(filename='static/update.html').render()
        elif action == 'auth':
            return Template(filename='static/select_idp_user.html').render(
                idp=self.idp,
                users=self.master_password_manager.get_users_for_idp(self.idp))
        elif action == 'update_idp':
            raise cherrypy.HTTPRedirect("/update_idp_credentials", 301)
        else:
            raise cherrypy.HTTPError(401)

    @cherrypy.expose
    def select_idp_user(self, idp_user: str = ''):
        if cherrypy.request.method != 'POST':
            raise cherrypy.HTTPError(405)

        if not idp_user or idp_user not in self.master_password_manager.get_users_for_idp(self.idp):
            raise cherrypy.HTTPError(401)

        master_username = self.master_password_manager.username
        master_password = self.master_password_manager.master_password
        self.password_manager = Password_Manager(master_username=master_username, master_password=master_password,
                                                 idp_user=idp_user, idp=self.idp)

        if not self.password_manager.load_password():
            raise cherrypy.HTTPRedirect(create_get_url(f"http://zkp_helper_app:1080/error",
                                                       params={'error_id': 'load_pass_error'}), 301)
        else:
            if not self.password_manager.load_private_key():
                self.zkp_auth()
            else:
                self.asymmetric_auth()

        # end authentication and request the user's identification to the IdP
        raise cherrypy.HTTPRedirect(create_get_url(f"{self.idp}/identity",
                                                   params={'saml_id': self.saml_id}))

    @cherrypy.expose
    def add_idp_user(self, username: str, password: str):
        if cherrypy.request.method != 'POST':
            raise cherrypy.HTTPError(405)

        # update keychain registered idp users
        if not self.master_password_manager.add_idp_user(idp_user=username, idp=self.idp):
            return Template(filename='static/select_idp_user.html').render(
                idp=self.idp,
                users=self.master_password_manager.get_users_for_idp(self.idp),
                message='Error: Error registering the new user!')

        master_username = self.master_password_manager.username
        master_password = self.master_password_manager.master_password
        self.password_manager = Password_Manager(master_username=master_username, master_password=master_password,
                                                 idp_user=username, idp=self.idp)

        self.password_manager.password = password.encode()
        self.zkp_auth()

        raise cherrypy.HTTPRedirect(create_get_url(f"{self.idp}/identity",
                                                   params={'saml_id': self.saml_id}))

    @cherrypy.expose
    def update_idp_credentials(self, **kwargs):
        # verify if the user is authenticated
        if not self.master_password_manager:
            return Template(filename='static/keychain.html').render(action='update_idp')

        if cherrypy.request.method == 'GET':
            return Template(filename='static/update_idp_cred.html').render(idps=self.master_password_manager.idps)
        elif cherrypy.request.method == 'POST':
            if 'idp_user' not in kwargs:
                return Template(filename='static/update_idp_cred.html').render(
                    idps=self.master_password_manager.idps,
                    message="Error: You must select a user to update!")

            indexes = [int(v) for v in kwargs['idp_user'].split('_')]

            selected_idp = list(self.master_password_manager.idps.keys())[indexes[0]]
            selected_user = self.master_password_manager.idps[selected_idp][indexes[1]]

            message = self.update_idp_user_credentials(idp_user=selected_user, idp=selected_idp,
                                                       username=kwargs['username'] if 'username' in kwargs else '',
                                                       password=kwargs['password'] if 'password' in kwargs else '')

            if not message:
                message = 'Success: The user was updated with success'

            return Template(filename='static/update_idp_cred.html').render(
                idps=self.master_password_manager.idps,
                message=message)
        else:
            raise cherrypy.HTTPError(405)

    @cherrypy.expose
    def update_idp_user(self, **kwargs):
        idp_user = self.password_manager.idp_username

        if cherrypy.request.method == 'GET':
            return Template(filename='static/update_idp_user.html').render(idp=self.idp, user=idp_user)
        elif cherrypy.request.method == 'POST':
            message = self.update_idp_user_credentials(idp_user=idp_user, idp=self.idp,
                                                       username=kwargs['username'] if 'username' in kwargs else '',
                                                       password=kwargs['password'] if 'password' in kwargs else '')
            if message:
                return Template(filename='static/update_idp_user.html').render(idp=self.idp, user=idp_user,
                                                                               message=message)

            self.zkp_auth(restart=True)
            raise cherrypy.HTTPRedirect(create_get_url(f"{self.idp}/identity",
                                                       params={'saml_id': self.saml_id}))
        else:
            raise cherrypy.HTTPError(405)

    def update_idp_user_credentials(self, idp_user: str, idp: str,  username: str = '', password: str = '') -> str:
        master_username = self.master_password_manager.username

        # update username
        if username:
            if not self.master_password_manager.update_idp_user(previous_idp_user=idp_user, idp=idp,
                                                                new_idp_user=username):
                return "Error: Error updating the user's username!"
            Password_Manager.update_idp_username(master_username=master_username,
                                                 previous_idp_user=idp_user, idp=idp,
                                                 new_idp_user=username)

            idp_user = username

        # update password
        if password:
            master_password = self.master_password_manager.master_password
            self.password_manager = Password_Manager(master_username=master_username, master_password=master_password,
                                                     idp_user=idp_user, idp=idp)

            if not self.password_manager.update_idp_password(new_password=password.encode()):
                return "Error: Error updating the user's password!"

        return ''

    @cherrypy.expose
    def update(self, **kwargs):
        if cherrypy.request.method == 'GET':
            return Template(filename='static/keychain.html').render(action='update')
        elif cherrypy.request.method == 'POST':
            username = ''
            password = ''
            if 'username' in kwargs and kwargs['username']:
                username = kwargs['username']
            if 'password' in kwargs and kwargs['password']:
                password = kwargs['password'].encode()

            if not self.master_password_manager.update_user(new_username=username, new_password=password):
                return Template(filename='static/update.html').render(message='Error: Error updating the user!')
            return Template(filename='static/update.html').render(message='Success: The user was updated with success')
        else:
            raise cherrypy.HTTPError(405)

    @cherrypy.expose
    def register(self, **kwargs):
        if cherrypy.request.method == 'GET':
            return Template(filename='static/register.html').render()
        elif cherrypy.request.method == 'POST':
            username = kwargs['username']
            master_password = kwargs['password'].encode()

            master_password_manager = Master_Password_Manager(username=username, master_password=master_password)
            if not master_password_manager.register_user():
                return Template(filename='static/register.html').render(
                    message='Error: Error creating the new user!')
            return Template(filename='static/register.html').render(
                message='Success: The user was registered with success')
        else:
            raise cherrypy.HTTPError(405)


if __name__ == '__main__':
    cherrypy.config.update({'server.socket_host': '127.1.2.3',
                            'server.socket_port': 1080})
    cherrypy.quickstart(HelperApp())
