import requests
import uuid

import cherrypy
from mako.template import Template


class HelperApp(object):
	@staticmethod
	def static_contents(path):
		return open(f"static/{path}", 'r').read()

	@cherrypy.expose
	def index(self):
		raise cherrypy.HTTPRedirect('/authenticate')

	@cherrypy.expose
	def authenticate(self, **kwargs):
		if cherrypy.request.method == 'GET':
			return Template(filename='static/authenticate.html').render(id=kwargs['id'])
		elif cherrypy.request.method == 'POST':
			nonce = str(uuid.uuid4()).encode()
			response = requests.get(f"http://localhost:8082/authenticate", params={
				'nonce': nonce,
				'id': kwargs['id'],
				'username': kwargs['username']
			})
			# TODO -> ZKP
			# after the ZKP
			raise cherrypy.HTTPRedirect(f"http://localhost:8082/identity?id={kwargs['id']}")


if __name__ == '__main__':
	cherrypy.config.update({'server.socket_host': '127.1.2.3',
	                        'server.socket_port': 1080})
	cherrypy.quickstart(HelperApp())
