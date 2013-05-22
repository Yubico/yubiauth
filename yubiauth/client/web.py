#
# Copyright (c) 2013 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

from wsgiref.simple_server import make_server
from webob import exc
from beaker.middleware import SessionMiddleware
from jinja2 import Environment, FileSystemLoader
from wtforms import Form
from wtforms.fields import TextField, PasswordField
from wtforms.validators import Optional, Required

from yubiauth.util.rest import Route, extract_params
from yubiauth.client.rest import SessionAPI, require_session
from yubiauth import settings

import os

base_dir = os.path.dirname(__file__)
template_dir = os.path.join(base_dir, 'templates')
env = Environment(loader=FileSystemLoader(template_dir))


def redirect(request, target):
    return exc.HTTPSeeOther(location=request.relative_url(target, True))


class LoginForm(Form):
    username = TextField('Username', [Required()])
    password = PasswordField('Password', [Required()])
    yubikey = TextField('YubiKey', [Optional()])


class ClientUI(SessionAPI):
    __routes__ = [
        Route(r'^/login$', 'login'),
        Route(r'^/logout$', 'logout'),
        Route(r'^/status$', 'status'),
    ]

    def add_message(self, message, level=None):
        self._messages.append({'text': message, 'level': level})

    def _call_setup(self, request):
        super(ClientUI, self)._call_setup(request)
        self._messages = []

    def render(self, request, tmpl, **data):
        template = env.get_template('%s.html' % tmpl)
        data['base_url'] = '%s/' % request.script_name
        data['messages'] = self._messages
        return template.render(data)

    @extract_params('username?', 'password?', 'yubikey?')
    def login(self, request, username=None, password=None, yubikey=None):
        form = LoginForm(request.params)
        if request.method == 'POST' and form.validate():
            client = request.environ['yubiauth.client']
            try:
                session = client.create_session(username, password, yubikey)
                request.environ['beaker.session'].update(session)
                session.delete()
                return redirect(request, 'status')
            except Exception:
                self.add_message('Login failed!', 'error')
                request.environ['beaker.session'].delete()

        return self.render(request, 'login', form=form)

    @require_session
    def status(self, request):
        return self.render(request, 'status')

    @require_session
    def logout(self, request):
        request.environ['beaker.session'].delete()
        return redirect(request, 'login')


application = ClientUI()
application = SessionMiddleware(application, settings['beaker'])

if __name__ == '__main__':
    httpd = make_server('localhost', 8080, application)
    httpd.serve_forever()
