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

__all__ = [
    'application'
]

from wsgiref.simple_server import make_server
from webob import exc
from jinja2 import Environment, FileSystemLoader
from wtforms import Form
from wtforms.fields import TextField, PasswordField
from wtforms.validators import Optional, Required, EqualTo, Regexp
from yubiauth.config import settings
from yubiauth.util import validate_otp
from yubiauth.util.rest import REST_API, Route, extract_params
from yubiauth.client.rest import session_api, require_session

import os
import logging as log

base_dir = os.path.dirname(__file__)
template_dir = os.path.join(base_dir, 'templates')
env = Environment(loader=FileSystemLoader(template_dir))

YUBIKEY_OTP = r'[cbdefghijklnrtuv]{32,64}'


def redirect(request, target):
    return exc.HTTPSeeOther(location=request.relative_url(target, True))


class LoginForm(Form):
    username = TextField('Username', [Required()])
    password = PasswordField('Password', [Required()])
    yubikey = TextField('YubiKey', [Optional(), Regexp(YUBIKEY_OTP)])


class RegisterForm(Form):
    username = TextField('Username', [Required()])
    password = PasswordField('Password', [Required()])
    verify_password = PasswordField(
        'Repeat password',
        [Required(), EqualTo('password', 'Passwords do not match!')]
    )
    yubikey = TextField('YubiKey', [Optional(), Regexp(YUBIKEY_OTP)])


class ReauthenticateForm(Form):
    legend = "Re-authenticate"
    description = "Please re-authenticate to complete this action"
    password = PasswordField('Password', [Required()])
    otp = TextField('YubiKey OTP', [Optional(), Regexp(YUBIKEY_OTP)])

    def __init__(self, request):
        super(ReauthenticateForm, self).__init__(request.params)
        user = request.environ['yubiauth.user']
        if len(user.yubikeys) == 0:
            del self.otp


class AssignYubikeyForm(Form):
    legend = "Assign new YubiKey"
    yubikey = TextField('New Yubikey OTP', [Regexp(YUBIKEY_OTP)])


class ClientUI(REST_API):
    __routes__ = [
        Route(r'^/$', 'index'),
        Route(r'^/login$', post='login'),
        Route(r'^/register$', post='register'),
        Route(r'^/logout$', 'logout'),
        Route(r'^/status$', 'status'),
        Route(r'^/assign_yubikey$', post='assign_yubikey'),
    ]

    def add_message(self, message, level=None):
        self._messages.append({'text': message, 'level': level})

    def _call_setup(self, request):
        super(ClientUI, self)._call_setup(request)
        self._messages = []

    def session_required(self, request, e):
        return self.render(request, 'session_required')

    def render(self, request, tmpl, **data):
        template = env.get_template('%s.html' % tmpl)
        data['base_url'] = '%s/' % request.script_name
        data['messages'] = self._messages
        return template.render(data)

    def index(self, request, login_form=LoginForm(),
              register_form=RegisterForm()):
        login_form.yubikey.data = None
        if settings['registration']:
            return self.render(request, 'register', login_form=login_form,
                               register_form=register_form)
        else:
            return self.render(request, 'login', login_form=login_form)

    def register(self, request):
        register_form = RegisterForm(request.params)
        if register_form.validate():
            client = request.environ['yubiauth.client']
            username = register_form.username.data
            password = register_form.password.data
            otp = register_form.yubikey.data
            if not otp:
                otp = None
            try:
                user = client.register(username, password, otp)
                return self.render(request, 'created', user=user,
                                   login_form=LoginForm())
            except Exception, e:
                self.add_message('Account registration failed!', 'error')
                log.warn(e)
        return self.index(request, register_form=register_form)

    @extract_params('username?', 'password?', 'yubikey?')
    def login(self, request, username=None, password=None, yubikey=None):
        login_form = LoginForm(request.params)
        if login_form.validate():
            client = request.environ['yubiauth.client']
            try:
                session = client.create_session(username, password, yubikey)
                request.environ['beaker.session'].update(session)
                session.delete()
                return redirect(request, 'status')
            except Exception:
                self.add_message('Login failed!', 'error')
                request.environ['beaker.session'].delete()
        return self.index(request, login_form=login_form)

    @require_session
    def status(self, request):
        user = request.environ['yubiauth.user']
        return self.render(request, 'status', user=user)

    @require_session
    @extract_params('yubikey', 'password?', 'otp?')
    def assign_yubikey(self, request, yubikey, password=None, otp=None):
        assign_form = AssignYubikeyForm(request.params)
        reauthenticate_form = ReauthenticateForm(request)
        user = request.environ['yubiauth.user']
        if assign_form.validate() and reauthenticate_form.validate():
            client = request.environ['yubiauth.client']
            try:
                client.authenticate(user.name, password, otp)
                prefix = yubikey[:-32]
                if not validate_otp(yubikey):
                    self.add_message('Invalid OTP for new YubiKey!')
                if not prefix in user.yubikeys:
                    user.assign_yubikey(prefix)
                return redirect(request, 'status')
            except Exception as e:
                log.info(e)
                self.add_message('Invalid credentials!')

        return self.render(request, 'assign_yubikey', user=user,
                           fieldsets=[assign_form, reauthenticate_form])

    @require_session
    def logout(self, request):
        request.environ['beaker.session'].delete()
        return redirect(request, '')


application = session_api(ClientUI())

if __name__ == '__main__':
    httpd = make_server('localhost', 8080, application)
    httpd.serve_forever()
