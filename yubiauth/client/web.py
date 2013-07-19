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
from wtforms.validators import (Optional, Required, EqualTo, Regexp,
                                ValidationError)
from yubiauth.config import settings
from yubiauth.util import validate_otp, MODHEX
from yubiauth.util.rest import REST_API, Route, extract_params
from yubiauth.client.rest import session_api, require_session
from yubiauth.client.controller import requires_otp

import os
import logging
log = logging.getLogger(__name__)

base_dir = os.path.dirname(__file__)
template_dir = os.path.join(base_dir, 'templates')
env = Environment(loader=FileSystemLoader(template_dir))

YUBIKEY_OTP = r'[%s]{32,64}' % MODHEX
YUBIKEY_PREFIX = r'[%s]{2,32}' % MODHEX


def redirect(request, target):
    return exc.HTTPSeeOther(location=request.relative_url(target, True))


def with_yubikey(func):
    def inner(self, request, prefix, *args, **kwargs):
        user = request.environ['yubiauth.user']
        if not prefix in user.yubikeys:
            raise exc.HTTPForbidden(detail='Unauthorized')
        return func(self, request, user.yubikeys[prefix], *args, **kwargs)
    return inner


class LoginForm(Form):
    username = TextField('Username', [Optional() if settings['yubikey_id']
                                      else Required()])
    password = PasswordField('Password', [Optional() if
                                          settings['allow_empty'] else
                                          Required()])
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
    password = PasswordField('Password')
    otp = TextField('YubiKey OTP', [Optional(), Regexp(YUBIKEY_OTP)])

    def __init__(self, request, prefix=None):
        super(ReauthenticateForm, self).__init__(request.params)
        user = request.environ['yubiauth.user']
        self.username = user.name
        self.client = request.environ['yubiauth.client']
        self.prefix = prefix
        if self.prefix:
            self.otp.description = 'OTP from YubiKey with prefix: %s' % prefix
        elif not requires_otp(user):
            del self.otp

    def validate_otp(self, field):
        if self.prefix and self.prefix != field.data[:-32]:
            raise ValidationError('OTP must have prefix %s' % self.prefix)

    def authenticate(self):
        password = self.password.data
        otp = self.data.get('otp', None)
        try:
            self.client.authenticate(self.username, password, otp)
            return True
        except:
            pass
        return False


class AssignYubikeyForm(Form):
    legend = "Assign new YubiKey"
    yubikey = TextField('New Yubikey OTP', [Regexp(YUBIKEY_OTP)])


class ChangePasswordForm(Form):
    legend = "Change password"
    new_password = PasswordField('New Password', [Required()])
    verify_password = PasswordField(
        'Repeat password',
        [Required(), EqualTo('new_password', 'Passwords do not match!')]
    )


class ClientUI(REST_API):
    __yubikey__ = r'/yubikey/(%s)' % YUBIKEY_PREFIX

    __routes__ = [
        Route(r'^/$', 'index'),
        Route(r'^/revoke$', 'revoke'),
        Route(r'^/login$', post='login'),
        Route(r'^/register$', post='register'),
        Route(r'^/logout$', 'logout'),
        Route(r'^/manage$', 'manage'),
        Route(r'^/assign_yubikey$', post='assign_yubikey'),
        Route(r'^/change_password$', 'change_password'),
        Route(r'^/delete_account$', 'delete_account'),
        Route(__yubikey__ + r'$', 'yubikey'),
        Route(__yubikey__ + r'/enable$', 'yubikey_enable'),
        Route(__yubikey__ + r'/disable$', 'yubikey_disable'),
        Route(__yubikey__ + r'/generate$', 'yubikey_generate'),
        Route(__yubikey__ + r'/unassign$', 'yubikey_unassign'),
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
        if 'yubiauth.user' in request.environ:
            data['user'] = request.environ['yubiauth.user']
        return template.render(data)

    def index(self, request, login_form=LoginForm(),
              register_form=RegisterForm()):
        login_form.yubikey.data = None
        if settings['registration']:
            return self.render(request, 'register', login_form=login_form,
                               register_form=register_form)
        else:
            return self.render(request, 'login', login_form=login_form)

    def revoke(self, request):
        if 'revoke' in request.params:
            client = request.environ['yubiauth.client']
            try:
                client.revoke(request.params['revoke'])
                self.add_message('YubiKey revoked!', 'success')
            except:
                self.add_message('Invalid revocation code!', 'error')
        return self.render(request, 'revoke')

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
            except:
                self.add_message('Account registration failed!', 'error')
                log.info('Account registration failed for username=%s',
                         username)
                log.debug('Registration failure:', exc_info=True)
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
                return redirect(request, 'manage')
            except Exception:
                self.add_message('Login failed!', 'error')
                request.environ['beaker.session'].delete()
        return self.index(request, login_form=login_form)

    @require_session
    def manage(self, request):
        can_delete = settings['deletion']
        return self.render(request, 'manage', can_delete=can_delete)

    @require_session
    @extract_params('noauth?')
    def assign_yubikey(self, request, noauth=None):
        assign_form = AssignYubikeyForm(request.params)
        auth_form = ReauthenticateForm(request)
        user = request.environ['yubiauth.user']
        if noauth is not None or not assign_form.validate():
            pass
        elif auth_form.validate() and auth_form.authenticate():
            yubikey = assign_form.yubikey.data
            prefix = yubikey[:-32]
            if not validate_otp(yubikey):
                self.add_message('Invalid OTP for new YubiKey!', 'error')
            if not prefix in user.yubikeys:
                user.assign_yubikey(prefix)
            return redirect(request, 'manage')
        else:
            self.add_message('Invalid credentials!', 'error')

        return self.render(request, 'assign_yubikey',
                           fieldsets=[assign_form, auth_form])

    @require_session
    @with_yubikey
    def yubikey_unassign(self, request, yubikey):
        auth_form = ReauthenticateForm(request)
        if request.method == 'POST' and auth_form.validate():
            if auth_form.authenticate():
                user = request.environ['yubiauth.user']
                del user.yubikeys[yubikey.prefix]
                return redirect(request, 'manage')
            else:
                self.add_message('Invalid credentials!', 'error')

        return self.render(request, 'reauthenticate', yubikey=yubikey,
                           fieldsets=[auth_form], target=request.path_info[1:])

    @require_session
    def change_password(self, request):
        password_form = ChangePasswordForm(request.params)
        auth_form = ReauthenticateForm(request)
        if request.method == 'POST' and password_form.validate() and \
                auth_form.validate():
            if auth_form.authenticate():
                new_password = password_form.new_password.data
                user = request.environ['yubiauth.user']
                user.set_password(new_password)
                return redirect(request, 'manage')
            else:
                self.add_message('Invalid credentials!', 'error')

        return self.render(request, 'change_password',
                           fieldsets=[password_form, auth_form])

    @require_session
    def delete_account(self, request):
        if not settings['deletion']:
            raise exc.HTTPForbidden(details='Account deletion disabled!')
        auth_form = ReauthenticateForm(request)
        if request.method == 'POST' and auth_form.validate():
            if auth_form.authenticate():
                user = request.environ['yubiauth.user']
                user.delete()
                return redirect(request, '')
            else:
                self.add_message('Invalid credentials!', 'error')

        return self.render(request, 'reauthenticate',
                           fieldsets=[auth_form])

    @require_session(error_handler=lambda req, *x: redirect(req, ''))
    def logout(self, request):
        request.environ['beaker.session'].delete()
        return redirect(request, '')

    @require_session
    @with_yubikey
    def yubikey(self, request, yubikey):
        return self.render(request, 'yubikey', yubikey=yubikey)

    @require_session
    @with_yubikey
    def yubikey_set_enabled(self, request, yubikey, enabled):
        auth_form = ReauthenticateForm(request, yubikey.prefix)
        if request.method == 'POST' and auth_form.validate():
            user = request.environ['yubiauth.user']
            # Validate otp manually as the YubiKey might be disabled
            if user.validate_password(auth_form.password.data) and \
                    validate_otp(auth_form.otp.data):
                yubikey.enabled = enabled
                return redirect(request, 'yubikey/%s' % yubikey.prefix)
            else:
                self.add_message('Invalid credentials!', 'error')

        return self.render(request, 'reauthenticate', yubikey=yubikey,
                           fieldsets=[auth_form], target=request.path_info[1:])

    def yubikey_enable(self, *args, **kwargs):
        return self.yubikey_set_enabled(*args, enabled=True, **kwargs)

    def yubikey_disable(self, *args, **kwargs):
        return self.yubikey_set_enabled(*args, enabled=False, **kwargs)

    @require_session
    @with_yubikey
    def yubikey_generate(self, request, yubikey):
        auth_form = ReauthenticateForm(request, yubikey.prefix)
        if request.method == 'POST' and auth_form.validate():
            if auth_form.authenticate():
                client = request.environ['yubiauth.client']
                code = client.generate_revocation(yubikey.prefix)
                return self.render(request, 'revocation_code', yubikey=yubikey,
                                   code=code)
            else:
                self.add_message('Invalid credentials!', 'error')
        return self.render(request, 'reauthenticate', yubikey=yubikey,
                           fieldsets=[auth_form], target=request.path_info[1:])

application = session_api(ClientUI())

if __name__ == '__main__':
    httpd = make_server('localhost', 8080, application)
    httpd.serve_forever()
