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
    'session_api',
    'require_session',
    'ClientAPI',
    'application',
]

from wsgiref.simple_server import make_server
from webob import exc
from webob.dec import wsgify
from beaker.middleware import SessionMiddleware
from yubiauth.client import Client
from yubiauth.util import validate_otp
from yubiauth.util.rest import (REST_API, Route, json_response, json_error,
                                extract_params)
from yubiauth import settings

import logging as log

SESSION_COOKIE = 'YubiAuth-Session'
SESSION_HEADER = 'X-%s' % SESSION_COOKIE
REVOKE_ATTRIBUTE = '_REVOKE'


@wsgify.middleware
def ClientMiddleware(request, app):
    # Allow the session ID to be provided as a header or cookie.
    if not SESSION_COOKIE in request.cookies and \
            SESSION_HEADER in request.headers:
        request.cookies[SESSION_COOKIE] = request.headers[SESSION_HEADER]
    if 'yubiauth.client' in request.environ:
        return app
    try:
        with Client() as client:
            request.environ['yubiauth.client'] = client
            response = request.get_response(app)
    finally:
        del request.environ['yubiauth.client']
    return response


def session_api(app):
    for name, method in app.__class__.__dict__.items():
        if hasattr(method, 'requires_session'):
            setattr(app, name, real_require_session(app, method))

    return ClientMiddleware(SessionMiddleware(app, settings['beaker']))


def require_session(func=None, **kwargs):
    """
    Used to decorate a method on a SessionAPI to ensure that the user has
    a valid UserSession when entering the method. If not, an error will be
    returned.

    To customize the error, override the session_required method of the api,
    or pass an explicit error handler to the decorator.
    """
    error_handler = kwargs.get('error_handler', None)

    def inner(func):
        def placeholder(self, *args, **kwargs):
            raise Exception('require_session requires session_api!')
        placeholder.requires_session = True
        placeholder.orig = func
        placeholder.error_handler = error_handler
        return placeholder
    #If func is not defined, the decorator was called with parentheses.
    return inner(func) if func else inner


def real_require_session(app, placeholder):
    def inner(request, *args, **kwargs):
        try:
            session = request.environ['beaker.session']
            client = request.environ['yubiauth.client']
            user_id = session.get('user_id', None)
            request.environ['yubiauth.user'] = client.auth.get_user(user_id)
        except Exception, e:
            log.warn(e)
            if placeholder.error_handler:
                return placeholder.error_handler(request, e)
            elif hasattr(app, 'session_required'):
                return app.session_required(request, e)
            else:
                raise exc.HTTPBadRequest(detail='Session required!')
        return placeholder.orig(app, request, *args, **kwargs)
    return inner


class ClientAPI(REST_API):
    __routes__ = [
        Route(r'^/login$', 'login'),
        Route(r'^/authenticate$', 'authenticate'),
        Route(r'^/logout$', 'logout'),
        Route(r'^/status$', 'status'),
        Route(r'^/password$', post='change_password'),
        Route(r'^/yubikey$', post='assign_yubikey'),
        Route(r'^/revoke/generate$', post='generate_revocation'),
        Route(r'^/revoke$', post='revoke_yubikey')
    ]

    def session_required(self, request, e):
        return json_error('Session required!')

    @extract_params('username?', 'password?', 'otp?')
    def authenticate(self, request, username=None, password=None, otp=None):
        try:
            client = request.environ['yubiauth.client']
            client.authenticate(username, password, otp)
            return json_response(True)
        except:
            return json_response(False, status=400)

    @extract_params('username?', 'password?', 'otp?')
    def login(self, request, username=None, password=None, otp=None):
        client = request.environ['yubiauth.client']
        try:
            session = client.create_session(username, password, otp)
            request.environ['beaker.session'].update(session)
            session.delete()
            return json_response(True)
        except Exception, e:
            log.warn(e)
            return json_error('Invalid credentials!')

    @require_session
    def logout(self, request):
        request.environ['beaker.session'].delete()
        return json_response(True)

    @require_session
    def status(self, request):
        return json_response(request.environ['beaker.session']._session())

    @require_session
    @extract_params('oldpass', 'newpass', 'otp?')
    def change_password(self, request, oldpass, newpass, otp=None):
        client = request.environ['yubiauth.client']
        user = request.environ['yubiauth.user']
        try:
            client.authenticate(user.name, oldpass, otp)
            user.set_password(newpass)
            return json_response(True)
        except:
            return json_error('Invalid credentials!')

    @require_session
    @extract_params('yubikey', 'password', 'otp?')
    def assign_yubikey(self, request, yubikey, password, otp=None):
        client = request.environ['yubiauth.client']
        user = request.environ['yubiauth.user']
        try:
            client.authenticate(user.name, password, otp)
            prefix = yubikey[:-32]
            if not validate_otp(yubikey):
                return json_error('Invalid OTP for new YubiKey!')
            if not prefix in user.yubikeys:
                user.assign_yubikey(prefix)
            return json_response(True)
        except:
            return json_error('Invalid credentials!')

    @require_session
    @extract_params('otp')
    def generate_revocation(self, request, otp):
        client = request.environ['yubiauth.client']
        user = request.session.user
        if not user.validate_otp(otp):
            return json_error('Invalid credentials!')
        code = client.generate_revocation(otp[:-32])
        return json_response(code)

    @extract_params('code')
    def revoke_yubikey(self, request, code):
        client = request.environ['yubiauth.client']
        try:
            client.revoke(code)
            return json_response(True)
        except:
            return json_error('Invalid code!')


application = session_api(ClientAPI())

if __name__ == '__main__':
    httpd = make_server('localhost', 8080, application)
    httpd.serve_forever()
