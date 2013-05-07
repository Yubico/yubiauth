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
from yubiauth.util import validate_otp
from yubiauth.util.rest import (REST_API, Route, json_response, json_error,
                                extract_params)
from yubiauth import settings
from yubiauth.client.controller import Client

import logging as log

SESSION_COOKIE = 'YubiAuth-Session'
SESSION_HEADER = 'X-%s' % SESSION_COOKIE
REVOKE_ATTRIBUTE = '_REVOKE'


def require_session(func):
    def inner(self, request, *args, **kwargs):
        if not request.session:
            return json_error('Session required!')

        return func(self, request, *args, **kwargs)
    return inner


class ClientAPI(REST_API):
    __routes__ = [
        Route(r'^login$', 'login'),
        Route(r'^authenticate$', 'authenticate'),
        Route(r'^logout$', 'logout'),
        Route(r'^status$', 'status'),
        Route(r'^password$', post='change_password'),
        Route(r'^yubikey$', post='assign_yubikey'),
        Route(r'^revoke/generate$', 'generate_revocation'),
        Route(r'^revoke$', post='revoke_yubikey')
    ]

    def _call_setup(self, request):
        request.client = Client()
        request.session = None
        if SESSION_COOKIE in request.cookies:
            sessionId = request.cookies[SESSION_COOKIE]
        elif SESSION_HEADER in request.headers:
            sessionId = request.headers[SESSION_HEADER]

        try:
            request.session = request.client.get_session(sessionId)
        except:
            pass

    def _call_teardown(self, request, response):
        try:
            if request.session:
                sessionId = str(request.session.sessionId)
                # TODO: Roll session key?
                if SESSION_COOKIE in request.cookies and \
                        request.cookies[SESSION_COOKIE] == sessionId:
                    return
                https = request.scheme == 'https'
                response.set_cookie(SESSION_COOKIE, sessionId,
                                    secure=https, httponly=True)
                response.headers[SESSION_HEADER] = sessionId
            elif SESSION_COOKIE in request.cookies:
                response.set_cookie(SESSION_COOKIE, None)
        finally:
            request.client.commit()
            del request.client

    @extract_params('username?', 'password?', 'otp?')
    def authenticate(self, request, username=None, password=None, otp=None):
        try:
            request.client.authenticate(username, password, otp)
            return json_response(True)
        except:
            return json_response(False, status=400)

    @extract_params('username?', 'password?', 'otp?')
    def login(self, request, username=None, password=None, otp=None):
        try:
            session = request.client.create_session(username, password, otp)
            request.session = session
            return json_response(True)
        except Exception as e:
            log.warn(e)
            if request.session:
                request.session.delete()
                request.session = None
            return json_error('Invalid credentials!')

    @require_session
    def logout(self, request):
        request.session.delete()
        request.session = None
        return json_response(True)

    @require_session
    def status(self, request):
        return json_response(request.session.data)

    @require_session
    @extract_params('oldpass', 'newpass', 'otp?')
    def change_password(self, request, oldpass, newpass, otp=None):
        user = request.session.user
        try:
            request.client.authenticate(user.name, oldpass, otp)
            user.set_password(newpass)
            return json_response(True)
        except:
            return json_error('Invalid credentials!')

    @require_session
    @extract_params('yubikey', 'password', 'otp?')
    def assign_yubikey(self, request, yubikey, password, otp=None):
        user = request.session.user
        try:
            request.client.authenticate(user.name, password, otp)
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
        user = request.session.user
        if not user.validate_otp(otp):
            return json_error('Invalid credentials!')
        code = request.client.generate_revocation(otp[:-32])
        return json_response(code)

    @extract_params('code')
    def revoke_yubikey(self, request, code):
        try:
            self.client.revoke(code)
            return json_response(True)
        except:
            return json_error('Invalid code!')


application = ClientAPI('/%s/client' % settings['rest_path'])

if __name__ == '__main__':
    httpd = make_server('localhost', 8080, application)
    httpd.serve_forever()
