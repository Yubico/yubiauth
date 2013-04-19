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
from yubiauth.util.rest import REST_API, Route, json_response, json_error
from yubiauth import settings
from yubiauth.client import Client

SESSION_COOKIE = 'YubiAuth-Session'


def require_session(func):
    def inner(self, request, *args, **kwargs):
        if not request.session:
            return json_error('Session required!')
        return func(self, request, *args, **kwargs)
    return inner


class ClientAPI(REST_API):
    __routes__ = [
        Route(r'^login', 'login'),
        Route(r'^logout', 'logout'),
        Route(r'^status', 'status')
    ]

    def _call_setup(self, request):
        request.client = Client()
        request.session = None
        if SESSION_COOKIE in request.cookies:
            print "Session: %s" % request.cookies[SESSION_COOKIE]
            try:
                request.session = request.client.get_session(
                    request.cookies[SESSION_COOKIE])
                print "Got session: %s" % request.session
            except:
                pass

    def _call_teardown(self, request, response):
        if request.session:
            sessionId = request.session.sessionId
            # TODO: Roll session key?
            if SESSION_COOKIE in request.cookies and \
                    request.cookies[SESSION_COOKIE] == sessionId:
                        return
            https = request.scheme == 'https'
            response.set_cookie(SESSION_COOKIE, sessionId,
                                secure=https, httponly=True)
        elif SESSION_COOKIE in request.cookies:
            response.set_cookie(SESSION_COOKIE, None)

    def login(self, request):
        try:
            username = request.params['username']
            password = request.params['password']
        except KeyError:
            return json_error('Missing required parameter(s)')
        otp = request.params['otp'] if 'otp' in request.params else None

        try:
            session = request.client.create_session(username, password, otp)
            request.session = session
            request.client.commit()
            return json_response(True)
        except:
            return json_error('Invalid credentials!')

    @require_session
    def logout(self, request):
        request.session.delete()
        request.session = None
        request.client.commit()
        return json_response(True)

    @require_session
    def status(self, request):
        return json_response(request.session.data)


application = ClientAPI('/%s/client' % settings['rest_path'])

if __name__ == '__main__':
    httpd = make_server('localhost', 8080, application)
    httpd.serve_forever()
