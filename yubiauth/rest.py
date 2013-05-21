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

import os
from wsgiref.simple_server import make_server
from webob import exc
from webob.dec import wsgify

from yubiauth.core.rest import application as core_api
from yubiauth.client.rest import application as client_api
from yubiauth.ui.web import application as client_ui
from yubiauth.util.static import DirectoryApp
from yubiauth.config import settings

STATIC_ASSETS = ['js', 'css', 'img', 'favicon.ico']
STATIC_PATH = settings['rest_path']


class YubiAuthAPI(object):
    def __init__(self):
        self.base = '/%s' % settings['rest_path']
        base_dir = os.path.dirname(__file__)
        static_dir = os.path.join(base_dir, 'static')
        self.static_app = DirectoryApp(static_dir)

        self._apis = [
            core_api,
            client_api,
            client_ui
        ]

    @wsgify
    def __call__(self, request):
        if request.path_info.startswith(self.base):
            path = request.path_info[len(self.base):]
            base = next((x for x in path.split('/') if x), None)
            if base in STATIC_ASSETS:
                trimmed = ''
                while trimmed != self.base:
                    trimmed += '/' + request.path_info_pop()
                return request.get_response(self.static_app)
            for api in self._apis:
                if request.path.startswith(api._base_path):
                    return api(request)

        raise exc.HTTPNotFound


application = YubiAuthAPI()

if __name__ == '__main__':
    httpd = make_server('localhost', 8080, application)
    httpd.serve_forever()
