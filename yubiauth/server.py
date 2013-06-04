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
import logging

from yubiauth.core.rest import application as core_rest
from yubiauth.client.rest import application as client_rest
from yubiauth.client.web import application as client_web
from yubiauth.util.static import DirectoryApp, FileApp

STATIC_ASSETS = ['js', 'css', 'img', 'favicon.ico']


class YubiAuthAPI(object):
    def __init__(self):
        base_dir = os.path.dirname(__file__)
        static_dir = os.path.join(base_dir, 'static')
        static_app = DirectoryApp(static_dir)
        favicon_app = FileApp(os.path.join(static_dir, 'favicon.ico'))

        self._apps = {
            'core': core_rest,
            'client': client_rest,
            'ui': client_web,
            'static': static_app,
            'favicon.ico': favicon_app
        }

    @wsgify
    def __call__(self, request):
        base_path = request.environ.get('BASE_PATH', '/')
        if not request.script_name and request.path_info.startswith(base_path):
            request.script_name = base_path
            request.path_info = request.path_info[len(base_path):]

        app_key = request.path_info_pop()
        if app_key in self._apps:
            return request.get_response(self._apps[app_key])

        raise exc.HTTPNotFound


application = YubiAuthAPI()

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)

    httpd = make_server('localhost', 8080, application)
    httpd.serve_forever()
