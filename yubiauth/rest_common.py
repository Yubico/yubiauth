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
    'Route',
    'REST_API',
    'json_response',
    'json_error'
]

from webob import exc, Response
from webob.dec import wsgify

import json
import re


def json_response(data, **kwargs):
    return Response(json.dumps(data), content_type='application/json',
                    **kwargs)


def json_error(message, **kwargs):
    if not 'status' in kwargs:
        kwargs['status'] = 400
    return json_response({'error': message}, **kwargs)


class Route(object):
    def __init__(self, pattern_str, controller=None, **kwargs):
        self.pattern = re.compile(pattern_str)

        if controller:
            self.get = controller
            self.post = controller
        if 'get' in kwargs:
            self.get = kwargs['get']
        if 'post' in kwargs:
            self.post = kwargs['post']
        if 'delete' in kwargs:
            self.delete = kwargs['delete']

    def get_controller(self, request, base_path):
        path = request.path[len(base_path) + 1:]
        if path.endswith('/'):
            path = path[:-1]
        match = self.pattern.match(path)

        if match:
            try:
                controller = self.__getattribute__(request.method.lower())
                return controller, match.groups()
            except AttributeError:
                return json_error('Method %s not allowed' % request.method,
                                  status=405)

        return None, None


class REST_API(object):
    __routes__ = []
    __base_path__ = '/'

    @wsgify
    def __call__(self, request):
        if not request.path.startswith(self.__base_path__):
            raise exc.HTTPNotFound

        for route in self.__routes__:
            controller, args = route.get_controller(request,
                                                    self.__base_path__)
            if controller:
                try:
                    self._call_setup(request)
                    return self.__getattribute__(controller)(request, *args)
                finally:
                    self._call_teardown(request)

        raise exc.HTTPNotFound

    def _call_setup(self, request):
        pass

    def _call_teardown(self, request):
        pass
