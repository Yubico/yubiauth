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
    'json_error',
    'extract_params'
]

from webob import exc, Response, Request
from webob.dec import wsgify

import json
import re


def no_content():
    return exc.HTTPNoContent()
    #return Response(status=204, content_type=None)


def json_response(data, **kwargs):
    return Response(json.dumps(data), content_type='application/json',
                    **kwargs)


def json_error(message, **kwargs):
    if not 'status' in kwargs:
        kwargs['status'] = 400
    return json_response({'error': message}, **kwargs)


class extract_params(object):
    """
    Decorator for extracting request parameters into kwargs.
    Suffix the parameter with a question mark (?) to make it optional.
    """
    def __init__(self, *params):
        self.params = params

    def _find_request(self, args):
            for arg in args:
                if type(arg) == Request:
                    self.request = arg
                    return True
            return False

    def _extract_params(self):
        self.extracted = {}
        for param in self.params:
            if param.endswith('?'):
                param = param[:-1]
            elif not param in self.request.params:
                return False
            if param in self.request.params and not param in self.extracted:
                self.extracted[param] = self.request.params[param]
        return True

    def __call__(self, func):
        def inner(*args, **kwargs):
            if not self._find_request(args):
                return json_error('Unable to find request!', status=500)

            if not self._extract_params():
                return json_error('Missing required parameter(s)!')

            kwargs.update(self.extracted)
            return func(*args, **kwargs)
        return inner


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

    def get_controller(self, request):
        match = self.pattern.match(request.path_info)

        if match:
            try:
                controller = self.__getattribute__(request.method.lower())
                return controller, match.groups()
            except AttributeError:
                return json_error('Method %s not allowed' % request.method,
                                  status=405), None

        return None, None


class REST_API(object):
    __routes__ = []

    @wsgify
    def __call__(self, request, *args, **kwargs):
        for route in self.__routes__:
            controller, sub_args = route.get_controller(request)
            if controller:
                if isinstance(controller, Response):
                    return controller
                self._call_setup(request)
                args += sub_args
                response = None
                try:
                    controller = self.__getattribute__(controller)
                    response = controller(request, *args, **kwargs)
                finally:
                    self._call_teardown(request, response)
                return response

        raise exc.HTTPNotFound

    def _call_setup(self, request):
        pass

    def _call_teardown(self, request, response):
        pass
