#!/usr/bin/python
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
from webob import exc, Response
from webob.dec import wsgify

from yubi_auth import YubiAuth
import json
import re

ID_PATTERN = r'\d+'
USERNAME_PATTERN = r'(?=.*[a-zA-Z])[-_a-zA-Z0-9]{3,}'
PASSWORD_PATTERN = r'\S{3,}'
YUBIKEY_PATTERN = r'[cbdefghijklnrtuv]{0,64}'
ATTRIBUTE_KEY_PATTERN = r'[-_a-zA-Z]+'

ID_RE = re.compile(r'^%s$' % ID_PATTERN)


class Route(object):
    def __init__(self, pattern_str, controller=None, get=None, post=None):
        self.pattern = re.compile(pattern_str)

        if controller:
            self.get = controller
            self.post = controller
        if get:
            self.get = get
        if post:
            self.post = post

    def get_controller(self, request):
        path = request.path[1:]
        if path.endswith('/'):
            path = path[:-1]
        match = self.pattern.match(path)

        if match:
            try:
                controller = self.__getattribute__(request.method.lower())
                return controller, match.groups()
            except AttributeError:
                raise exc.HTTPMethodNotAllowed

        return None, None


class WebAPI(object):
    __user__ = r'^users/(%s|%s)' % (ID_PATTERN, USERNAME_PATTERN)
    __attribute__ = __user__ + r'/attributes/(%s)' % ATTRIBUTE_KEY_PATTERN
    __yubikey__ = __user__ + r'/yubikeys/(%s)' % YUBIKEY_PATTERN

    __routes__ = [
        Route(r'^users$', get='list_users', post='create_user'),
        Route(__user__ + r'$', get='show_user'),
        Route(__user__ + r'/reset$', get='reset_password'),
        Route(__user__ + r'/delete$', post='delete_user'),
        Route(__user__ + r'/attributes$', get='list_attributes',
              post='set_attribute'),
        Route(__attribute__ + r'$', get='show_attribute'),
        Route(__attribute__ + r'/delete$', post='unset_attribute'),
        Route(__user__ + r'/yubikeys$', get='list_yubikeys',
              post='bind_yubikey'),
        Route(__yubikey__ + r'$', get='show_yubikey'),
        Route(__yubikey__ + r'/delete$', post='unbind_yubikey'),
        Route(r'^validate$', 'validate'),
        Route(r'^authenticate$', 'authenticate')
    ]

    @wsgify
    def __call__(self, request):
        self.auth = YubiAuth()

        for route in self.__routes__:
            controller, args = route.get_controller(request)
            if controller:
                return self.__getattribute__(controller)(request, *args)

        raise exc.HTTPNotFound

    def _get_user(self, username_or_id):
        if ID_RE.match(username_or_id):
            username_or_id = int(username_or_id)

        try:
            return self.auth.get_user(username_or_id)
        except:
            raise exc.HTTPNotFound

    # Users

    def list_users(self, request):
        return Response(json.dumps(self.auth.query_users()))

    def create_user(self, request):
        try:
            username = request.params['username']
            password = request.params['password']
        except KeyError:
            raise exc.HTTPBadRequest

        user = self.auth.create_user(username, password)

        return exc.HTTPSeeOther(location='/users/%d' % user.id)

    def show_user(self, request, username_or_id):
        user = self._get_user(username_or_id)
        return Response(json.dumps(user.data))

    def reset_password(self, request, username_or_id):
        user = self._get_user(username_or_id)
        try:
            password = request.params['password']
        except KeyError:
            raise exc.HTTPBadRequest

        user.set_password(password)
        self.auth.commit()

        return Response(json.dumps({
            'status': True,
            'action': 'reset_password',
            'user': user.data
        }))

    def delete_user(self, request, username_or_id):
        user = self._get_user(username_or_id)
        user.delete()
        self.auth.commit()

        return Response(json.dumps({
            'status': True,
            'action': 'delete',
            'user': user.data
        }))

    # Attributes

    def list_attributes(self, request, username_or_id):
        user = self._get_user(username_or_id)
        return Response(json.dumps(user.attributes.copy()))

    def show_attribute(self, request, username_or_id, attribute_key):
        user = self._get_user(username_or_id)
        if attribute_key in user.attributes:
            return Response(json.dumps(user.attributes[attribute_key]))
        return Response(json.dumps(None))

    def set_attribute(self, request, username_or_id):
        user = self._get_user(username_or_id)
        try:
            key = request.params['key']
            value = request.params['value']
        except KeyError:
            raise exc.HTTPBadRequest

        user.attributes[key] = value
        self.auth.commit()

        return Response(json.dumps(True))

    def unset_attribute(self, request, username_or_id, attribute_key):
        user = self._get_user(username_or_id)
        del user.attributes[attribute_key]
        self.auth.commit()

        return Response(json.dumps(True))

    # YubiKeys

    def list_yubikeys(self, request, username_or_id):
        user = self._get_user(username_or_id)
        return Response(json.dumps(user.yubikeys.keys()))

    def show_yubikey(self, request, username_or_id, prefix):
        user = self._get_user(username_or_id)
        return Response(json.dumps(user.yubikeys[prefix].data))

    def bind_yubikey(self, request, username_or_id):
        user = self._get_user(username_or_id)
        prefix = request.params['yubikey']
        user.assign_yubikey(prefix)
        self.auth.commit()

        return Response(json.dumps(True))

    def unbind_yubikey(self, request, username_or_id, prefix):
        user = self._get_user(username_or_id)
        del user.yubikeys[prefix]
        self.auth.commit()

        return Response(json.dumps(True))

    # Validate

    def validate(self, request):
        try:
            username = request.params['username']
        except KeyError:
            raise exc.HTTPBadRequest
        user = self.auth.get_user(username)

        if 'password' in request.params:
            password = request.params['password']
            valid_pass = user.validate_password(password)
        else:
            valid_pass = False

        if 'otp' in request.params:
            otp = request.params['otp']
            valid_otp = user.validate_otp(otp)
        else:
            valid_otp = False

        return Response(json.dumps({
            'user': user.data,
            'valid_password': valid_pass,
            'valid_otp': valid_otp
        }))

    def authenticate(self, request):
        try:
            username = request.params['username']
            password = request.params['password']
        except KeyError:
            raise exc.HTTPBadRequest

        otp = request.params['otp'] if 'otp' in request.params else None

        user = self.auth.authenticate(username, password, otp)

        if user:
            return Response(json.dumps(user.data))
        raise exc.HTTPUnauthorized


application = WebAPI()

if __name__ == '__main__':
    httpd = make_server('localhost', 8080, application)
    httpd.serve_forever()
