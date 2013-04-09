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

from yubiauth import YubiAuth, settings
import json
import re

ID_PATTERN = r'\d+'
USERNAME_PATTERN = r'(?=.*[a-zA-Z])[-_a-zA-Z0-9]{3,}'
PASSWORD_PATTERN = r'\S{3,}'
YUBIKEY_PATTERN = r'[cbdefghijklnrtuv]{0,64}'
ATTRIBUTE_KEY_PATTERN = r'[-_a-zA-Z0-9]+'

ID_RE = re.compile(r'^%s$' % ID_PATTERN)

BASE_PATH = '/%s' % settings['rest_path']


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

    def get_controller(self, request):
        path = request.path[len(BASE_PATH) + 1:]
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


class WebAPI(object):
    __user__ = r'^users/(%s|%s)' % (ID_PATTERN, USERNAME_PATTERN)
    __user_attribute__ = __user__ + r'/attributes/(%s)' % ATTRIBUTE_KEY_PATTERN
    __user_yubikey__ = __user__ + r'/yubikeys/(%s)' % YUBIKEY_PATTERN
    __yubikey__ = r'^yubikeys/(%s)' % YUBIKEY_PATTERN
    __yubikey_attribute__ = __yubikey__ + r'/attributes/(%s)' %\
        ATTRIBUTE_KEY_PATTERN
    __user_yubikey_attribute__ = __user_yubikey__ + r'/attributes/(%s)' %\
        ATTRIBUTE_KEY_PATTERN

    __routes__ = [
        Route(r'^user$', 'find_user'),
        Route(r'^users$', get='list_users', post='create_user'),
        Route(__user__ + r'$', get='show_user', delete='delete_user'),
        Route(__user__ + r'/reset$', post='reset_password'),
        Route(__user__ + r'/delete$', post='delete_user'),
        Route(__user__ + r'/validate$', 'validate'),
        Route(__user__ + r'/attributes$', get='list_user_attributes',
              post='set_user_attribute'),
        Route(__user_attribute__ + r'$', get='show_user_attribute',
              delete='unset_user_attribute'),
        Route(__user_attribute__ + r'/delete$', post='unset_user_attribute'),
        Route(__user__ + r'/yubikeys$', get='list_yubikeys',
              post='bind_yubikey'),

        Route(__user_yubikey__ + r'$', get='show_yubikey',
              delete='unbind_yubikey'),
        Route(__user_yubikey__ + r'/delete$', post='unbind_yubikey'),
        Route(__user_yubikey__ + r'/attributes$',
              get='list_yubikey_attributes', post='set_yubikey_attribute'),
        Route(__user_yubikey_attribute__ + r'$', get='show_yubikey_attribute',
              delete='unset_yubikey_attribute'),
        Route(__user_yubikey_attribute__ + r'/delete$',
              post='unset_yubikey_attribute'),

        Route(__yubikey__ + r'$', get='show_yubikey', delete='delete_yubikey'),
        Route(__yubikey__ + r'/delete$', post='delete_yubikey'),
        Route(__yubikey__ + r'/attributes$', get='list_yubikey_attributes',
              post='set_yubikey_attribute'),
        Route(__yubikey_attribute__ + r'$', get='show_yubikey_attribute',
              delete='unset_yubikey_attribute'),
        Route(__yubikey_attribute__ + r'/delete$',
              post='unset_yubikey_attribute'),

        Route(r'^authenticate$', 'authenticate')
    ]

    @wsgify
    def __call__(self, request):
        print request.script_name
        self.auth = YubiAuth()

        if not request.path.startswith(BASE_PATH):
            raise exc.HTTPNotFound

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

    def _get_yubikey(self, *args):
        try:
            if len(args) == 1:
                return self.auth.get_yubikey(args[0])
            elif len(args) >= 2:
                user = self._get_user(args[0])
                return user.yubikeys[args[1]]
        except:
            pass

        raise exc.HTTPNotFound

    # Users

    def find_user(self, request):
        users = self.auth.query_users(**request.params)
        if len(users) == 1:
            user_id = users[0]['id']
            user = self.auth.get_user(user_id)
            response = json_response(user.data)
            response.headers.add('Link', '<%s>; rel="canonical"' %
                                 request.relative_url('users/%d' % user_id))
            return response

        raise exc.HTTPNotFound

    def list_users(self, request):
        return json_response(self.auth.query_users(**request.params))

    def create_user(self, request):
        try:
            username = request.params['username']
            password = request.params['password']
        except KeyError:
            return json_error('Missing required parameter(s)')

        try:
            user = self.auth.create_user(username, password)
            url = '%s/users/%d' % (BASE_PATH, user.id)
            return json_response({
                'id': user.id,
                'name': user.name
            }, location=url, status=201)
        except Exception, e:
            return json_error(e.message)

    def show_user(self, request, username_or_id):
        user = self._get_user(username_or_id)
        return json_response(user.data)

    def reset_password(self, request, username_or_id):
        user = self._get_user(username_or_id)
        try:
            password = request.params['password']
        except KeyError:
            return json_error('Missing required parameter(s)')

        user.set_password(password)
        self.auth.commit()

        raise exc.HTTPNoContent

    def delete_user(self, request, username_or_id):
        user = self._get_user(username_or_id)
        user.delete()
        self.auth.commit()

        raise exc.HTTPNoContent

    # Attributes

    def _list_attributes(self, owner):
        return json_response(owner.attributes.copy())

    def list_user_attributes(self, request, username_or_id):
        return self._list_attributes(self._get_user(username_or_id))

    def list_yubikey_attributes(self, request, *args):
        return self._list_attributes(self._get_yubikey(*args))

    def _show_attribute(self, owner, attribute_key):
        if attribute_key in owner.attributes:
            return json_response(owner.attributes[attribute_key])
        return json_response(None)

    def show_user_attribute(self, request, username_or_id, attribute_key):
        return self._show_attribute(self._get_user(username_or_id),
                                    attribute_key)

    def show_yubikey_attribute(self, request, *args):
        attribute_key = args[-1]
        return self._show_attribute(self._get_yubikey(*args[:-1]),
                                    attribute_key)

    def _set_attribute(self, request, owner):
        try:
            key = request.params['key']
            value = request.params['value']
        except KeyError:
            return json_error('Missing required parameter(s)')

        owner.attributes[key] = value
        self.auth.commit()

        raise exc.HTTPNoContent

    def set_user_attribute(self, request, username_or_id):
        return self._set_attribute(request, self._get_user(username_or_id))

    def set_yubikey_attribute(self, request, *args):
        return self._set_attribute(request, self._get_yubikey(*args))

    def _unset_attribute(self, owner, attribute_key):
        if attribute_key in owner.attributes:
            del owner.attributes[attribute_key]
            self.auth.commit()

        raise exc.HTTPNoContent

    def unset_user_attribute(self, request, username_or_id, attribute_key):
        return self._unset_attribute(self._get_user(username_or_id),
                                     attribute_key)

    def unset_yubikey_attribute(self, request, *args):
        attribute_key = args[-1]
        return self._unset_attribute(self._get_yubikey(*args[:-1]),
                                     attribute_key)

    # YubiKeys

    def list_yubikeys(self, request, username_or_id):
        user = self._get_user(username_or_id)
        return json_response(user.yubikeys.keys())

    def show_yubikey(self, request, *args):
        yubikey = self._get_yubikey(*args)
        return json_response(yubikey.data)

    def bind_yubikey(self, request, username_or_id):
        user = self._get_user(username_or_id)
        prefix = request.params['yubikey']
        user.assign_yubikey(prefix)
        self.auth.commit()

        raise exc.HTTPNoContent

    def unbind_yubikey(self, request, username_or_id, prefix):
        user = self._get_user(username_or_id)
        del user.yubikeys[prefix]
        self.auth.commit()

        raise exc.HTTPNoContent

    def delete_yubikey(self, request, prefix):
        yubikey = self._get_yubikey(prefix)
        yubikey.delete()
        self.auth.commit()

        raise exc.HTTPNoContent

    # Validate

    def validate(self, request, username_or_id):
        user = self._get_user(username_or_id)

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

        return json_response({
            'valid_password': valid_pass,
            'valid_otp': valid_otp
        })

    def authenticate(self, request):
        try:
            username = request.params['username']
            password = request.params['password']
        except KeyError:
            return json_error('Missing required parameter(s)')

        otp = request.params['otp'] if 'otp' in request.params else None

        try:
            user = self.auth.authenticate(username, password, otp)
            if user:
                return json_response(user.data)
        except:
            pass

        raise exc.HTTPUnauthorized


application = WebAPI()

if __name__ == '__main__':
    httpd = make_server('localhost', 8080, application)
    httpd.serve_forever()
