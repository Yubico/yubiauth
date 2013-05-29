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
from webob import exc
import re

from yubiauth.core import YubiAuth
from yubiauth.util import MODHEX
from yubiauth.util.rest import (
    REST_API, Route, no_content, json_response, json_error, extract_params)

ID_PATTERN = r'\d+'
USERNAME_PATTERN = r'(?=.*[a-zA-Z])[-_a-zA-Z0-9]{3,}'
PASSWORD_PATTERN = r'\S{3,}'
YUBIKEY_PATTERN = r'[%s]{0,64}' % MODHEX
ATTRIBUTE_KEY_PATTERN = r'[-_a-zA-Z0-9]+'

ID_RE = re.compile(r'^%s$' % ID_PATTERN)


class CoreAPI(REST_API):
    __user__ = r'^/users/(%s|%s)' % (ID_PATTERN, USERNAME_PATTERN)
    __user_attribute__ = __user__ + r'/attributes/(%s)' % ATTRIBUTE_KEY_PATTERN
    __user_yubikey__ = __user__ + r'/yubikeys/(%s)' % YUBIKEY_PATTERN
    __yubikey__ = r'^/yubikeys/(%s)' % YUBIKEY_PATTERN
    __yubikey_attribute__ = __yubikey__ + r'/attributes/(%s)' %\
        ATTRIBUTE_KEY_PATTERN
    __user_yubikey_attribute__ = __user_yubikey__ + r'/attributes/(%s)' %\
        ATTRIBUTE_KEY_PATTERN

    __routes__ = [
        Route(r'^/user$', 'find_user'),
        Route(r'^/users$', get='list_users', post='create_user'),
        Route(__user__ + r'$', get='show_user', delete='delete_user'),
        Route(__user__ + r'/reset$', post='reset_password'),
        Route(__user__ + r'/rename$', post='rename_user'),
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
              post='unset_yubikey_attribute')
    ]

    def _call_setup(self, request):
        request.auth = YubiAuth()

    def _call_teardown(self, request, response):
        request.auth.commit()
        del request.auth

    def _get_user(self, request, username_or_id):
        if ID_RE.match(username_or_id):
            username_or_id = int(username_or_id)

        try:
            return request.auth.get_user(username_or_id)
        except:
            raise exc.HTTPNotFound

    def _get_yubikey(self, request, *args):
        try:
            if len(args) == 1:
                return request.auth.get_yubikey(args[0])
            elif len(args) >= 2:
                user = self._get_user(request, args[0])
                return user.yubikeys[args[1]]
        except:
            pass

        raise exc.HTTPNotFound

    # Users

    def find_user(self, request):
        users = request.auth.query_users(**request.params)
        if len(users) == 1:
            user_id = users[0]['id']
            user = request.auth.get_user(user_id)
            response = json_response(user.data)
            response.headers.add('Link', '<%s>; rel="canonical"' %
                                 request.relative_url('users/%d' % user_id))
            return response

        raise exc.HTTPNotFound

    def list_users(self, request):
        return json_response(request.auth.query_users(**request.params))

    @extract_params('username', 'password')
    def create_user(self, request, username, password):
        try:
            user = request.auth.create_user(username, password)
            request.auth.commit()
            url = '%s/users/%d' % (request.script_name, user.id)
            return json_response({
                'id': user.id,
                'name': user.name
            }, location=url, status=201)
        except Exception, e:
            return json_error(e.message)

    def show_user(self, request, username_or_id):
        user = self._get_user(request, username_or_id)
        return json_response(user.data)

    @extract_params('password')
    def reset_password(self, request, username_or_id, password):
        user = self._get_user(request, username_or_id)
        user.set_password(password)

        return no_content()

    @extract_params('username')
    def rename_user(self, request, username_or_id, username):
        user = self._get_user(request, username_or_id)
        try:
            request.auth.get_user(username)
            return json_error('User "%s" already exists!' % username)
        except:
            user.name = username

        return no_content()

    def delete_user(self, request, username_or_id):
        user = self._get_user(request, username_or_id)
        user.delete()

        return no_content()

    # Attributes

    def _list_attributes(self, owner):
        return json_response(owner.attributes.copy())

    def list_user_attributes(self, request, username_or_id):
        return self._list_attributes(self._get_user(request, username_or_id))

    def list_yubikey_attributes(self, request, *args):
        return self._list_attributes(self._get_yubikey(request, *args))

    def _show_attribute(self, owner, attribute_key):
        if attribute_key in owner.attributes:
            return json_response(owner.attributes[attribute_key])
        return json_response(None)

    def show_user_attribute(self, request, username_or_id, attribute_key):
        return self._show_attribute(self._get_user(request, username_or_id),
                                    attribute_key)

    def show_yubikey_attribute(self, request, *args):
        attribute_key = args[-1]
        return self._show_attribute(self._get_yubikey(request, *args[:-1]),
                                    attribute_key)

    @extract_params('key', 'value')
    def _set_attribute(self, request, owner, key, value):
        owner.attributes[key] = value

        return no_content()

    def set_user_attribute(self, request, username_or_id):
        return self._set_attribute(request, self._get_user(request,
                                                           username_or_id))

    def set_yubikey_attribute(self, request, *args):
        return self._set_attribute(request, self._get_yubikey(request, *args))

    def _unset_attribute(self, owner, attribute_key):
        if attribute_key in owner.attributes:
            del owner.attributes[attribute_key]

        return no_content()

    def unset_user_attribute(self, request, username_or_id, attribute_key):
        return self._unset_attribute(self._get_user(request, username_or_id),
                                     attribute_key)

    def unset_yubikey_attribute(self, request, *args):
        attribute_key = args[-1]
        return self._unset_attribute(self._get_yubikey(request, *args[:-1]),
                                     attribute_key)

    # YubiKeys

    def list_yubikeys(self, request, username_or_id):
        user = self._get_user(request, username_or_id)
        return json_response(user.yubikeys.keys())

    def show_yubikey(self, request, *args):
        yubikey = self._get_yubikey(request, *args)
        return json_response(yubikey.data)

    @extract_params('yubikey')
    def bind_yubikey(self, request, username_or_id, yubikey):
        user = self._get_user(request, username_or_id)
        user.assign_yubikey(yubikey)

        return no_content()

    def unbind_yubikey(self, request, username_or_id, prefix):
        user = self._get_user(request, username_or_id)
        del user.yubikeys[prefix]

        return no_content()

    def delete_yubikey(self, request, prefix):
        yubikey = self._get_yubikey(request, prefix)
        yubikey.delete()

        return no_content()

    # Validate

    def validate(self, request, username_or_id):
        user = self._get_user(request, username_or_id)

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


application = CoreAPI()


if __name__ == '__main__':
    httpd = make_server('localhost', 8080, application)
    httpd.serve_forever()
