#!/usr/bin/python

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
        else:
            self.get = get
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
                print 'method not found!'
                print path
                print self.pattern.pattern
                print request.method.lower()
                print self.__dict__

                raise exc.HTTPMethodNotAllowed

        return None, None


class WebAPI(object):
    __user__ = r'^users/(%s|%s)' % (ID_PATTERN, USERNAME_PATTERN)
    __attribute__ = __user__ + r'/attributes/(%s)' % ATTRIBUTE_KEY_PATTERN
    __yubikey__ = __user__ + r'/yubikeys/(%s)' % YUBIKEY_PATTERN

    __routes__ = [
        Route(r'^users$', get='list_users', post='create_user'),
        Route(__user__ + r'$', 'show_user'),
        Route(__user__ + r'/reset$', 'reset_password'),
        Route(__user__ + r'/delete$', 'delete_user'),
        Route(__user__ + r'/attributes$', get='list_attributes',
              post='set_attribute'),
        Route(__attribute__ + r'$', 'show_attribute'),
        Route(__attribute__ + r'/delete$', 'unset_attribute'),
        Route(__user__ + r'/yubikeys$', get='list_yubikeys',
              post='bind_yubikey'),
        Route(__yubikey__ + r'$', 'show_yubikey'),
        Route(__yubikey__ + r'/delete$', 'unbind_yubikey'),
        Route(r'^validate$', get='validate', post='validate')
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
        username = request.params['username']
        password = request.params['password']

        user = self.auth.create_user(username, password)

        return exc.HTTPSeeOther(location='/users/%d' % user.id)

    def show_user(self, request, username_or_id):
        user = self._get_user(username_or_id)
        return Response(json.dumps(user.data))

    def reset_password(self, request, username_or_id):
        user = self._get_user(username_or_id)
        password = request.params['password']
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
        return Response(json.dumps(user.attributes[attribute_key]))

    def set_attribute(self, request, username_or_id):
        user = self._get_user(username_or_id)
        key = request.params['key']
        value = request.params['value']
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
        username = request.params['user']
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

application = WebAPI()

if __name__ == '__main__':
    httpd = make_server('localhost', 8080, application)
    httpd.serve_forever()
