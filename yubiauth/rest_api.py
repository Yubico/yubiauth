#!/usr/bin/python

from wsgiref.simple_server import make_server
from webob import exc, Response
from webob.dec import wsgify

from yubi_auth import YubiAuth
import json


class WebAPI(object):
    """
    Provides a REST API for accessing YubiAuth.
    """

    __routes__ = [
        (lambda p: 'get' in p or 'id' in p, 'show_user'),
        (lambda p: 'create' in p, 'create_user'),
        (lambda p: 'delete' in p, 'delete_user'),
        (lambda p: 'reset' in p, 'reset_password'),
        (lambda p: 'assign' in p, 'assign_yubikey'),
        (lambda p: 'unassign' in p, 'unassign_yubikey'),
        (lambda p: 'key' in p and 'value' in p, 'set_attribute')
    ]

    @wsgify
    def __call__(self, request):
        self.auth = YubiAuth()

        if request.path == '/users':
            return self.users(request)
        elif request.path == '/validate':
            return self.validate(request)

        return Response('Index')

    def users(self, request):
        for route in WebAPI.__routes__:
            if route[0](request.params):
                return getattr(self, route[1])(request)

        return self.list_users(request)

    def list_users(self, request):
        return Response("Users:<br/>%s" %
                        (json.dumps(self.auth.list_users())))

    def show_user(self, request):
        if 'get' in request.params:
            name_or_id = request.params['get']
        elif 'id' in request.params:
            try:
                name_or_id = int(request.params['id'])
            except ValueError:
                raise exc.HTTPBadRequest('Invalid ID format!')
        else:
            raise exc.HTTPInternalServerError()

        user = self.auth.get_user(name_or_id)

        return Response('User: %s' % (user))

    def create_user(self, request):
        if not 'password' in request.params:
            raise exc.HTTPBadRequest('Missing password!')

        username = request.params['create']
        password = request.params['password']
        user = self.auth.create_user(username, password)

        return Response('Created: %r' % (user))

    def delete_user(self, request):
        try:
            user_id = int(request.params['delete'])
        except ValueError:
            raise exc.HTTPBadRequest('Invalid user ID format!')

        user = self.auth.get_user(user_id)
        self.auth.delete_user(user)

        return Response('Deleted user: %s' % (user))

    def reset_password(self, request):
        if not 'password' in request.params:
            raise exc.HTTPBadRequest('Missing password!')
        password = request.params['password']

        try:
            user_id = int(request.params['reset'])
        except ValueError:
            raise exc.HTTPBadRequest('Invalid user ID format!')

        user = self.auth.get_user(user_id)
        user.set_password(password)
        self.auth.commit()

        return Response('Set password for %s' % (user))

    def assign_yubikey(self, request):
        if not 'yubikey' in request.params:
            raise exc.HTTPBadRequest('Missing YubiKey!')

        try:
            user_id = int(request.params['assign'])
        except ValueError:
            raise exc.HTTPBadRequest('Invalid user ID format!')

        yubikey = request.params['yubikey']

        user = self.auth.get_user(user_id)
        user.assign_yubikey(yubikey)
        self.auth.commit()

    def unassign_yubikey(self, request):
        if not 'yubikey' in request.params:
            raise exc.HTTPBadRequest('Missing YubiKey!')

        try:
            user_id = int(request.params['unassign'])
        except ValueError:
            raise exc.HTTPBadRequest('Invalid user ID format!')

        public_id = request.params['yubikey']
        if len(public_id) > 32:
            public_id = public_id[:-32]

        user = self.auth.get_user(user_id)
        del user.yubikeys[public_id]
        self.auth.commit()

    def validate(self, request):
        if not 'user' in request.params:
            raise exc.HTTPBadRequest('Missing user!')

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
            'user': user.data(),
            'valid_password': valid_pass,
            'valid_otp': valid_otp
        }))

    def set_attribute(self, request):
        if not 'user' in request.params:
            raise exc.HTTPBadRequest('Missing user!')

        try:
            user_id = int(request.params['user'])
        except ValueError:
            raise exc.HTTPBadRequest('Invalid user ID format!')

        attr_key = request.params['key']
        attr_value = request.params['value']

        user = self.auth.get_user(user_id)
        user.attributes[attr_key] = attr_value
        self.auth.commit()


application = WebAPI()

if __name__ == '__main__':
    httpd = make_server('localhost', 8080, application)
    httpd.serve_forever()
