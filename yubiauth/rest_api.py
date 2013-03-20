#!/usr/bin/python

from wsgiref.simple_server import make_server
from webob import exc, Response
from webob.dec import wsgify

from yubi_auth import YubiAuth
from model import YubiKey


class WebAPI(object):
    @wsgify
    def __call__(self, request):
        self.auth = YubiAuth()

        if request.path == '/users':
            return self.users(request)
        elif request.path == '/validate':
            return self.validate(request)

        return Response('Index')

    def users(self, request):
        if 'get' in request.params or 'id' in request.params:
            return self.show_user(request)
        if 'create' in request.params:
            return self.create_user(request)
        if 'delete' in request.params:
            return self.delete_user(request)
        if 'reset' in request.params:
            return self.reset_password(request)
        if 'assign' in request.params:
            return self.assign_yubikey(request)
        if 'unassign' in request.params:
            return self.unassign_yubikey(request)

        return self.list_users(request)

    def list_users(self, request):
        return Response("Users:<br/>%s" %
                       ('<br/>'.join(self.auth.list_users())))

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

        public_id = request.params['yubikey']
        if len(public_id) > 32:
            public_id = public_id[:-32]

        user = self.auth.get_user(user_id)
        user.yubikeys.append(YubiKey(public_id))
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
        user.yubikeys.filter(YubiKey.public_id == public_id).delete()
        self.auth.commit()

    def validate(self, request):
        if not 'user' in request.params:
            raise exc.HTTPBadRequest('Missing password!')

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

        return Response("Authenticated: '%s', password: %r, OTP: %r" %
                       (user['name'], valid_pass, valid_otp))


application = WebAPI()

if __name__ == '__main__':
    httpd = make_server('localhost', 8080, application)
    httpd.serve_forever()
