#!/usr/bin/python

from wsgiref.simple_server import make_server
from webob import exc, Response
from webob.dec import wsgify

from model import Session, User


def user_by_name(session, name):
    return session.query(User).filter(User.name == name).one()


def user_by_id(session, id):
    return session.query(User).filter(User.id == id).one()


class WebAPI(object):
    @wsgify
    def __call__(self, request):
        self.session = Session()

        if request.path == '/users':
            return self.users(request)

        return Response('Index')

    def users(self, request):
        if 'get' in request.params or 'id' in request.params:
            return self.show_user(request)
        elif 'create' in request.params:
            return self.create_user(request)
        return self.list_users(request)

    def show_user(self, request):
        if 'get' in request.params:
            user = user_by_name(self.session, request.params['get'])
        elif 'id' in request.params:
            try:
                user = user_by_id(self.session, int(request.params['id']))
            except ValueError:
                raise exc.HTTPBadRequest('Invalid ID format!')
        else:
            raise exc.HTTPInternalServerError()
        return Response('User: %s' % (user))

    def create_user(self, request):
        if not 'password' in request.params:
            raise exc.HTTPBadRequest('Missing password!')
        username = request.params['create']
        password = request.params['password']
        user = User(username, password)
        self.session.add(user)
        self.session.commit()

        return Response('Created: %s' % (user))

    def list_users(self, request):
        return Response("Users:<br/>%s" %
                       ('<br/>'.join(
                           [x for x, in self.session.query(User.name).all()]
                       )))

application = WebAPI()

if __name__ == '__main__':
    httpd = make_server('localhost', 8080, application)
    httpd.serve_forever()
