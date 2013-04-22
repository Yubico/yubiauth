from webtest import TestApp
from yubiauth.rest import application
from yubiauth.util.model import engine
from yubiauth import create_tables, YubiAuth


create_tables(engine)


app = TestApp(application)


def setup():
    auth = YubiAuth()
    for user in auth.query_users():
        auth.get_user(user['id']).delete()
    auth.commit()
    auth.create_user('user1', 'pass1')
    auth.create_user('user2', 'pass2')
    auth.commit()
    del auth
    # app.post('/yubiauth/core/users',
    #         {'username': 'user1', 'password': 'pass1'})
    # app.post('/yubiauth/core/users',
    #         {'username': 'user2', 'password': 'pass2'})


def test_login_logout():
    sessionId = app.post(
        '/yubiauth/client/login',
        {'username': 'user1', 'password': 'pass1'}
    ).headers['X-YubiAuth-Session']

    # Uses the cookie set by the previous call
    sessionId2 = app.get('/yubiauth/client/status').json['sessionId']

    assert sessionId == sessionId2

    app.get('/yubiauth/client/logout')
    app.get('/yubiauth/client/status', status=400)


def test_update_password():
    app.post(
        '/yubiauth/client/login',
        {'username': 'user1', 'password': 'pass1'}
    )

    app.post('/yubiauth/client/password', {
        'oldpass': 'pass1', 'newpass': 'foobar'})

    assert app.post('/yubiauth/client/authenticate',
                    {'username': 'user1', 'password': 'foobar'}).json

    app.post('/yubiauth/client/password', {
        'oldpass': 'pass1', 'newpass': 'foobar'}, status=400)

    app.post('/yubiauth/client/password', {
        'oldpass': 'foobar', 'newpass': 'pass1'})
