from webtest import TestApp
from yubiauth.rest import application
from yubiauth.util.model import engine
from yubiauth import create_tables, YubiAuth
from utils import setting
from mock import patch


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
    app.get('/yubiauth/client/logout')


def test_empty_password_login():
    app.post(
        '/yubiauth/client/login',
        {'username': 'user1', 'password': 'pass1'}
    )

    app.post('/yubiauth/client/password', {
        'oldpass': 'pass1', 'newpass': ''})

    assert not app.post('/yubiauth/client/authenticate',
                        {'username': 'user1'}, status=400).json

    with setting(allow_empty=True):
        assert app.post('/yubiauth/client/authenticate',
                        {'username': 'user1'}).json

        app.post('/yubiauth/client/password', {
            'oldpass': '', 'newpass': 'pass1'})

    app.get('/yubiauth/client/logout')


@patch('yubiauth.util.utils.yubico', return_value=True)
def test_authentication_without_username(mock):
    app.post(
        '/yubiauth/client/login',
        {'username': 'user1', 'password': 'pass1'}
    )

    otp = 'c' * 44
    app.post('/yubiauth/client/yubikey', {'yubikey': otp, 'password': 'pass1'})

    assert not app.post('/yubiauth/client/authenticate',
                        {'otp': otp, 'password': 'pass1'},
                        status=400).json

    with setting(yubikey_id=True):
        assert app.post('/yubiauth/client/authenticate',
                        {'otp': otp, 'password': 'pass1'}).json

        assert not app.post('/yubiauth/client/authenticate',
                            {'otp': otp, 'password': 'wrongpass'},
                            status=400).json
        otp = 'd' * 44

        assert not app.post('/yubiauth/client/authenticate',
                            {'otp': otp, 'password': 'pass1'},
                            status=400).json

    app.get('/yubiauth/client/logout')


@patch('yubiauth.util.utils.yubico', return_value=True)
def test_single_factor_login(mock):
    otp = 'c' * 44
    with setting(yubikey_id=True, allow_empty=True):
        assert app.post('/yubiauth/client/authenticate', {'otp': otp}).json
        app.post('/yubiauth/client/login', {'otp': otp})
        status = app.get('/yubiauth/client/status').json
        assert status['username'] == 'user1'
        app.get('/yubiauth/client/logout')

    assert not app.post('/yubiauth/client/authenticate', {'otp': otp},
                        status=400).json
