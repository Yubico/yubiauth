from webtest import TestApp
from yubiauth.client.rest import application, SESSION_COOKIE, SESSION_HEADER
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


def test_login_logout():
    app.post(
        '/login',
        {'username': 'user1', 'password': 'pass1'}
    )

    # Uses the cookie set by the previous call
    username = app.get('/status').json['username']
    assert username == 'user1'

    app.get('/logout')
    app.get('/status', status=400)


def test_header_authentication():
    app.post(
        '/login',
        {'username': 'user1', 'password': 'pass1'}
    )

    session_id = app.cookies[SESSION_COOKIE]
    #Clear the cookie
    app.reset()
    app.get('/status', status=400)

    headers = {SESSION_HEADER: session_id}

    username = app.get('/status', headers=headers).json['username']
    assert username == 'user1'

    app.reset()
    app.get('/logout', headers=headers)
    app.reset()
    app.get('/status', headers=headers, status=400)


def test_update_password():
    app.post(
        '/login',
        {'username': 'user1', 'password': 'pass1'}
    )

    app.post('/password', {
        'oldpass': 'pass1', 'newpass': 'foobar'})

    assert app.post('/authenticate',
                    {'username': 'user1', 'password': 'foobar'}).json

    app.post('/password', {
        'oldpass': 'pass1', 'newpass': 'foobar'}, status=400)

    app.post('/password', {
        'oldpass': 'foobar', 'newpass': 'pass1'})
    app.get('/logout')


def test_empty_password_login():
    app.post(
        '/login',
        {'username': 'user1', 'password': 'pass1'}
    )

    app.post('/password', {
        'oldpass': 'pass1', 'newpass': ''})

    assert not app.post('/authenticate',
                        {'username': 'user1'}, status=400).json

    with setting(allow_empty=True):
        assert app.post('/authenticate',
                        {'username': 'user1'}).json

        app.post('/password', {
            'oldpass': '', 'newpass': 'pass1'})

    app.get('/logout')


@patch('yubiauth.util.utils.yubico', return_value=True)
def test_authentication_without_username(mock):
    app.post(
        '/login',
        {'username': 'user1', 'password': 'pass1'}
    )

    otp = 'c' * 44
    app.post('/yubikey', {'yubikey': otp, 'password': 'pass1'})

    assert not app.post('/authenticate',
                        {'otp': otp, 'password': 'pass1'},
                        status=400).json

    with setting(yubikey_id=True):
        assert app.post('/authenticate',
                        {'otp': otp, 'password': 'pass1'}).json

        assert not app.post('/authenticate',
                            {'otp': otp, 'password': 'wrongpass'},
                            status=400).json
        otp = 'd' * 44

        assert not app.post('/authenticate',
                            {'otp': otp, 'password': 'pass1'},
                            status=400).json

    app.get('/logout')


@patch('yubiauth.util.utils.yubico', return_value=True)
def test_single_factor_login(mock):
    otp = 'c' * 44
    with setting(yubikey_id=True, allow_empty=True):
        assert app.post('/authenticate', {'otp': otp}).json
        app.post('/login', {'otp': otp})
        status = app.get('/status').json
        assert status['username'] == 'user1'
        app.get('/logout')

    assert not app.post('/authenticate', {'otp': otp},
                        status=400).json
