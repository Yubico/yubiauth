import json
from webtest import TestApp
from yubiauth.rest_api import application

app = TestApp(application)


# Users


def test_create_user():
    resp = app.post('/users', {'username': 'user1', 'password': 'foo'},
                    status=303)
    user_page = resp.follow()
    user = json.loads(user_page.body)
    assert user['name'] == 'user1'
    assert user['id'] == 1
    app.post('/users', {'username': 'user2', 'password': 'bar'},
             status=303)


def test_get_user_by_id():
    resp = app.get('/users/1', status=200)
    user = json.loads(resp.body)
    assert user['id'] == 1
    assert user['name'] == 'user1'


def test_get_user_by_name():
    resp = app.get('/users/user1')
    user = json.loads(resp.body)
    assert user['id'] == 1
    assert user['name'] == 'user1'


def test_authenticate_user_get():
    resp = app.get('/authenticate?username=user1&password=foo')
    user = json.loads(resp.body)
    assert user['name'] == 'user1'


def test_authenticate_user_post():
    resp = app.post('/authenticate', {'username': 'user1', 'password': 'foo'})
    user = json.loads(resp.body)
    assert user['name'] == 'user1'


def test_reset_password():
    app.get('/authenticate?username=user1&password=foo')
    app.post('/users/1/reset', {'password': 'foobar'})

    app.get('/authenticate?username=user1&password=foo', status=401)
    app.get('/authenticate?username=user1&password=foobar')


def test_create_user_with_existing_username():
    app.post('/users', {'username': 'user1', 'password': 'bar'}, status=500)


def test_authenticate_with_invalid_username():
    app.post('/authenticate', {'username': 'notauser',
                               'password': 'foo'}, status=401)
    app.post('/authenticate', {'username': 'notauser'}, status=400)


def test_authenticate_with_invalid_password():
    app.post('/authenticate', {'username': 'user1',
                               'password': 'wrongpassword'}, status=401)
    app.post('/authenticate', {'username': 'user1'}, status=400)


def test_get_user_by_invalid_username():
    assert app.get('/users/notauser', status=404)


# YubiKeys


PREFIX_1 = 'ccccccccccce'
PREFIX_2 = 'cccccccccccd'
PREFIX_3 = 'cccccccccccf'


def test_bind_yubikeys():
    resp = app.get('/users/1/yubikeys')
    yubikeys = json.loads(resp.body)
    assert len(yubikeys) == 0

    app.post('/users/1/yubikeys', {'yubikey': PREFIX_1})
    resp = app.get('/users/1/yubikeys')
    yubikeys = json.loads(resp.body)
    assert yubikeys == [PREFIX_1]

    app.post('/users/1/yubikeys', {'yubikey': PREFIX_2})
    app.post('/users/2/yubikeys', {'yubikey': PREFIX_2})

    resp = app.get('/users/1/yubikeys')
    yubikeys = json.loads(resp.body)
    assert sorted(yubikeys) == sorted([PREFIX_1, PREFIX_2])

    resp = app.get('/users/1')
    user = json.loads(resp.body)
    assert sorted(user['yubikeys']) == sorted([PREFIX_1, PREFIX_2])

    resp = app.get('/users/2')
    user = json.loads(resp.body)
    assert user['yubikeys'] == [PREFIX_2]


def test_show_yubikey():
    resp = app.get('/users/1/yubikeys/%s' % PREFIX_1)
    yubikey = json.loads(resp.body)
    assert yubikey['enabled']
    assert yubikey['prefix'] == PREFIX_1


def test_show_yubikey_for_wrong_user():
    app.get('/users/2/yubikeys/%s' % PREFIX_1, status=404)


def test_unbind_yubikeys():
    app.post('/users/1/yubikeys/%s/delete' % PREFIX_1)
    resp = app.get('/users/1/yubikeys')
    yubikeys = json.loads(resp.body)
    assert yubikeys == [PREFIX_2]


# Attributes


def test_assign_attributes():
    app.post('/users/1/attributes', {'key': 'attr1', 'value': 'val1'})
    app.post('/users/1/attributes', {'key': 'attr2', 'value': 'val2'})

    resp = app.get('/users/1/attributes')
    attributes = json.loads(resp.body)
    assert attributes['attr1'] == 'val1'
    assert attributes['attr2'] == 'val2'
    assert len(attributes) == 2

    resp = app.get('/users/1')
    user = json.loads(resp.body)
    assert user['attributes'] == attributes


def test_read_attribute():
    resp = app.get('/users/1/attributes/attr1')
    assert json.loads(resp.body) == 'val1'


def test_read_missing_attribute():
    resp = app.get('/users/1/attributes/foo')
    assert not json.loads(resp.body)


def test_overwrite_attributes():
    app.post('/users/1/attributes', {'key': 'attr1', 'value': 'newval'})
    resp = app.get('/users/1/attributes')
    attributes = json.loads(resp.body)

    assert attributes['attr1'] == 'newval'
    assert attributes['attr2'] == 'val2'
    assert len(attributes) == 2


def test_unset_attributes():
    app.post('/users/1/attributes/attr1/delete')
    resp = app.get('/users/1/attributes')
    attributes = json.loads(resp.body)

    assert attributes['attr2'] == 'val2'
    assert len(attributes) == 1

    resp = app.get('/users/1/attributes/attr1')
    assert not json.loads(resp.body)
