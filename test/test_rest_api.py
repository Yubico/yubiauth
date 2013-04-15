from webtest import TestApp
from yubiauth.model import engine, create_db
from yubiauth.rest_api import application

create_db(engine)

app = TestApp(application)


# Users


def test_create_user():
    resp = app.post(
        '/yubiauth/users',
        {'username': 'user1', 'password': 'foo'},
        status=201
    )
    user = app.get(resp.location).json
    assert user['name'] == 'user1'
    assert user['id'] == 1
    app.post('/yubiauth/users', {'username': 'user2', 'password': 'bar'},
             status=201)
    app.post('/yubiauth/users', {'username': 'user3', 'password': 'baz'},
             status=201)

    assert len(app.get('/yubiauth/users').json) == 3


def test_delete_user_by_id():
    resp = app.post(
        '/yubiauth/users',
        {'username': 'redshirt', 'password': 'llap'},
        status=201
    )
    id = app.get(resp.location).json['id']

    app.delete('/yubiauth/users/%d' % id)
    app.get('/yubiauth/users/%d' % id, status=404)


def test_delete_user_by_name():
    resp = app.post(
        '/yubiauth/users',
        {'username': 'redshirt', 'password': 'llap'},
        status=201
    )
    name = app.get(resp.location).json['name']

    app.delete('/yubiauth/users/%s' % name.encode('ascii'))
    app.get('/yubiauth/users/%s' % name, status=404)


def test_delete_user_by_post():
    resp = app.post(
        '/yubiauth/users',
        {'username': 'redshirt', 'password': 'llap'},
        status=201
    )
    id = app.get(resp.location).json['id']

    app.post('/yubiauth/users/%d/delete' % id)
    app.get('/yubiauth/users/%d' % id, status=404)


def test_get_user_by_id():
    user = app.get('/yubiauth/users/1', status=200).json
    assert user['id'] == 1
    assert user['name'] == 'user1'


def test_get_user_by_name():
    user = app.get('/yubiauth/users/user1').json
    assert user['id'] == 1
    assert user['name'] == 'user1'


def test_authenticate_user_get():
    user = app.get('/yubiauth/authenticate?username=user1&password=foo').json
    assert user['name'] == 'user1'


def test_authenticate_user_post():
    user = app.post(
        '/yubiauth/authenticate',
        {'username': 'user1', 'password': 'foo'}
    ).json
    assert user['name'] == 'user1'


def test_reset_password():
    app.get('/yubiauth/authenticate?username=user1&password=foo')
    app.post('/yubiauth/users/1/reset', {'password': 'foobar'})

    app.get('/yubiauth/authenticate?username=user1&password=foo', status=401)
    app.get('/yubiauth/authenticate?username=user1&password=foobar')


def test_create_user_with_existing_username():
    app.post('/yubiauth/users', {
             'username': 'user1', 'password': 'bar'}, status=400)


def test_authenticate_with_invalid_username():
    app.post('/yubiauth/authenticate', {'username': 'notauser',
                                        'password': 'foo'}, status=401)
    app.post('/yubiauth/authenticate', {'username': 'notauser'}, status=400)


def test_authenticate_with_invalid_password():
    app.post(
        '/yubiauth/authenticate',
        {'username': 'user1', 'password': 'wrongpassword'},
        status=401
    )
    app.post('/yubiauth/authenticate', {'username': 'user1'}, status=400)


def test_get_user_by_invalid_username():
    assert app.get('/yubiauth/users/notauser', status=404)


# YubiKeys


PREFIX_1 = 'ccccccccccce'
PREFIX_2 = 'cccccccccccd'
PREFIX_3 = 'cccccccccccf'


def test_bind_yubikeys():
    yubikeys = app.get('/yubiauth/users/1/yubikeys').json
    assert len(yubikeys) == 0

    app.post('/yubiauth/users/1/yubikeys', {'yubikey': PREFIX_1})
    yubikeys = app.get('/yubiauth/users/1/yubikeys').json
    assert yubikeys == [PREFIX_1]

    app.post('/yubiauth/users/1/yubikeys', {'yubikey': PREFIX_2})
    app.post('/yubiauth/users/2/yubikeys', {'yubikey': PREFIX_2})

    yubikeys = app.get('/yubiauth/users/1/yubikeys').json
    assert sorted(yubikeys) == sorted([PREFIX_1, PREFIX_2])

    user = app.get('/yubiauth/users/1').json
    assert sorted(user['yubikeys']) == sorted([PREFIX_1, PREFIX_2])

    user = app.get('/yubiauth/users/2').json
    assert user['yubikeys'] == [PREFIX_2]


def test_show_yubikey():
    yubikey = app.get('/yubiauth/users/1/yubikeys/%s' % PREFIX_1).json
    assert yubikey['enabled']
    assert yubikey['prefix'] == PREFIX_1


def test_show_yubikey_for_wrong_user():
    app.get('/yubiauth/users/2/yubikeys/%s' % PREFIX_1, status=404)


def test_unbind_yubikeys():
    app.delete('/yubiauth/users/1/yubikeys/%s' % PREFIX_1)
    yubikeys = app.get('/yubiauth/users/1/yubikeys').json
    assert yubikeys == [PREFIX_2]


def test_authenticate_without_yubikey():
    app.get('/yubiauth/authenticate?username=user2&password=bar', status=401)


def test_find_user_by_yubikey():
    app.post('/yubiauth/users/2/yubikeys', {'yubikey': PREFIX_3})

    user = app.get('/yubiauth/user?yubikey=%s' % PREFIX_3).json
    assert user['id'] == 2
    assert PREFIX_3 in user['yubikeys']


# Attributes


def test_assign_attributes():
    app.post('/yubiauth/users/1/attributes', {'key': 'attr1', 'value': 'val1'})
    app.post('/yubiauth/users/1/attributes', {'key': 'attr2', 'value': 'val2'})

    attributes = app.get('/yubiauth/users/1/attributes').json
    assert attributes['attr1'] == 'val1'
    assert attributes['attr2'] == 'val2'
    assert len(attributes) == 2

    user = app.get('/yubiauth/users/1').json
    assert user['attributes'] == attributes


def test_find_user_by_attribute():
    user1 = app.get('/yubiauth/user?attr1=val1&attr2=val2').json
    assert user1['id'] == 1

    user2 = app.post('/yubiauth/user', {'attr1': 'val1', 'attr2': 'val2'}).json
    assert user1 == user2


def test_read_attribute():
    value = app.get('/yubiauth/users/1/attributes/attr1').json
    assert value == 'val1'


def test_read_missing_attribute():
    value = app.get('/yubiauth/users/1/attributes/foo').json
    assert not value


def test_overwrite_attributes():
    app.post('/yubiauth/users/1/attributes', {
             'key': 'attr1', 'value': 'newval'})
    attributes = app.get('/yubiauth/users/1/attributes').json

    assert attributes['attr1'] == 'newval'
    assert attributes['attr2'] == 'val2'
    assert len(attributes) == 2


def test_unset_attributes():
    app.delete('/yubiauth/users/1/attributes/attr1')
    attributes = app.get('/yubiauth/users/1/attributes').json

    assert attributes['attr2'] == 'val2'
    assert len(attributes) == 1

    value = app.get('/yubiauth/users/1/attributes/attr1').json
    assert not value


def _basic_attribute_test(base_url):
    values = {
        'attr1': 'foo',
        'attr2': 'bar',
        'attr3': 'baz',
    }

    for key, value in values.items():
        app.post(base_url, {'key': key, 'value': value})
        assert app.get('%s/%s' % (base_url, key)).json == value

    app.delete('%s/attr2' % (base_url))
    assert not app.get('%s/attr2' % base_url).json

    app.post(base_url, {'key': 'attr3', 'value': 'newval'})
    assert app.get('%s/attr3' % base_url).json == 'newval'

    del values['attr2']
    values['attr3'] = 'newval'
    assert app.get(base_url).json == values


def test_user_attributes():
    _basic_attribute_test('/yubiauth/users/1/attributes')
    _basic_attribute_test('/yubiauth/users/2/attributes')


def test_yubikey_attributes():
    _basic_attribute_test('/yubiauth/yubikeys/%s/attributes' % PREFIX_1)
    _basic_attribute_test(
        '/yubiauth/users/2/yubikeys/%s/attributes' % PREFIX_2)
