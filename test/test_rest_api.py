from webtest import TestApp
from yubiauth.core.rest import application
from yubiauth.util.model import engine
from yubiauth import create_tables, YubiAuth


create_tables(engine)

app = TestApp(application)


# Users
def setup():
    auth = YubiAuth()
    for user in auth.query_users():
        auth.get_user(user['id']).delete()
    auth.commit()
    del auth


def test_create_user():
    resp = app.post(
        '/users',
        {'username': 'user1', 'password': 'foo'},
        status=201
    )
    user = app.get(resp.location).json
    assert user['name'] == 'user1'
    assert user['id'] == 1
    app.post('/users', {'username': 'user2', 'password': 'bar'},
             status=201)
    app.post('/users', {'username': 'user3', 'password': 'baz'},
             status=201)

    assert len(app.get('/users').json) == 3


def test_delete_user_by_id():
    resp = app.post(
        '/users',
        {'username': 'redshirt', 'password': 'llap'},
        status=201
    )
    id = app.get(resp.location).json['id']

    app.delete('/users/%d' % id)
    app.get('/users/%d' % id, status=404)


def test_delete_user_by_name():
    resp = app.post(
        '/users',
        {'username': 'redshirt', 'password': 'llap'},
        status=201
    )
    name = app.get(resp.location).json['name']

    app.delete('/users/%s' % name.encode('ascii'))
    app.get('/users/%s' % name, status=404)


def test_delete_user_by_post():
    resp = app.post(
        '/users',
        {'username': 'redshirt', 'password': 'llap'},
        status=201
    )
    id = app.get(resp.location).json['id']

    app.post('/users/%d/delete' % id)
    app.get('/users/%d' % id, status=404)


def test_get_user_by_id():
    user = app.get('/users/1', status=200).json
    assert user['id'] == 1
    assert user['name'] == 'user1'


def test_get_user_by_name():
    user = app.get('/users/user1').json
    assert user['id'] == 1
    assert user['name'] == 'user1'


def test_validate_password_get():
    status = app.get('/users/user1/validate?password=foo'
                     ).json
    assert status['valid_password']


def test_validate_password_post():
    status = app.post(
        '/users/user1/validate',
        {'password': 'foo'}
    ).json
    assert status['valid_password']


def test_reset_password():
    status = app.get('/users/user1/validate?password=foo').json
    assert status['valid_password']
    app.post('/users/1/reset', {'password': 'foobar'})

    status = app.get('/users/user1/validate?password=foo').json
    assert not status['valid_password']

    status = app.get('/users/user1/validate?password=foobar'
                     ).json
    assert status['valid_password']


def test_rename_user():
    app.post('/users/user1/rename', {'username': 'user2'},
             status=400)
    app.post('/users/user1/rename', {'username': 'new_user'})
    app.get('/users/user1', status=404)
    app.get('/users/new_user')
    app.post('/users/new_user/rename', {'username': 'user1'})
    app.get('/users/user1')
    app.get('/users/new_user', status=404)


def test_create_user_with_existing_username():
    app.post('/users', {
             'username': 'user1', 'password': 'bar'}, status=400)


def test_validate_with_invalid_username():
    app.post('/users/notauser/validate',
             {'password': 'foo'}, status=404)

    app.post('/users/notauser/validate', status=404)


def test_validate_with_invalid_password():
    status = app.post('/users/user1/validate',
                      {'password': 'wrongpassword'}).json
    assert not status['valid_password']

    status = app.post('/users/user1/validate').json
    assert not status['valid_password']


def test_get_user_by_invalid_username():
    assert app.get('/users/notauser', status=404)


# YubiKeys


PREFIX_1 = 'ccccccccccce'
PREFIX_2 = 'cccccccccccd'
PREFIX_3 = 'cccccccccccf'


def test_bind_yubikeys():
    yubikeys = app.get('/users/1/yubikeys').json
    assert len(yubikeys) == 0

    app.post('/users/1/yubikeys', {'yubikey': PREFIX_1})
    yubikeys = app.get('/users/1/yubikeys').json
    assert yubikeys == [PREFIX_1]

    app.post('/users/1/yubikeys', {'yubikey': PREFIX_2})
    app.post('/users/2/yubikeys', {'yubikey': PREFIX_2})

    yubikeys = app.get('/users/1/yubikeys').json
    assert sorted(yubikeys) == sorted([PREFIX_1, PREFIX_2])

    user = app.get('/users/1').json
    assert sorted(user['yubikeys']) == sorted([PREFIX_1, PREFIX_2])

    user = app.get('/users/2').json
    assert user['yubikeys'] == [PREFIX_2]


def test_show_yubikey():
    yubikey = app.get('/users/1/yubikeys/%s' % PREFIX_1).json
    assert yubikey['enabled']
    assert yubikey['prefix'] == PREFIX_1


def test_show_yubikey_for_wrong_user():
    app.get('/users/2/yubikeys/%s' % PREFIX_1, status=404)


def test_unbind_yubikeys():
    app.delete('/users/1/yubikeys/%s' % PREFIX_1)
    yubikeys = app.get('/users/1/yubikeys').json
    assert yubikeys == [PREFIX_2]


def test_find_user_by_yubikey():
    app.post('/users/2/yubikeys', {'yubikey': PREFIX_3})

    user = app.get('/user?yubikey=%s' % PREFIX_3).json
    assert user['id'] == 2
    assert PREFIX_3 in user['yubikeys']


# Attributes


def test_assign_attributes():
    val1 = 'val1'
    val2 = 'value 2'
    val3 = 'val3' * 1024
    app.post('/users/1/attributes', {
             'key': 'attr1', 'value': val1})
    app.post('/users/1/attributes', {
             'key': 'attr2', 'value': val2})
    app.post('/users/1/attributes', {
             'key': 'attr3', 'value': val3})

    attributes = app.get('/users/1/attributes').json
    assert attributes['attr1'] == val1
    assert attributes['attr2'] == val2
    assert attributes['attr3'] == val3
    assert len(attributes) == 3

    user = app.get('/users/1').json
    assert user['attributes'] == attributes


def test_find_user_by_attribute():
    user1 = app.get('/user?attr1=val1&attr2=value 2').json
    assert user1['id'] == 1

    user2 = app.post('/user', {
                     'attr1': 'val1', 'attr2': 'value 2'}).json
    assert user1 == user2


def test_read_attribute():
    value = app.get('/users/1/attributes/attr1').json
    assert value == 'val1'


def test_read_missing_attribute():
    value = app.get('/users/1/attributes/foo').json
    assert not value


def test_overwrite_attributes():
    app.post('/users/1/attributes', {
             'key': 'attr1', 'value': 'newval'})
    attributes = app.get('/users/1/attributes').json

    assert attributes['attr1'] == 'newval'
    assert attributes['attr2'] == 'value 2'
    assert len(attributes) == 3


def test_unset_attributes():
    app.delete('/users/1/attributes/attr1')
    attributes = app.get('/users/1/attributes').json

    assert attributes['attr2'] == 'value 2'
    assert len(attributes) == 2

    value = app.get('/users/1/attributes/attr1').json
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
    _basic_attribute_test('/users/1/attributes')
    _basic_attribute_test('/users/2/attributes')


def test_yubikey_attributes():
    _basic_attribute_test('/yubikeys/%s/attributes' % PREFIX_1)
    _basic_attribute_test(
        '/users/2/yubikeys/%s/attributes' % PREFIX_2)
