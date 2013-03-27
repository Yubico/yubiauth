from nose import with_setup
from nose.tools import raises

from yubiauth.model import create_db
from yubiauth import YubiAuth

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

engine = create_engine('sqlite:///:memory:', echo=True)
create_db(engine)
Session = sessionmaker(bind=engine)
auth = None


def setup():
    global auth
    auth = YubiAuth(Session)
    teardown()
    auth.create_user('user1', 'p4ssw0rd')
    auth.create_user('user2', 'foo')


def teardown():
    for user in auth.query_users():
        auth.get_user(user['id']).delete()


@with_setup(setup, teardown)
def test_create_users():
    user = auth.create_user('test_user', 'test_password')
    assert user.name == 'test_user'


@with_setup(setup, teardown)
@raises(Exception)
def test_create_existing_username():
    auth.create_user('user1', 'testing')


@with_setup(setup, teardown)
def test_validate_password():
    user = auth.get_user('user1')
    assert user.validate_password('p4ssw0rd')
    assert not user.validate_password('foo')
    assert not user.validate_password('bar')

    user2 = auth.get_user('user2')
    assert user2.validate_password('foo')
    assert not user2.validate_password('bar')
