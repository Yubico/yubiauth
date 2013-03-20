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
    for user in auth.list_users():
        auth.delete_user(user)


@with_setup(setup, teardown)
def test_create_users():
    user = auth.create_user('test_user', 'test_password')
    assert user['name'] == 'test_user'


@with_setup(setup, teardown)
@raises(Exception)
def test_create_existing_username():
    auth.create_user('user1', 'testing')


@with_setup(setup, teardown)
def test_validate_password():
    assert auth.validate_password('user1', 'p4ssw0rd')
    assert not auth.validate_password('user1', 'foo')
    assert not auth.validate_password('user1', 'bar')

    assert auth.validate_password('user2', 'foo')
    assert not auth.validate_password('user2', 'bar')
