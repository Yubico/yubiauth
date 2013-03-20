from nose import with_setup

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
def test_yubikey_assignment():
    auth.assign_yubikey('user1', 'cccccccccccb')
    auth.assign_yubikey('user2', 'cccccccccccd')
    auth.assign_yubikey('user2', 'ccccccccccce')
