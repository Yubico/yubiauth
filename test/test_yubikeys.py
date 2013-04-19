from nose import with_setup

from yubiauth import create_tables
from yubiauth.core import YubiAuth

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

engine = create_engine('sqlite:///:memory:', echo=True)
create_tables(engine)
Session = sessionmaker(bind=engine)
auth = None


def setup():
    global auth
    auth = YubiAuth(Session())
    teardown()
    auth.create_user('user1', 'p4ssw0rd')
    auth.create_user('user2', 'foo')


def teardown():
    for user in auth.query_users():
        auth.get_user(user['id']).delete()


@with_setup(setup, teardown)
def test_yubikey_assignment():
    user1 = auth.get_user('user1')
    user1.assign_yubikey('cccccccccccb')

    user2 = auth.get_user('user2')
    user2.assign_yubikey('cccccccccccd')
    user2.assign_yubikey('ccccccccccce')

    assert auth.commit()

    assert user1.yubikeys['cccccccccccb']
    assert len(user2.yubikeys) == 2
