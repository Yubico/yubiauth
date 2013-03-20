from nose import with_setup

from yubiauth.model import create_db, YubiKey
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
    user1 = auth.get_user('user1')
    user1.yubikeys.append(YubiKey('cccccccccccb'))

    user2 = auth.get_user('user2')
    user2.yubikeys.append(YubiKey('cccccccccccd'))
    user2.yubikeys.append(YubiKey('ccccccccccce'))

    auth.commit()

    assert user1.yubikeys.filter(YubiKey.public_id == 'cccccccccccb').one()
    assert user2.yubikeys.count() == 2
