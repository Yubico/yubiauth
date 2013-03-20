from nose import with_setup

from yubiauth.model import User, Session, create_db

from sqlalchemy import create_engine
from yubiauth import settings

engine = create_engine(settings['db'], echo=True)
create_db(engine)
Session.configure(bind=engine)
session = None


def setup():
    global session
    session = Session()
    session.add(User('user1', 'p4ssw0rd'))
    session.add(User('user2', 'foo'))


@with_setup(setup)
def test_create_users():
    user = User('test_user', 'test_password')
    assert user.name == 'test_user'


@with_setup(setup)
def test_validate_password():
    (user1, user2) = session.query(User)

    assert user1.validate_password('p4ssw0rd')
    assert not user1.validate_password('foo')
    assert not user1.validate_password('bar')

    assert user2.validate_password('foo')
    assert not user2.validate_password('bar')
