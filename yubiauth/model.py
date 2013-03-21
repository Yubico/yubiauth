#!/usr/bin/python

__all__ = [
    'User',
    'Session',
    'create_db'
]

from config import settings
import password_auth

from sqlalchemy import create_engine, Sequence, Column, Integer, \
    String, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, backref

import json

Base = declarative_base()


class User(Base):
    """
    A user. Has a unique id and username, as well as a password and zero or
    more YubiKeys.

    @cvar id: ID column.
    @cvar name: Name column.
    @cvar auth: Authentication data column.
    @cvar yubikeys: Queryable reference to the users YubiKeys.
    """
    __tablename__ = 'users'

    id = Column(Integer, Sequence('user_id_seq'), primary_key=True)
    name = Column(String(32), nullable=False, unique=True)
    auth = Column(String(128))
    yubikeys = relationship(
        'YubiKey', backref=backref('user'),
        lazy='dynamic',
        cascade='all, delete, delete-orphan'
    )

    def __init__(self, name, password):
        self.name = name
        self.set_password(password)

    def set_password(self, password):
        """
        Sets the password of the user, not yet committing the change to the
        database.

        @param password: The new password to set for the user.
        @type password: string
        """
        self.auth = password_auth.generate(password)

    def validate_password(self, password):
        """
        Validates a password.

        @param password: A password to validate for the user.
        @type password: string

        @return: True if the password was valid, False if not.
        @rtype bool
        """
        return password_auth.validate(password, self.auth)

    def validate_otp(self, otp):
        """
        Validates a YubiKey OTP (One Time Password) for the user.

        @param otp: The OTP to validate.
        @type otp: string

        @return: True if the OTP was valid, and from a YubiKey belonging
        to the user. False if not.
        @rtype: bool
        """
        public_id = otp[:-32]
        try:
            return self.yubikeys.\
                filter(YubiKey.public_id == public_id).one().validate(otp)
        except:
            return False

    @property
    def data(self):
        return {
            'id': self.id,
            'name': self.name
        }

    def __repr__(self):
        return json.dumps(self.data)


class YubiKey(Base):
    """
    A reference to a YubiKey.

    This class connects a particular YubiKey to a C{User} in a many-to-one
    relationship. It is also used to validate OTPs (One Time Passwords)
    from the YubiKey.

    @cvar id: ID column.
    @cvar public_id: YubiKey public ID column.
    @cvar user_id: FK of the owner.
    """
    __tablename__ = 'yubikeys'

    id = Column(Integer, Sequence('user_id_seq'), primary_key=True)
    public_id = Column(String(32), nullable=False, unique=True)
    user_id = Column(Integer, ForeignKey('users.id'))

    def __init__(self, public_id):
        self.public_id = public_id

    def validate(self, otp):
        """
        Validates an OTP (One Time Password) from a YubiKey.

        @param otp: The OTP to validate.
        @type otp: string

        @return: True if the OTP was valid, and belonging to this YubiKey.
        False if not.
        """
        if self.public_id == otp[:-32]:
            # TODO: Validate
            return True
        return False

    @property
    def data(self):
        return {
            'public_id': self.public_id,
            'owner': self.user_id
        }

    def __repr__(self):
        return json.dumps(self.data)


def create_db(engine):
    """
    Initializes the required tables in the database for the model objects in
    this package.

    @param engine: A database engine.
    @type engine:  C{sqlalchemy.engine.base.Engine}
    """
    Base.metadata.create_all(engine)


engine = create_engine(settings['db'], echo=True)
# TODO: Remove this, add a utility to create the tables.
create_db(engine)
Session = sessionmaker(bind=engine)
