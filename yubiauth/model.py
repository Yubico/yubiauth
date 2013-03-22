#!/usr/bin/python

__all__ = [
    'User',
    'Session',
    'create_db'
]

from config import settings

from sqlalchemy import (create_engine, Sequence, Column, Integer,
                        String, ForeignKey, UniqueConstraint)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.orm.collections import attribute_mapped_collection
from sqlalchemy.ext.associationproxy import association_proxy

from passlib.context import CryptContext

Base = declarative_base()
pwd_context = CryptContext(**settings['crypt_context'])


class User(Base):
    """
    A user.

    Has a unique id and username, as well as a password and zero or
    more YubiKeys. Each user also has a key-value mapping of attributes.

    @cvar id: ID column.
    @cvar name: Name column.
    @cvar auth: Authentication data column.
    @cvar yubikeys: Dict of the users YubiKeys, with public IDs as keys.
    @cvar attributes: Dict of the users attributes.
    """
    __tablename__ = 'users'

    id = Column(Integer, Sequence('user_id_seq'), primary_key=True)
    name = Column(String(32), nullable=False, unique=True)
    auth = Column(String(128))
    yubikeys = relationship(
        'YubiKey',
        backref='user',
        order_by='YubiKey.public_id',
        collection_class=attribute_mapped_collection('public_id'),
        cascade='all, delete-orphan'
    )
    _attributes = relationship(
        'Attribute',
        backref='user',
        order_by='Attribute.key',
        collection_class=attribute_mapped_collection('key'),
        cascade='all, delete-orphan'
    )
    attributes = association_proxy(
        '_attributes',
        'value',
        creator=lambda k, v: Attribute(k, v)
    )

    def __init__(self, name, password):
        self.name = name
        self.set_password(password)

    def assign_yubikey(self, public_id_or_otp):
        """
        Assigns a YubiKey to the user.

        @param public_id_or_otp: The public ID of a YubiKey, or a full OTP.
        @type public_id_or_otp: string
        """
        if len(public_id_or_otp) > 32:
            public_id = public_id_or_otp[:-32]
        else:
            public_id = public_id_or_otp

        self.yubikeys[public_id] = YubiKey(public_id)

    def set_password(self, password):
        """
        Sets the password of the user, not yet committing the change to the
        database.

        @param password: The new password to set for the user.
        @type password: string
        """
        self.auth = pwd_context.encrypt(password)

    def validate_password(self, password):
        """
        Validates a password.

        @param password: A password to validate for the user.
        @type password: string

        @return: True if the password was valid, False if not.
        @rtype bool
        """
        valid, new_auth = pwd_context.verify_and_update(password, self.auth)
        if valid:
            if new_auth:
                self.auth = new_auth
            return True
        return False

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
            return self.yubikeys[public_id].validate(otp)
        except:
            return False

    @property
    def data(self):
        return {
            'id': self.id,
            'name': self.name,
            'attributes': self.attributes.copy(),
            'yubikeys': self.yubikeys.keys()
        }

    def __repr__(self):
        return ("User(id: '%d', name: '%s', attributes: '%r')" %
                (self.id, self.name, self.attributes)).encode('utf-8')


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

    id = Column(Integer, Sequence('yubikey_id_seq'), primary_key=True)
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
        return ("YubiKey(id: '%d', user: '%s', public_id: '%s')" %
                (self.id, self.user.name, self.public_id)).encode('utf-8')


class Attribute(Base):
    """
    Holds an attribute for a user.

    A user can have zero or more attributes, though each attribute must have
    a unique key per user.
    """
    __tablename__ = 'attributes'
    __table_args__ = (UniqueConstraint('user_id', 'key', name='_user_key_uc'),
                      )

    id = Column(Integer, Sequence('attribute_id_seq'), primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    key = Column(String(32), nullable=False)
    value = Column(String(128), nullable=False)

    def __init__(self, key, value):
        self.key = key
        self.value = value

    def __repr__(self):
        return ("%s[%s] = %s" % (self.user.name, self.key, self.value)
                ).encode('utf-8')


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
