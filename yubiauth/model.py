#!/usr/bin/python

__all__ = [
    'User',
    'Session',
    'create_db'
]

from config import settings

from sqlalchemy import (create_engine, Sequence, Column, Boolean, Integer,
                        String, ForeignKey, UniqueConstraint, Table)
from sqlalchemy.ext.declarative import declarative_base, declared_attr
from sqlalchemy.orm import sessionmaker, relationship, backref
from sqlalchemy.orm.collections import attribute_mapped_collection
from sqlalchemy.ext.associationproxy import association_proxy


Base = declarative_base()

pwd_context = settings['pwd_context']


user_yubikeys = Table('user_yubikeys', Base.metadata,
                      Column('user_id', Integer, ForeignKey('users.id')),
                      Column('yubikey_id', Integer, ForeignKey('yubikeys.id'))
                      )


class AttributeAssociation(Base):
    __tablename__ = 'attribute_associations'

    id = Column(Integer, Sequence('attr_assoc_seq'), primary_key=True)
    _discriminator = Column('discriminator', String(16))
    _attributes = relationship(
        'Attribute',
        backref='association',
        order_by='Attribute.key',
        collection_class=attribute_mapped_collection('key'),
        cascade='all, delete-orphan'
    )
    attributes = association_proxy(
        '_attributes',
        'value',
        creator=lambda k, v: Attribute(k, v)
    )

    @property
    def owner(self):
        return getattr(self, '%s_owner' % self._discriminator)


class Attribute(Base):
    """
    Holds an attribute for an AttributeHolder.

    A user can have zero or more attributes, though each attribute must have
    a unique key per user.
    """
    __tablename__ = 'attributes'
    __table_args__ = (UniqueConstraint('association_id', 'key',
                                       name='_owner_key_uc'),)

    id = Column(Integer, Sequence('attribute_id_seq'), primary_key=True)
    _association_id = Column('association_id', Integer, ForeignKey(
        'attribute_associations.id'))
    key = Column(String(32), nullable=False)
    value = Column(String(128), nullable=False)
    owner = association_proxy('association', 'owner')

    def __init__(self, key, value):
        self.key = key
        self.value = value

    def __repr__(self):
        return ('%s = %s' % (self.key, self.value)).encode('utf-8')


class AttributeHolder(object):
    def __init__(self):
        discriminator = self.__class__.__name__.lower()
        self._attribute_association = AttributeAssociation(
            _discriminator=discriminator)

    @declared_attr
    def _attribute_association_id(cls):
        return Column('attribute_association_id', Integer, ForeignKey(
            'attribute_associations.id'))

    @declared_attr
    def _attribute_association(cls):
        discriminator = cls.__name__.lower()
        cls.attributes = association_proxy(
            '_attribute_association',
            'attributes'
        )
        return relationship('AttributeAssociation', backref=backref(
            '%s_owner' % discriminator, uselist=False), cascade=
            'all, delete')


class User(AttributeHolder, Base):
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
        secondary=user_yubikeys,
        backref='users',
        order_by='YubiKey.prefix',
        collection_class=attribute_mapped_collection('prefix'),
        # cascade='all, delete-orphan'
    )

    def __init__(self, name, password):
        self.name = name
        self.set_password(password)
        super(User, self).__init__()

    def assign_yubikey(self, prefix_or_otp):
        """
        Assigns a YubiKey to the user.

        @param prefix_or_otp: The public ID of a YubiKey, or a full OTP.
        @type prefix_or_otp: string
        """
        if len(prefix_or_otp) > 32:
            prefix = prefix_or_otp[:-32]
        else:
            prefix = prefix_or_otp

        session = Session.object_session(self)
        existing_key = session.query(YubiKey).filter(
            YubiKey.prefix == prefix).first()

        if existing_key:
            existing_key.users.append(self)
        else:
            self.yubikeys[prefix] = YubiKey(prefix)
        session.commit()

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
        valid, new_auth = pwd_context.\
            verify_and_update(password, self.auth)
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
        prefix = otp[:-32]
        otp_valid = True  # TODO: Validate OTP against YKVAL

        if prefix in self.yubikeys:
            return otp_valid and self.yubikeys[prefix].enabled

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
        return ("User(id: '%r', name: '%s', attributes: '%r')" %
                (self.id, self.name, self.attributes)).encode('utf-8')


class YubiKey(AttributeHolder, Base):
    """
    A reference to a YubiKey.

    This class connects a particular YubiKey to a C{User} in a many-to-one
    relationship. It is also used to validate OTPs (One Time Passwords)
    from the YubiKey.

    @cvar id: ID column.
    @cvar prefix: YubiKey public ID column.
    @cvar user_id: FK of the owner.
    """
    __tablename__ = 'yubikeys'

    id = Column(Integer, Sequence('yubikey_id_seq'), primary_key=True)
    prefix = Column(String(32), nullable=False, unique=True)
    enabled = Column(Boolean, default=True)

    def __init__(self, prefix):
        self.prefix = prefix
        super(YubiKey, self).__init__()

    @property
    def data(self):
        return {
            'prefix': self.prefix,
            'owner': self.user_id
        }

    def __repr__(self):
        return ("YubiKey(id: '%r', prefix: '%s')" %
                (self.id, self.prefix)).encode('utf-8')


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
