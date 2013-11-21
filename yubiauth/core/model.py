#
# Copyright (c) 2013 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

__all__ = [
    'User',
    'Attribute',
    'YubiKey',
    'Base',
]

from UserDict import DictMixin
from yubiauth.config import settings
from yubiauth.util import validate_otp
from yubiauth.util.model import Session, Deletable

from sqlalchemy import (Sequence, Column, Boolean, Integer, String, Text,
                        ForeignKey, UniqueConstraint, Table)
from sqlalchemy.ext.declarative import declarative_base, declared_attr
from sqlalchemy.orm import relationship, backref
from sqlalchemy.orm.collections import attribute_mapped_collection
from sqlalchemy.ext.associationproxy import association_proxy

from passlib.context import CryptContext
from passlib.registry import register_crypt_handler_path

if settings['use_ldap']:
    from yubiauth.core.ldapauth import LDAPAuthenticator
    global ldapauth
    ldapauth = LDAPAuthenticator(settings['ldap_server'],
                                 settings['ldap_bind_dn'])

if settings['use_hsm']:
    register_crypt_handler_path('yhsm_pbkdf2_sha1', 'yubiauth.yhsm')
    register_crypt_handler_path('yhsm_pbkdf2_sha256', 'yubiauth.yhsm')
    register_crypt_handler_path('yhsm_pbkdf2_sha512', 'yubiauth.yhsm')


Base = declarative_base()

pwd_context = CryptContext(**settings['crypt_context'])


user_yubikeys = Table(
    'user_yubikeys',
    Base.metadata,
    Column('user_id', Integer, ForeignKey('users.id', ondelete='cascade')),
    Column('yubikey_id', Integer,
           ForeignKey('yubikeys.id', ondelete='cascade'))
)


class AttributeAssociation(Base):
    """
    Holds Attributes. Each AttributeHolder has one of these.

    cvar id: Primary key.
    cvar discriminator: The name of the type of the owner.
    cvar attributes: Dict of attributes.
    cvar owner: The owner of the attributes.
    """
    __tablename__ = 'attribute_associations'

    id = Column(Integer, Sequence('attr_assoc_seq'), primary_key=True)
    discriminator = Column('discriminator', String(16))
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
        return getattr(self, '%s_owner' % self.discriminator)


class Attribute(Base):
    """
    Holds an attribute for an AttributeHolder.

    An AttributeHolder can have zero or more attributes, though each attribute
    must have a unique key per user.

    cvar id: Primary key.
    cvar key: The key of the attribute.
    cvar value: The value of the attribute.
    cvar owner: The owner of the attribute.
    """
    __tablename__ = 'attributes'
    __table_args__ = (UniqueConstraint('association_id', 'key',
                                       name='_owner_key_uc'),)

    id = Column(Integer, Sequence('attribute_id_seq'), primary_key=True)
    _association_id = Column('association_id', Integer, ForeignKey(
        'attribute_associations.id'))
    key = Column(String(32), nullable=False)
    value = Column(Text(), nullable=False)
    owner = association_proxy('association', 'owner')

    def __init__(self, key, value):
        self.key = key
        self.value = value

    def __repr__(self):
        return ('%s = %s' % (self.key, self.value)).encode('utf-8')


class AttributeProxy(DictMixin):
        """
        Proxy used in AttributeHolder used to give access to Attributes
        via an AttributeAssociation object, creating that object when
        necessary.
        """
        def __init__(self, owner):
            self.owner = owner

        @property
        def has_assoc(self):
            return bool(self.owner._attribute_association)

        @property
        def assoc(self):
            if not self.owner._attribute_association:
                discriminator = self.owner.__class__.__name__.lower()
                self.owner._attribute_association = AttributeAssociation(
                    discriminator=discriminator)
            return self.owner._attribute_association

        def __getitem__(self, key):
            if self.has_assoc:
                return self.assoc.attributes[key]
            raise KeyError(key)

        def __setitem__(self, key, value):
            self.assoc.attributes[key] = value

        def __delitem__(self, key):
            if self.has_assoc:
                del self.assoc.attributes[key]
            else:
                raise KeyError(key)

        def keys(self):
            if self.has_assoc:
                return self.assoc.attributes.keys()
            return []

        def copy(self):
            copy = {}
            copy.update(self)
            return copy


class AttributeHolder(object):
    """
    Mixin class for model objects that should hold Attributes.

    Attributes can be easily accessed through common dict operations.

    holder.attributes['foo'] = 'bar'
    holder.attributes = {'key1': 'val', 'key2': 'otherval'}
    """

    @property
    def attributes(self):
        if not '_attributes' in self.__dict__:
            self._attributes = AttributeProxy(self)
        return self._attributes

    @attributes.setter
    def attributes(self, value):
        self.attributes.clear()
        self.attributes.update(value)

    @declared_attr
    def _discriminator(cls):
        return cls.__name__.lower()

    @declared_attr
    def _attribute_association_id(cls):
        return Column('attribute_association_id', Integer, ForeignKey(
            'attribute_associations.id'))

    @declared_attr
    def _attribute_association(cls):
        return relationship('AttributeAssociation', backref=backref(
            '%s_owner' % cls._discriminator, uselist=False), cascade=
            'all, delete')


class User(AttributeHolder, Deletable, Base):
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
        return self.yubikeys[prefix]

    def set_password(self, password):
        """
        Sets the password of the user. An empty String is treated as no
        password. If no password is set the user either can't log in (default)
        or, if the ALLOW_EMPTY_PASSWORDS setting is set to True, the user may
        log in without providing a password.

        @param password: The new password to set for the user.
        @type password: string
        """
        if settings['use_ldap']:
            raise ValueError("Cannot set password when using LDAP")

        if password:
            self.auth = pwd_context.encrypt(password)
        else:
            self.auth = None

    def validate_password(self, password):
        """
        Validates a password.

        @param password: A password to validate for the user.
        @type password: string

        @return: True if the password was valid, False if not.
        @rtype bool
        """
        if settings['use_ldap']:
            return ldapauth.authenticate(self.name, password)

        if not password:
            return settings['allow_empty'] is True

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
        otp_valid = validate_otp(otp)
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
        return (
            "User(id: %r, name: '%s', yubikeys: %r, attributes: %r)" %
            (self.id, self.name, self.yubikeys.keys(), self.attributes)
        ).encode('utf-8')


class YubiKey(AttributeHolder, Deletable, Base):
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
            'id': self.id,
            'prefix': self.prefix,
            'enabled': self.enabled,
            'attributes': self.attributes.copy()
        }

    def __repr__(self):
        return ("YubiKey(id: %r, prefix: '%s')" %
                (self.id, self.prefix)).encode('utf-8')
