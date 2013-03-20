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
        self.auth = password_auth.generate(password)

    def validate_password(self, password):
        return password_auth.validate(password, self.auth)

    def validate_otp(self, otp):
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
    __tablename__ = 'yubikeys'

    id = Column(Integer, Sequence('user_id_seq'), primary_key=True)
    public_id = Column(String(32), nullable=False, unique=True)
    user_id = Column(Integer, ForeignKey('users.id'))

    def __init__(self, public_id):
        self.public_id = public_id

    def validate(self, otp):
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
    Base.metadata.create_all(engine)


engine = create_engine(settings['db'], echo=True)
# TODO: Remove this, add a utility to create the tables.
create_db(engine)
Session = sessionmaker(bind=engine)
