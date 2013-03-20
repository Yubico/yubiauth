#!/usr/bin/python

__all__ = [
    'User',
    'Session',
    'create_db'
]

from config import settings
import password_auth

from sqlalchemy import create_engine, Sequence, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

Base = declarative_base()


class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, Sequence('user_id_seq'), primary_key=True)
    name = Column(String(32))
    auth = Column(String(128))

    def __init__(self, name, password):
        self.name = name
        self.set_password(password)

    def set_password(self, password):
        self.auth = password_auth.generate(password)

    def validate_password(self, password):
        return password_auth.validate(password, self.auth)

    def __repr__(self):
        return "User('%s','%s')" % (self.name, self.auth)


def create_db(engine):
    Base.metadata.create_all(engine)


engine = create_engine(settings['db'], echo=True)
create_db(engine)
Session = sessionmaker(bind=engine)
