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
    'UserSession'
]

from sqlalchemy import (func, Sequence, Column, Boolean, Integer,
                        String, DateTime)
from sqlalchemy.ext.declarative import declarative_base

from datetime import datetime
import re
import uuid
import base64

from yubiauth.util.model import Deletable, Session
from yubiauth.core.model import User

Base = declarative_base()


class UserSession(Deletable, Base):
    __tablename__ = 'user_sessions'

    id = Column(Integer, Sequence('user_session_id_seq'), primary_key=True)
    sessionId = Column(String(64), nullable=False, unique=True)
    username = Column(String(32), nullable=False)
    yubikey_prefix = Column(String(32))
    created_at = Column(DateTime, default=func.now())
    last_used = Column(DateTime, default=func.now())

    def __init__(self, username, prefix=None):
        self.sessionId = self.generate_key()
        self.username = username
        self.yubikey_prefix = prefix

    def generate_key(self):
        #TODO: Make sessionId stronger.
        return base64.urlsafe_b64encode(uuid.uuid4().get_bytes())

    def is_expired(self):
        return False

    def update_used(self):
        self.last_used = datetime.now()

    @property
    def data(self):
        return {
            'sessionId': self.sessionId,
            'username': self.username,
            'yubikey_prefix': self.yubikey_prefix,
            'created_at': self.created_at.ctime(),
            'last_used': self.last_used.ctime()
        }

    @property
    def user(self):
        try:
            return self._user
        except:
            session = Session.object_session(self)
            self._user = session.query(User).filter(User.name ==
                                                    self.username).one()
        return self._user

    def __repr__(self):
        return (
            "UserSession(sessionId: '%s', username: '%s')" %
            (self.sessionId, self.username)
        ).encode('utf-8')


PERMS = {
    'ALL': 1,
    'USER': 2,
    'ADMIN': 3,
    'NOBODY': 100
}


def clamp_perms(view_perms, edit_perms):
    if view_perms and not view_perms in PERMS:
        raise ValueError("Invalid value for view_perms: '%d'" % view_perms)
    if edit_perms and not edit_perms in PERMS:
        raise ValueError("Invalid value for edit_perms: '%d'" % view_perms)
    if view_perms > edit_perms:
        if edit_perms:
            raise ValueError("view_perms > edit_perms")
        edit_perms = view_perms

    return view_perms, edit_perms


class AttributeType(Deletable, Base):
    __tablename__ = 'attribute_types'

    id = Column(Integer, Sequence('attribute_type_id_seq'), primary_key=True)
    name = Column(String(32), unique=True, nullable=False)
    pattern = Column(String(128), nullable=False, default='.*')
    required = Column(Boolean, default=False)
    view_perms = Column(Integer, default=PERMS['ADMIN'])
    edit_perms = Column(Integer, default=PERMS['USER'])

    def __init__(self, name, pattern=None, required=False, view_perms=0,
                 edit_perms=0):
        view_perms, edit_perms = clamp_perms(view_perms, edit_perms)

        self.type = type
        self.name = name
        if pattern:
            self.pattern = pattern
        self.required = required
        if view_perms:
            self.view_perms = view_perms
        if edit_perms:
            self.edit_perms = edit_perms

    def validate(self, value):
        if not self.required and value is None:
            return True
        regex = re.compile(self.pattern)
        return bool(regex.match(value))

    @property
    def key(self):
        # TODO: normalize name
        return '__%s' % self.name

    @property
    def data(self):
        return {
            'name': self.name,
            'key': self.key,
            'pattern': self.pattern,
            'required': self.required,
            'view_perms': self.view_perms,
            'edit_perms': self.edit_perms
        }

    def __repr__(self):
        return (
            "AttributeType(name: '%s', key: '%s', pattern: '%s')" %
            (self.name, self.key, self.pattern)
        ).encode('utf-8')
