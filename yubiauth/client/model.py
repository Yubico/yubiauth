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
    'AttributeType',
    'PERMS'
]

from sqlalchemy import Sequence, Column, Boolean, Integer, String
from sqlalchemy.ext.declarative import declarative_base

import re

from yubiauth.util.model import Deletable

Base = declarative_base()

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
