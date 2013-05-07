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

from yubiauth import settings, YubiAuth
from yubiauth.util import validate_otp
from yubiauth.util.controller import Controller
from yubiauth.util.model import Session
from yubiauth.client.model import UserSession, AttributeType, PERMS

__all__ = [
    'Client',
    'requires_otp'
]

REVOKE_KEY = '_revoke'


def requires_otp(user):
    sl = settings['security_level']
    count = len([key for key in user.yubikeys.values() if key.enabled])
    return not (sl == 0 or (sl == 1 and count == 0))


def authenticate_otp(user, otp):
    if otp:
        if settings['auto_provision'] and len(user.yubikeys) == 0:
            if validate_otp(otp):
                user.assign_yubikey(otp)
                return True
            else:
                return False
        else:
            return user.validate_otp(otp)
    else:
        return not requires_otp(user)


class Client(Controller):
    """
    Main class for accessing user data.
    """
    def __init__(self, session=Session()):
        super(Client, self).__init__(session)
        self.auth = YubiAuth(session)

    def _user_for_otp(self, otp):
        if settings['yubikey_id']:
            yubikey = self.auth.get_yubikey(otp[:-32])
            if yubikey.enabled and len(yubikey.users) == 1:
                return yubikey.users[0]
        raise ValueError("Unable to locate user!")

    def authenticate(self, username, password, otp=None):
        if not username and otp:
            user = self._user_for_otp(otp)
        else:
            user = self.auth.get_user(username)
        if user.validate_password(password):
            if authenticate_otp(user, otp):
                return user
        else:
            # Consume the OTP even if the password was incorrect.
            validate_otp(otp)
        raise ValueError("Invalid credentials!")

    def create_session(self, username, password, otp=None):
        user = self.authenticate(username, password, otp)
        prefix = otp[:-32] if otp else None
        user_session = UserSession(user.name, prefix)
        self.session.add(user_session)
        # Prevent loading the user twice
        user_session._user = user
        return user_session

    def get_session(self, sessionId):
        try:
            user_session = self.session.query(UserSession).filter(
                UserSession.sessionId == sessionId).one()
        except Exception:
            raise ValueError("Session not found!")

        user_session.update_used()

        if user_session.is_expired() or not user_session.user:
            user_session.delete()
            raise ValueError("Session is expired!")

        return user_session

    def clear_sessions(self, user=None):
        query = self.session.query(UserSession)
        if user:
            query = query.filter(UserSession.username == user.name)
        query.delete()

    def create_attribute(self, *args, **kwargs):
        attribute = AttributeType(*args, **kwargs)
        self.session.add(attribute)
        return attribute

    def get_attributes(self):
        return self.session.query(AttributeType).all()

    def generate_revocation(self, prefix):
        yubikey = self.auth.get_yubikey(prefix)
        code = UserSession(REVOKE_KEY).sessionId
        yubikey.attributes[REVOKE_KEY] = code
        return code

    def revoke(self, code):
        kwargs = {REVOKE_KEY: code}
        keys = self.auth.query_yubikeys(**kwargs)
        if not len(keys) == 1:
            raise ValueError('Invalid revocation code!')
        keys[0].enabled = False

    def sign_up(self, username, password, otp=None, attributes={}):
        validate_attributes(self.get_attributes(), attributes)

        if otp and not validate_otp(otp):
            raise ValueError('Invalid OTP!')

        user = self.auth.create_user(username, password)
        user.attributes.update(attributes)
        if otp:
            user.assign_yubikey(otp)


def validate_attributes(user_attrs, supplied_attrs, perm_level=PERMS['USER']):
    for attr in user_attrs:
        key = attr.key
        if key in supplied_attrs:
            if attr.edit_perms > perm_level:
                raise ValueError('Not permitted to set attribute: %s' % key)
            if not attr.validate(supplied_attrs[key]):
                raise ValueError('Invalid value for attribute: %s = "%s"'
                                 % (key, supplied_attrs[key]))
        elif attr.required:
            raise ValueError('Missing required attribute: %s' % key)
