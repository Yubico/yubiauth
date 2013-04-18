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
from yubiauth.util.controller import Controller
from yubiauth.util.model import Session
from yubiauth.client.model import UserSession, AttributeType

__all__ = [
    'Client'
]


class Client(Controller):
    """
    Main class for accessing user data.
    """
    def __init__(self, create_session=Session):
        super(Client, self).__init__(create_session)
        self.auth = YubiAuth()

    def create_session(self, username, password, otp=None):
        user = self.auth.get_user(username)
        if not user.validate_password(password):
            raise ValueError("Invalid credentials!")
        if otp:
            if user.validate_otp(otp):
                return
        else:
            sl = settings['security_level']
            if sl == 0 or (sl == 1 and len(user.yubikeys) == 0):
                return
        raise ValueError("Invalid credentials!")

        prefix = otp[:-32] if otp else None
        user_session = UserSession(username, prefix)
        self.session.add(user_session)
        if self.commit():
            #Prevent loading the user twice
            user_session._user = user
            return user_session

        raise ValueError("Error creating session for user: '%s'" % (username))

    def get_session(self, sessionId):
        try:
            user_session = self.session.query(UserSession).filter(
                UserSession.sessionId == sessionId).one()
            assert user_session.user
        except Exception:
            if user_session:
                user_session.delete()
                self.commit()
            raise ValueError("Session not found!")

        user_session.update_used()

        if user_session.is_expired():
            user_session.delete()
            raise ValueError("Session is expired!")

        if self.commit():
            return user_session

        raise ValueError("Error getting session!")

    def clear_sessions(self, user=None):
        query = self.session.query(UserSession)
        if user:
            query = query.filter(UserSession.username == user.name)
        query.delete()
        self.commit()

    def create_attribute(self, *args, **kwargs):
        attribute = AttributeType(*args, **kwargs)
        self.session.add(attribute)
        if self.commit():
            return attribute

    def get_attributes(self):
        return self.session.query(AttributeType).all()
