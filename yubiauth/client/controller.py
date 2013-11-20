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
from yubiauth.client.model import AttributeType, PERMS
from beaker.session import Session as UserSession
from functools import partial
import uuid
import base64
import logging
log = logging.getLogger(__name__)

__all__ = [
    'Client',
    'requires_otp'
]

REVOKE_KEY = '_revoke'


if settings['use_ldap'] and settings['ldap_auto_import']:
    from yubiauth.core.ldapauth import LDAPAuthenticator
    global ldapauth
    ldapauth = LDAPAuthenticator(settings['ldap_server'],
                                 settings['ldap_bind_dn'])

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


session_config = dict([(key[8:], value) for key, value in
                       settings['beaker'].items() if
                       key.startswith('session.')])
session_config['use_cookies'] = False


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
        try:
            if not username and otp:
                user = self._user_for_otp(otp)
            else:
                user = self.auth.get_user(username)
        except Exception as e:
            if settings['use_ldap'] and settings['ldap_auto_import'] \
                    and ldapauth.authenticate(username, password):
                user = self.auth.create_user(username, None)
                user.attributes['_ldap_auto_imported'] = True
            else:
                log.info('Authentication failed. No such user: %s', username)
                raise e

        if user.validate_password(password):
            pw = 'valid password' if password else 'None (valid)'
            if authenticate_otp(user, otp):
                log.info(
                    'Authentication successful. '
                    'Username: %s, password: <%s>, OTP: %s',
                    username, pw, otp)
                return user
        else:
            pw = 'invalid password' if password else 'None (invalid)'
            # Consume the OTP even if the password was incorrect.
            if otp:
                validate_otp(otp)
        log.info(
            'Authentication failed. Username: %s, password: <%s>, OTP: %s',
            username, pw, otp)
        raise ValueError("Invalid credentials!")

    def create_session(self, username, password, otp=None):
        user = self.authenticate(username, password, otp)
        prefix = otp[:-32] if otp else None
        user_session = UserSession({}, **session_config)
        user_session['user_id'] = user.id
        user_session['username'] = user.name
        user_session['prefix'] = prefix if prefix else None
        user_session.save()
        return user_session

    def get_session(self, sessionId):
        user_session = UserSession({}, id=sessionId, **session_config)
        if user_session.is_new:
            user_session.delete()
            raise ValueError("Session not found!")
        return user_session

    def create_attribute(self, *args, **kwargs):
        attribute = AttributeType(*args, **kwargs)
        self.session.add(attribute)
        return attribute

    def get_attributes(self):
        return self.session.query(AttributeType).all()

    def generate_revocation(self, prefix):
        yubikey = self.auth.get_yubikey(prefix)
        code = base64.urlsafe_b64encode(uuid.uuid4().get_bytes())
        yubikey.attributes[REVOKE_KEY] = code
        return code

    def revoke(self, code):
        kwargs = {REVOKE_KEY: code}
        keys = self.auth.query_yubikeys(**kwargs)
        if not len(keys) == 1:
            log.error('Revocation failed. Matching keys: %d, Code: %s',
                      len(keys), code)
            raise ValueError('Invalid revocation code!')
        yubikey = keys[0]
        yubikey.enabled = False
        del yubikey.attributes[REVOKE_KEY]
        log.info('Revocation successful. '
                 'YubiKey [%s] has been revoked using code: %s',
                 yubikey.prefix, code)

    def register(self, username, password, otp=None, attributes={}):
        if not settings['registration']:
            raise ValueError('User registration disabled!')

        validate_attributes(self.get_attributes(), attributes)

        if otp and not validate_otp(otp):
            raise ValueError('Invalid OTP!')

        user = self.auth.create_user(username, password)
        user.attributes.update(attributes)
        if otp:
            user.assign_yubikey(otp)
        log.info('User %s registered with attributes: %r', username,
                 attributes)
        return user


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
