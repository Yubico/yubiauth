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
    'LDAPAuthenticator'
]

import ldap
import logging
log = logging.getLogger(__name__)


class UserStub(object):

    def __init__(self, name):
        self.name = name
        self.attributes = {}


class LDAPAuthenticator(object):

    """Authenticates users against an external LDAP server."""

    def __init__(self, ldap_server, bind_dn):
        self.ldap_server = ldap_server
        self.bind_dn = bind_dn

    def authenticate(self, user, password):
        if isinstance(user, basestring):
            user = UserStub(user)
        conn = None
        tmpl = user.attributes.get('_ldap_bind_dn', self.bind_dn)
        try:
            bind_dn = tmpl.format(user=user)
        except Exception:
            log.exception("Error in LDAP Bind DN template expansion")
            return False

        try:
            conn = ldap.initialize(self.ldap_server)
            conn.set_option(ldap.OPT_NETWORK_TIMEOUT, 10.0)
            conn.simple_bind_s(bind_dn, password)
            log.info("LDAP authentication successful. "
                     "Bind DN: %s, server: %s", bind_dn, self.ldap_server)
            return True
        except ldap.LDAPError:
            log.exception("LDAP authentication failed. "
                          "Bind DN: %s, server: %s", bind_dn, self.ldap_server)
        finally:
            if conn:
                conn.unbind_s()

        return False
