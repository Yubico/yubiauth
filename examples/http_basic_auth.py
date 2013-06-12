# Copyright (c) 2013 Yubico AB
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#   * Redistributions in binary form must reproduce the above
#     copyright notice, this list of conditions and the following
#     disclaimer in the documentation and/or other materials provided
#     with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#
# This is a working example of using a YubiAuth backend to validate HTTP BASIC
# AUTH user authentication. It can be used, for example, by mod_wsgi to add
# authetication to a WSGI application.
#
# YubiKey OTPs are expected to be appended to either the username or password.
#

import re
import base64
import requests

OTP_PATTERN = re.compile(r'^(.*)([cbdefghijklnrtuv]{44})$')


def parse_auth(auth):
    username, password = base64.b64decode(auth).split(':', 1)
    username_match = OTP_PATTERN.match(username)
    if username_match:
        username = username_match.group(1)
        otp = username_match.group(2)
    else:
        password_match = OTP_PATTERN.match(password)
        if password_match:
            password = password_match.group(1)
            otp = password_match.group(2)
        else:
            otp = None
    return username, password, otp


class YubiAuthValidator(object):
    """
    Validates HTTP BASIC authentication credentials using a YubiAuth backend.
    HTTP BASIC sends the credentials for each request. Initially we parse
    the username, password and (optionally) OTP and create a user session.
    On subsequent requests, we use the auth string as a key to lookup the
    session key and validate the session.

    Example:
    validator = YubiAuthValidator()
    if validator(auth):
        print 'Validation OK!'
    """
    def __init__(self, url='http://127.0.0.1/yubiauth/client'):
        self.base_url = url
        self.sessions = {}

    def __call__(self, auth):
        """
        Call with the Base64 encoded auth string from the request.
        Returns True on successful authentication, else False.
        """
        if auth in self.sessions:
            return self.validate_session(auth)
        return self.create_session(auth)

    def create_session(self, auth):
        username, password, otp = parse_auth(auth)
        if not self.validate_user(username):
            return False
        url = '%s/login' % self.base_url
        response = requests.post(url, data={
            'username': username, 'password': password, 'otp': otp})
        if response.status_code == requests.codes.ok:
            self.sessions[auth] = response.cookies['YubiAuth-Session']
            return True
        return False

    def validate_user(self, username):
        """
        Override this to return False if the given user shouldn't be granted
        access.
        """
        return True

    def validate_session(self, auth):
        if auth in self.sessions:
            session_id = self.sessions[auth]
            url = '%s/status' % self.base_url
            response = requests.get(url,
                                    cookies={'YubiAuth-Session': session_id})
            if response.status_code == requests.codes.ok:
                return True
            del self.sessions[auth]
        return False

validator = YubiAuthValidator()


# check_password function for use with mod_wsgi. To use, add this to your
# Apache configuration.
#
# AuthType Basic
# AuthName "YubiAuth"
# AuthBasicProvider wsgi
# WSGIAuthUserScript /path/to/http_basic_auth.py
# Require valid-user
def check_password(environ, user, password):
    # mod_wsgi has already unpacked the username and password,
    # but we expect them to be packed, so re-pack:
    return validator(base64.b64encode('%s:%s' % (user, password)))
