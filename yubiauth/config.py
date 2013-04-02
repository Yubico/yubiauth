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
    'settings'
]

from passlib.context import CryptContext
from passlib.registry import register_crypt_handler_path

register_crypt_handler_path('yhsm_pbkdf2_sha1', 'yubiauth.yhsm')
register_crypt_handler_path('yhsm_pbkdf2_sha256', 'yubiauth.yhsm')
register_crypt_handler_path('yhsm_pbkdf2_sha512', 'yubiauth.yhsm')

#TODO: Read settings file /etc/yubico/yubiauth/yubiauth.cfg
settings = {
    'db': 'sqlite:///:memory:',
    'ykval': [
        'https://api.yubico.com/wsapi/2.0/verify',
        'https://api2.yubico.com/wsapi/2.0/verify',
        'https://api3.yubico.com/wsapi/2.0/verify',
        'https://api4.yubico.com/wsapi/2.0/verify',
        'https://api5.yubico.com/wsapi/2.0/verify'
    ],
    'yhsm_devices': {
        'main': '/dev/ttyACM0'
    },
    #ALT: 'yhsm_devices': '/dev/ttyACM0',
    'crypt_context': {
        #'schemes': ['yhsm_pbkdf2_sha1', 'sha512_crypt', 'sha256_crypt'],
        #'default': 'yhsm_pbkdf2_sha1',
        'schemes': ['sha512_crypt', 'sha256_crypt'],
        'default': 'sha256_crypt',
        'yhsm_pbkdf2_sha1__hsm': 'main',
        'yhsm_pbkdf2_sha1__key_handle': 1,
        'all__vary_rounds': 0.1,
        'sha512_crypt__min_rounds': 60000,
        'sha256_crypt__min_rounds': 80000,
        'admin__sha512_crypt__min_rounds': 120000,
        'admin__sha256_crypt__min_rounds': 160000
    }
}

if isinstance(settings['yhsm_devices'], basestring):
    settings['yhsm_devices'] = {'main': settings['yhsm_devices']}

settings['pwd_context'] = CryptContext(**settings['crypt_context'])
