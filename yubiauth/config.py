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

import sys
import imp
import errno
import os
import default_settings


SETTINGS_FILE = os.getenv('YUBIAUTH_SETTINGS',
                          '/etc/yubico/auth/yubiauth.conf')

VALUES = {
    #Core
    'DATABASE_CONFIGURATION': 'db',
    'YKVAL_SERVERS': 'ykval',
    'YKVAL_CLIENT_ID': 'ykval_id',
    'YKVAL_CLIENT_SECRET': 'ykval_secret',
    'ALLOW_EMPTY_PASSWORDS': 'allow_empty',
    'USE_HSM': 'use_hsm',
    'YHSM_DEVICE': 'yhsm_device',
    'CRYPT_CONTEXT': 'crypt_context',
    'REST_PATH': 'rest_path',
    #Client
    'CORE_URL': 'core_url',
    'SECURITY_LEVEL': 'security_level',
    'AUTO_PROVISION': 'auto_provision',
    'YUBIKEY_IDENTIFICATION': 'yubikey_id'
}


def parse(conf, settings={}):
    for confkey, settingskey in VALUES.items():
        try:
            settings[settingskey] = conf.__getattribute__(confkey)
        except AttributeError:
            pass
    return settings


settings = parse(default_settings)

dont_write_bytecode = sys.dont_write_bytecode
try:
    sys.dont_write_bytecode = True
    user_settings = imp.load_source('user_settings', SETTINGS_FILE)
    settings = parse(user_settings, settings)
except IOError, e:
    if not e.errno in [errno.ENOENT, errno.EACCES]:
        raise e
finally:
    sys.dont_write_bytecode = dont_write_bytecode

settings['rest_path'] = settings['rest_path'].strip('/')

if not 'YHSM_DEVICE' in os.environ and 'yhsm_device' in settings:
    #The environment variable is the one that is actually used.
    os.environ['YHSM_DEVICE'] = settings['yhsm_device']
