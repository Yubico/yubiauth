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
    'yhsm_pbkdf2_sha1',
    'yhsm_pbkdf2_sha256',
    'yhsm_pbkdf2_sha512'
]

import os
from base64 import b64encode, b64decode
from passlib.utils import (to_hash_str, to_unicode)
from passlib.hash import pbkdf2_sha1, pbkdf2_sha256, pbkdf2_sha512

from pyhsm.base import YHSM
from pyhsm.util import key_handle_to_int

_UDOLLAR = u'$'
_UKH = u'kh='
_UDEFAULT_KH = u'1'

DEFAULT_DEVICE = 'daemon://localhost:5348'

hsm = YHSM(device=os.getenv('YHSM_DEVICE', DEFAULT_DEVICE))


def _yhsm__init__(base, self, key_handle=_UDEFAULT_KH, **kwds):
    super(base, self).__init__(**kwds)
    self.key_handle = key_handle


def _yhsmfrom_string(base, cls, hash):
    if not hash:
        raise ValueError('No hash specified')
    hash = to_unicode(hash, 'ascii', 'hash')

    if not hash.startswith(cls.ident):
        raise ValueError('invalid %s hash' % (cls.name))

    hash = hash[len(cls.ident):]

    if hash.startswith(_UKH):
        part, hash = hash.split(_UDOLLAR, 1)
        key_handle = part[len(_UKH):]
    else:
        key_handle = _UDEFAULT_KH

    inner_config, chk = hash.rsplit('$', 1)
    inner = base.from_string('%s%s' % (base.ident, inner_config))

    params = {}
    for kwd in inner.setting_kwds:
        try:
            params[kwd] = inner.__getattribute__(kwd)
        except AttributeError:
            pass
    params['key_handle'] = key_handle
    params['checksum'] = b64decode(chk.encode('ascii'))

    return cls(**params)


def _yhsm_hash_needs_update(base, cls, hash, **opts):
    key = 'deprecated_key_handles'
    if key in opts:
        for kh in opts[key].split(','):
            if 'kh=%s' % kh in hash:
                return True
    return False


def _yhsmto_string(base, self):
    hash = self.ident

    inner_str = super(base, self).to_string()
    inner_str = inner_str[len(self.ident):].rsplit('$', 1)[0]

    chk = b64encode(self.checksum).decode('ascii')

    hash += u'%s%s$%s$%s' % (
        _UKH,
        self.key_handle,
        inner_str,
        chk
    )

    return to_hash_str(hash)


def _yhsmcalc_checksum(base, self, secret):
    base_chk = super(base, self).calc_checksum(secret)
    result = hsm.hmac_sha1(key_handle_to_int(self.key_handle), base_chk)

    return result.result.hash_result


def _make_yhsm_handler(base, base_name):
    name = 'yhsm_%s' % (base_name)
    ident = u'$yhsm-%s$' % (base_name.replace('_', '-'))
    return type(name, (base,), dict(
        name=name,
        ident=ident,
        setting_kwds=('key_handle',) + base.setting_kwds,
        checksum_size=20,
        __init__=lambda *args, **kwargs: _yhsm__init__(base, *args, **kwargs),
        from_string=classmethod(lambda *args, **kwargs: _yhsmfrom_string(
            base, *args, **kwargs)),
        _hash_needs_update=classmethod(lambda *args, **kwargs:
                                       _yhsm_hash_needs_update(
                                           base, *args, **kwargs)),
        to_string=lambda *args, **kwargs: _yhsmto_string(
            base, *args, **kwargs),
        calc_checksum=lambda *args, **kwargs: _yhsmcalc_checksum(base, *args,
                                                                 **kwargs)
    ))


yhsm_pbkdf2_sha1 = _make_yhsm_handler(pbkdf2_sha1, 'pbkdf2_sha1')
yhsm_pbkdf2_sha256 = _make_yhsm_handler(pbkdf2_sha256, 'pbkdf2_sha256')
yhsm_pbkdf2_sha512 = _make_yhsm_handler(pbkdf2_sha512, 'pbkdf2_sha512')
