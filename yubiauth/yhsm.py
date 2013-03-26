__all__ = [
    'yhsm_pbkdf2_sha1',
    'yhsm_pbkdf2_sha256',
    'yhsm_pbkdf2_sha512'
]

from passlib.utils import (to_hash_str, to_unicode, adapted_b64_decode,
                           adapted_b64_encode)
from passlib.hash import pbkdf2_sha1, pbkdf2_sha256, pbkdf2_sha512

from pyhsm.base import YHSM
from pyhsm.util import key_handle_to_int

from config import settings

_UDOLLAR = u'$'
_UHSM = u'hsm='
_UKH = u'kh='
_UDEFAULT_HSM = u'main'
_UDEFAULT_KH = u'1'
_UDEFAULT_DEVICE = u'/dev/ttyACM0'


def _yhsm__init__(base, self, hsm=_UDEFAULT_HSM,
                  key_handle=_UDEFAULT_KH, **kwds):
    super(base, self).__init__(**kwds)
    self.hsm = hsm
    self.key_handle = key_handle


def _yhsmfrom_string(base, cls, hash):
    if not hash:
        raise ValueError('No hash specified')
    hash = to_unicode(hash, 'ascii', 'hash')

    if not hash.startswith(cls.ident):
        raise ValueError('invalid %s hash' % (cls.name))

    hash = hash[len(cls.ident):]

    if hash.startswith(_UHSM):
        part, hash = hash.split(_UDOLLAR, 1)
        hsm = part[len(_UHSM):]
    else:
        hsm = _UDEFAULT_HSM

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
    params['hsm'] = hsm
    params['key_handle'] = key_handle
    params['checksum'] = adapted_b64_decode(chk.encode('ascii'))

    return cls(**params)


def _yhsmto_string(base, self):
    hash = self.ident

    if self.hsm != _UDEFAULT_HSM:
        hash += "%s%s$" % (_UHSM, self.hsm)

    inner_str = super(base, self).to_string()
    print inner_str

    inner_str = inner_str[len(self.ident):].rsplit('$', 1)[0]

    chk = adapted_b64_encode(self.checksum).decode('ascii')

    hash += u'%s%s$%s$%s' % (
        _UKH,
        self.key_handle,
        inner_str,
        chk
    )

    return to_hash_str(hash)


def _yhsmcalc_checksum(base, self, secret):
    base_chk = super(base, self).calc_checksum(secret)
    hsm = YHSM(device=settings['yhsm_devices'][self.hsm])
    result = hsm.hmac_sha1(key_handle_to_int(self.key_handle), base_chk)

    return result.result.hash_result


def _make_yhsm_handler(base, base_name):
    name = 'yhsm_%s' % (base_name)
    ident = u'$yhsm-%s$' % (base_name.replace('_', '-'))
    return type(name, (base,), dict(
        name=name,
        ident=ident,
        setting_kwds=('hsm', 'key_handle') + base.setting_kwds,
        checksum_size=20,
        __init__=lambda *args, **kwargs: _yhsm__init__(base, *args, **kwargs),
        from_string=classmethod(lambda *args, **kwargs: _yhsmfrom_string(
            base, *args, **kwargs)),
        to_string=lambda *args, **kwargs: _yhsmto_string(
            base, *args, **kwargs),
        calc_checksum=lambda *
        args, **kwargs: _yhsmcalc_checksum(base, *args, **kwargs)
    ))


yhsm_pbkdf2_sha1 = _make_yhsm_handler(pbkdf2_sha1, 'pbkdf2_sha1')
yhsm_pbkdf2_sha256 = _make_yhsm_handler(pbkdf2_sha256, 'pbkdf2_sha256')
yhsm_pbkdf2_sha512 = _make_yhsm_handler(pbkdf2_sha512, 'pbkdf2_sha512')
