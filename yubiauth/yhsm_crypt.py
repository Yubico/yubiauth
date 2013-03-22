__all__ = [
    'yhsm_crypt'
]

from passlib.utils import to_unicode
from passlib.utils.handlers import GenericHandler, HasSalt

# from pyhsm.util import key_handle_to_int
from config import settings


_UDOLLAR = u'$'
_UDOUBLEDOLLAR = u'$$'
_UHSM = u'hsm='
_UKH = u'kh='
_UDEFAULT_HSM = u'main'
_UDEFAULT_KH = u'1'
RANDOM_NONCE = '000000000000'


class yhsm_crypt(HasSalt, GenericHandler):
    """
    Handler for generating and verifying AEADs from passwords using a YubiHSM.

    Nonce is stored as salt, AEAD data is stored as checksum.

    Example:
    $yhsm$kh=1$1a16ed273b5f$Pl<snip>2Y.$$$6$rounds=40000$AfrT8KTSqpVacmwT$
    """
    name = 'yhsm_crypt'
    ident = u'$yhsm$'
    setting_kwds = ("hsm", "key_handle, wrapped_hash")

    def __init__(self, hsm=None, key_handle=_UDEFAULT_KH,
                 wrapped_hash=None, **kwds):
        if not 'salt' in kwds:
            kwds['salt'] = RANDOM_NONCE

        super(yhsm_crypt, self).__init__(**kwds)
        self.hsm = hsm
        self.key_handle = key_handle
        self.wrapped_hash = wrapped_hash

    @classmethod
    def from_string(cls, hash):
        """
        Format is:
        $yhsm$[hsm=<hsm_name>$][kh=<key_handle>$]nonce$aead$$checksum

        Where checksum is another hash without checksum.
        """
        hash = to_unicode(hash, 'ascii', 'hash')
        if not hash.startswith(cls.ident):
            raise ValueError('invalid yhsm_crypt hash')

        yhsm, wrapped_hash = hash[6:].split(_UDOUBLEDOLLAR, 1)

        parts = yhsm.split(_UDOLLAR)

        if parts[0].startswith(_UHSM):
            assert len(_UHSM) == 4
            hsm = parts.pop(0)[4:]
        else:
            hsm = _UDEFAULT_HSM

        if parts[0].startswith(_UKH):
            assert len(_UKH) == 3
            key_handle = parts.pop(0)[3:]
        else:
            key_handle = _UDEFAULT_KH

        if len(parts) != 2:
            raise ValueError('invalid yhsm_crypt hash')
        nonce, aead = parts

        return cls(
            hsm=hsm,
            key_handle=key_handle,
            wrapped_hash=wrapped_hash,
            salt=nonce,
            checksum=aead
        )

    def to_string(self):
        hash = self.ident

        if self.hsm and self.hsm != _UDEFAULT_HSM:
            hash += "%s%s$" % (_UHSM, self.hsm)

        hash += "%s%s$%s$%s$$%s" % (
            _UKH,
            self.key_handle,
            self.salt,
            self.checksum,
            self.wrapped_hash
        )

        return hash

    #def _generate_salt(self, salt_size):
    #    # YubiHSM will generate a random nonce if given 0.
    #    return RANDOM_NONCE

    def _calc_wrapped_checksum(self, secret):
        context = settings['pwd_context']
        handler = context.identify(self.wrapped_hash, resolve=True)
        record = handler.from_string(self.wrapped_hash)
        return record.calc_checksum(secret)

    def _encrypt_checksum(self, checksum):
        # TODO: encrypt checksum
        # try:
        #    aead = hsm.generate_aead_simple(
        #        self.salt.decode('hex'),
        #        key_handle_to_int(self.key_handle),
        #        checksum
        #    )
        #    self.salt = aead.nonce.encode('hex')
        # except pyhsm.exception.YHSM_CommandFailed, e:
        #    raise exc.InvalidHashError(self.__class__)
        # return aead.data.encode('hex')
        self.salt = 'nonce'
        return checksum

    def _calc_checksum(self, secret):
        checksum = self._calc_wrapped_checksum(secret)
        return self._encrypt_checksum(checksum)

    @classmethod
    def encrypt(cls, secret, **kwds):
        self = cls(**kwds)

        context = settings['pwd_context']
        inner_handler = context.policy.get_handler()
        if inner_handler == cls:
            # We obviously can't use ourself for the inner hash
            for scheme in context.policy.schemes():
                if scheme != cls.__name__:
                    inner_handler = context.policy.get_handler(scheme)
                    break
            else:
                # No scheme available, crap!
                raise Exception('No other scheme configured! \
                        yhsm_crypt requires at least one more scheme')

        inner_hash = inner_handler.encrypt(secret)
        record = inner_handler.from_string(inner_hash)
        self.checksum = self._encrypt_checksum(record.checksum)
        record.checksum = None
        self.wrapped_hash = record.to_string()
        return self.to_string()

    @classmethod
    def verify(cls, secret, hash, **context):
        self = cls.from_string(hash, **context)
        if self.checksum is None:
            raise TypeError('checksum is missing!')

        checksum = self._calc_wrapped_checksum(secret)

        # TODO: validate encrypted checksum
        # return hsm.validate_aead(
        #    self.salt.decode('hex'),
        #    key_handle_to_int(self.key_handle),
        #    self.checksum,
        #    checksum
        #)

        return checksum == self.checksum
