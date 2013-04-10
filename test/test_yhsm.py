from passlib.context import CryptContext
from passlib.registry import register_crypt_handler_path

register_crypt_handler_path('yhsm_pbkdf2_sha1', 'yubiauth.yhsm')
register_crypt_handler_path('yhsm_pbkdf2_sha256', 'yubiauth.yhsm')
register_crypt_handler_path('yhsm_pbkdf2_sha512', 'yubiauth.yhsm')

from nose.plugins.attrib import attr

PASSWORDS = [
    'foobar',
    '',
    '1234567890',
    '!"#%&/()=?',
    chr(150) + chr(200) + chr(255)
]

context = None


@attr(hsm=True)
def setup():
    global context
    context = CryptContext(
        schemes=['yhsm_pbkdf2_sha1', 'yhsm_pbkdf2_sha256',
                 'yhsm_pbkdf2_sha512'],
        default='yhsm_pbkdf2_sha1',
        all__key_handle=1,
        all__rounds=10
    )


def _algorithm_test(scheme):
    for pwd in PASSWORDS:
        res = context.encrypt(pwd, scheme=scheme)
        assert context.identify(res) == scheme
        assert context.verify(pwd, res)
        assert res != context.encrypt(pwd, scheme=scheme)


@attr(hsm=True)
def test_yhsm_pbkdf2_sha1():
    _algorithm_test('yhsm_pbkdf2_sha1')


@attr(hsm=True)
def test_yhsm_pbkdf2_sha256():
    _algorithm_test('yhsm_pbkdf2_sha256')


@attr(hsm=True)
def test_yhsm_pbkdf2_sha512():
    _algorithm_test('yhsm_pbkdf2_sha512')
