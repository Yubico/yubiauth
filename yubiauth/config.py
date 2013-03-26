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
        'schemes': ['yhsm_pbkdf2_sha1', 'sha512_crypt', 'sha256_crypt'],
        'default': 'yhsm_pbkdf2_sha1',
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
