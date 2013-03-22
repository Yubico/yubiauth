__all__ = [
    'settings'
]

from passlib.utils import sys_bits


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
    'crypt_context': {
        'schemes': ['sha512_crypt', 'sha256_crypt'],
        'default': 'sha256_crypt' if sys_bits < 64 else 'sha512_crypt',
        'all__vary_rounds': 0.1,
        'sha512_crypt__min_rounds': 60000,
        'sha256_crypt__min_rounds': 80000,
        'admin__sha512_crypt__min_rounds': 120000,
        'admin__sha256_crypt__min_rounds': 160000
    }
}
