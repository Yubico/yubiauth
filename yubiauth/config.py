__all__ = [
    'settings'
]


#TODO: Read settings file /etc/yubico/yubiauth/yubiauth.cfg
settings = {
    'db': 'sqlite:///:memory:',
    'ykval': [
        'https://api.yubico.com/wsapi/2.0/verify',
        'https://api2.yubico.com/wsapi/2.0/verify',
        'https://api3.yubico.com/wsapi/2.0/verify',
        'https://api4.yubico.com/wsapi/2.0/verify',
        'https://api5.yubico.com/wsapi/2.0/verify'
    ]
}
