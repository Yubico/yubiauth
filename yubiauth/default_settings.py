# Database configuration string
DATABASE_CONFIGURATION = 'sqlite:///:memory:'

# YubiKey Validation Server URLs
YKVAL_SERVERS = [
    'https://api.yubico.com/wsapi/2.0/verify',
    'https://api2.yubico.com/wsapi/2.0/verify',
    'https://api3.yubico.com/wsapi/2.0/verify',
    'https://api4.yubico.com/wsapi/2.0/verify',
    'https://api5.yubico.com/wsapi/2.0/verify'
]

# Passlib configuration
CRYPT_CONTEXT = {
    #'schemes': ['yhsm_pbkdf2_sha1', 'sha512_crypt', 'sha256_crypt'],
    #'default': 'yhsm_pbkdf2_sha1',
    'schemes': ['sha512_crypt', 'sha256_crypt'],
    'default': 'sha256_crypt',
    'yhsm_pbkdf2_sha1__key_handle': 1,
    'all__vary_rounds': 0.1,
    'sha512_crypt__min_rounds': 60000,
    'sha256_crypt__min_rounds': 80000,
    'admin__sha512_crypt__min_rounds': 120000,
    'admin__sha256_crypt__min_rounds': 160000
}

# Base path to host REST API from.
# The default, 'yubiauth', will serve pages with URLs like
# http://<host>/yubiauth/users and so on.
REST_PATH = 'yubiauth'

# Defines who is required to provide a YubiKey OTP when logging in.
# The available levels are:
# 0 = Permissive. OTPs are not required to authenticate, by anyone.
#
# 1 = Require when provisioned. OTPs are required by all users that
# have a YubiKey assigned to them.
#
# 2 = Always require. OTPs are required by all users. If no YubiKey
# has been assigned, that user cannot log in, unless auto-provisioning
# is enabled.
SEURITY_LEVEL = 2

# YubiHSM, only needed if you have a YubiHSM.
# Setting the 'YHSM_DEVICE' environment variable will override this.
YHSM_DEVICE = '/dev/ttyACM0'
