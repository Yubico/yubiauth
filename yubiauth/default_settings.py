#
# Core API settings
#

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

# YubiKey Validation server API key and secret
YKVAL_CLIENT_ID = 11004
YKVAL_CLIENT_SECRET = '5Vm3Zp2mUTQHMo1DeG9tdojpc1Y='

# Allow users with no password to log in without providing a password.
# When set to False (default), a user with no password will be unable to log
# in.
#
# WARNING: In combination with the SECURITY_LEVEL settings, this setting may
# allow a user to log in using ONLY a username. If you're unsure if you need
# this, leave it to False.
ALLOW_EMPTY_PASSWORDS = False

# LDAP server configuration
# YubiAuth can optionally use an LDAP server such as OpenLDAP or Active
# Directory to validate users instead of the built-in user database.
# NOTE: When USE_LDAP is set to True, password validation will go through LDAP
# and changing the password of a user will not work.
USE_LDAP = False

# LDAP server URI to bind to.
LDAP_SERVER = "ldap://127.0.0.1"

# Template for the bind DN to use for a user. The User object will be passed to
# the templates .format() method, and it's attributes can thus be used within
# the DN. For example: {user.name} can be used.
# For Active Directory, the following command can be used on the Windows Server
# to determine the Bind DN: "dsquery user -name *"
#
# NOTE: If a user has an attribute named _ldap_bind_dn, this will override the
# below setting for that user only.
LDAP_BIND_DN = "uid={user.name},ou=People,dc=example,dc=com"

# When True, users will be automatically created in YubiAuth when a user that
# exists in the LDAP database tried to authenticate using correct credentials.
LDAP_AUTO_IMPORT = True

# Use a YubiHSM for increased security
# This requires the pyhsm package, and should be used with the yhsm-daemon
# utility that comes with it.
USE_HSM = False

# YubiHSM, only used if USE_HSM is True.
# Setting the 'YHSM_DEVICE' environment variable will override this.
YHSM_DEVICE = 'yhsm://localhost:5348'

# Passlib configuration
# Will default to using yhsm_pbkdf2_sha1 for password hashes if a HSM is
# available.
CRYPT_CONTEXT = {
    'schemes': ['yhsm_pbkdf2_sha1', 'sha256_crypt'] if USE_HSM
    else ['sha256_crypt'],
    'deprecated': ['sha256_crypt'] if USE_HSM else [],
    'default': 'yhsm_pbkdf2_sha1' if USE_HSM else 'sha256_crypt',
    'yhsm_pbkdf2_sha1__key_handle': 1,
    'all__vary_rounds': 0.1,
    'sha256_crypt__min_rounds': 80000,
    'admin__sha256_crypt__min_rounds': 160000
}

#
# Client API settings
#

# Defines who is required to provide a YubiKey OTP when logging in.
# The available levels are:
# 0 = Permissive. OTPs are not required to authenticate, by anyone.
#
# 1 = Require when provisioned. OTPs are required by all users that have a
# YubiKey assigned to them.
#
# 2 = Always require. OTPs are required by all users. If no YubiKey has been
# assigned, that user cannot log in, unless auto-provisioning is enabled.
#
# WARNING: In combination with the ALLOW_EMPTY_PASSWORDS settings, setting
# this to 0 may allow a user to log in using ONLY a username.
SECURITY_LEVEL = 1

# Auto-provision YubiKeys.
# When enabled, an attempt to authenticate a user that doesn't have a YubiKey
# assigned with a valid YubiKey OTP, will cause that YubiKey to become
# automatically assigned to the user.
AUTO_PROVISION = True

# When set to True, allow users authenticating with a YubiKey to omit their
# username, using the OTP to do a lookup on the username.
YUBIKEY_IDENTIFICATION = False

# When set to True, allow users to register accounts via the client API.
ENABLE_USER_REGISTRATION = False

# When set to True, allow users to delete their own accounts via the client
# API.
ALLOW_USER_DELETE = False

# Beaker configuration, which is used for session management.
BEAKER = {
    'session.lock_dir': '/tmp/cache/lock',
    'session.type': 'ext:database',
    'session.auto': True,
    'session.key': 'YubiAuth-Session',
    'session.secret': 'LGnYUI5ZeSQ5ooGykySO9vMHKKyGwoC1',
}
