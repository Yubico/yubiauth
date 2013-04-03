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

from sqlalchemy.exc import IntegrityError

from model import Session, User, YubiKey, AttributeAssociation

__all__ = [
    'YubiAuth'
]


class YubiAuth(object):
    """
    Main class for interacting with the YubiAuth backend.
    """
    def __init__(self, create_session=Session):
        self.session = create_session()

    def __del__(self):
        self.session.close()

    def commit(self):
        """
        Commits any unchanged modifications to the database.

        @return: True if successful, False on error
        @rtype: bool
        """
        try:
            self.session.commit()
            return True
        except IntegrityError:
            self.session.rollback()
            return False

    def query_users(self, **kwargs):
        """
        Performs a query on all available users.

        Gets a list of all users matching the filter, represented as dicts
        containing id and name.

        Filtering is dony by supplying keyword arguments, where each key-value
        pair will match an Attribute for the user.

        A special keyword "yubikey" will create a filter on users assigned
        to the YubiKey with the prefix of the value given.

        Example:

        # Get users with the YubiKey ccccccccccce:
        query_users(yubikey='ccccccccccce')

        # Get users with the attribute 'area' equal to 'Stockholm'
        # AND the attribute 'admin' equal to 'True':
        query_users(area='Stockholm', admin='True')

        For more advanced querying, use the session attribute directly.

        @return: A list of users
        @rtype: list
        """
        query = self.session.query(User.id, User.name)

        if 'yubikey' in kwargs:
            query = query.filter(User.yubikeys.any(prefix=kwargs['yubikey']))
            del kwargs['yubikey']

        for key in kwargs:
            query = query.filter(
                User._attribute_association.has(
                    AttributeAssociation._attributes.any(
                        key=key,
                        value=kwargs[key]
                    )
                )
            )

        return [
            {'id': row[0], 'name': row[1]}
            for row in query.all()
        ]

    def query_yubikeys(self, **kwargs):
        """
        Performs a query on all available YubiKeys.

        Gets a list of all YubiKeys matching the filter.

        Filtering is dony by supplying keyword arguments, where each key-value
        pair will match an Attribute for the YubiKey.

        Example:
        # Get YubiKey with the attribute 'revoke' equal to 'foo':
        query_yubikeys(revoke='foo')

        @return: A list of YubiKeys
        @rtype: list
        """
        query = self.session.query(YubiKey)

        for key in kwargs:
            query = query.filter(
                YubiKey._attribute_association.has(
                    AttributeAssociation._attributes.any(
                        key=key,
                        value=kwargs[key]
                    )
                )
            )

        return query.all()

    def get_user(self, user_username_or_id):
        """
        Does a lookup for a user based on a username or ID.

        For practicality also checks if the argument is a C{User},
        in which case it is returned as-is.

        @param user_username_or_id: A username or user ID
        @type user_username_or_id: C{User} or string or int
        """
        if isinstance(user_username_or_id, User):
            return user_username_or_id
        else:
            query = self.session.query(User)
            try:
                if isinstance(user_username_or_id, int):
                    user = query.get(user_username_or_id)
                    if user:
                        return user
                else:
                    return query.filter(User.name == user_username_or_id).one()
            except:
                pass

        raise LookupError('User not found!')

    def get_yubikey(self, prefix):
        """
        Gets a YubiKey by its prefix.

        @param prefix: A YubiKey prefix
        @type prefix: string
        """
        return self.session.query(YubiKey).filter(
            YubiKey.prefix == prefix).one()

    def create_user(self, username, password):
        """
        Creates a new user, immediately committing the change to the database.

        @param username: A unique username to give the new user.
        @type username: string

        @param password: The password to give the new user.
        @type password: string

        @return: The created user.
        @rtype: C{User}
        """
        user = User(username, password)
        self.session.add(user)
        if self.commit():
            return user
        raise ValueError("Error creating user: '%s'" % (username))

    def authenticate(self, name, password, otp=None):
        """
        Authenticates a user.

        Takes authentication parameters for a user and returns the user upon
        successful authentication. Authentication is concidered successful if:
        The password is valid for the user with the given username, and either:

        A valid YubiKey OTP is given for a YubiKey which is assigned to the
        user.

            OR

        No otp is given and the user has no YubiKeys assigned.

        @param name: The username of the user.
        @type name: string

        @param password: The password of the user.
        @type password: string

        @param otp: A YubiKey OTP from one of the users YubiKeys.
        @type otp: string

        @return: A C{User} upon successful authentication, or None
        @rtype: C{User}
        """
        user = self.get_user(name)
        valid_pass = user.validate_password(password)

        if otp:
            valid_otp = user.validate_otp(otp)
        else:
            valid_otp = len(user.yubikeys) == 0

        if valid_pass and valid_otp:
            return user
        else:
            return None
