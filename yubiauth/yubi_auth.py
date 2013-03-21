from sqlalchemy.exc import IntegrityError

from model import Session, User

__all__ = [
    'YubiAuth'
]


class YubiAuth():
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

    def list_users(self):
        """
        Gets all available users.

        Gets a list of all users, represented as dicts containing id and name.

        @return: A list of users
        @rtype: list
        """
        return [
            {'id': row[0], 'name': row[1]}
            for row in self.session.query(User.id, User.name).all()
        ]

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
            if isinstance(user_username_or_id, int):
                return query.get(user_username_or_id)
            else:
                return query.filter(User.name == user_username_or_id).one()

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

    def delete_user(self, user):
        """
        Deletes the given user.

        @param user: The user to delete.
        @type user: C{User}
        """
        self.session.delete(user)
        if self.commit():
            return
        raise ValueError("Error deleting user: '%s'" % (user.name))
