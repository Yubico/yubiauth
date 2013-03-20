from sqlalchemy.exc import IntegrityError

from model import Session, User

__all__ = [
    'YubiAuth'
]


class YubiAuth():
    def __init__(self, create_session=Session):
        self.session = create_session()

    def __del__(self):
        self.session.close()

    def commit(self):
        try:
            self.session.commit()
            return True
        except IntegrityError:
            self.session.rollback()
            return False

    def list_users(self):
        return self.session.query(User).all()

    def get_user(self, user_username_or_id):
        if isinstance(user_username_or_id, User):
            return user_username_or_id
        else:
            query = self.session.query(User)
            if isinstance(user_username_or_id, int):
                return query.get(user_username_or_id)
            else:
                return query.filter(User.name == user_username_or_id).one()

    def create_user(self, username, password):
        user = User(username, password)
        self.session.add(user)
        if self.commit():
            return user
        raise ValueError("Error creating user: '%s'" % (username))

    def delete_user(self, user):
        self.session.delete(user)
        if self.commit():
            return
        raise ValueError("Error deleting user: '%s'" % (user.name))
