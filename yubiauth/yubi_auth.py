from sqlalchemy.exc import IntegrityError

from model import Session, User, YubiKey

__all__ = [
    'YubiAuth'
]


class YubiAuth():
    def __init__(self, create_session=Session):
        self.session = create_session()

    def __del__(self):
        self.session.close()

    def _commit(self):
        try:
            self.session.commit()
            return True
        except IntegrityError:
            self.session.rollback()
            return False

    def _row_to_dict(self, user_tuple):
        return {
            'id': user_tuple[0],
            'name': user_tuple[1]
        }

    def _get_user_model(self, user_username_or_id):
        if isinstance(user_username_or_id, User):
            return user_username_or_id

        query = self.session.query(User)
        if isinstance(user_username_or_id, dict):
            return query.get(user_username_or_id['id'])
        elif isinstance(user_username_or_id, int):
            return query.get(user_username_or_id)
        else:
            return query.filter(User.name == user_username_or_id).one()

    def list_users(self):
        return [self._row_to_dict(row) for row in
                self.session.query(User.id, User.name)]

    def get_user(self, user_username_or_id):
        if isinstance(user_username_or_id, User):
            row = (user_username_or_id.id, user_username_or_id.name)
        elif isinstance(user_username_or_id, dict):
            return user_username_or_id
        else:
            query = self.session.query(User.id, User.name)
            if isinstance(user_username_or_id, int):
                row = query.filter(User.id == user_username_or_id).one()
            else:
                row = query.filter(User.name == user_username_or_id).one()

        return self._row_to_dict(row)

    def create_user(self, username, password):
        user_model = User(username, password)
        self.session.add(user_model)
        if self._commit():
            return self.get_user(user_model.id)
        raise ValueError("Error creating user: '%s'" % (username))

    def delete_user(self, user_username_or_id):
        user_model = self._get_user_model(user_username_or_id)
        user = self.get_user(user_model)
        self.session.delete(user_model)
        if self._commit():
            return user
        raise ValueError("Error deleting user: '%s'" % (user_username_or_id))

    def set_password(self, user_username_or_id, password):
        user_model = self._get_user_model(user_username_or_id)
        user_model.set_password(password)
        if self._commit():
            return self.get_user(user_model)
        raise ValueError("Error setting password for user: '%s'"
                         % (user_username_or_id))

    def validate_password(self, user_username_or_id, password):
        user_model = self._get_user_model(user_username_or_id)
        return user_model.validate_password(password)

    def assign_yubikey(self, user_username_or_id, public_id):
        user_model = self._get_user_model(user_username_or_id)
        user_model.yubikeys.append(YubiKey(public_id))
        if not self._commit():
            raise ValueError("Error assigning YubiKey '%s' to user '%s'"
                             % (public_id, user_username_or_id))

    def unassign_yubikey(self, user_username_or_id, public_id):
        user_model = self._get_user_model(user_username_or_id)
        yubikey_model = self.session.query(YubiKey).\
            filter(YubiKey.user == user_model).one()
        self.session.delete(yubikey_model)
        if not self._commit():
            raise ValueError("Error unassigning YubiKey '%s' from user '%s'"
                             % (public_id, user_username_or_id))

    def validate_otp(self, user_username_or_id, otp):
        user_model = self._get_user_model(user_username_or_id)
        return user_model.validate_otp(otp)
