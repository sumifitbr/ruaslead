# from flask_login import UserMixin

# class AdminUser(UserMixin):
#     def __init__(self, email: str):
#         self.id = email
#         self.email = email


from functools import wraps
from flask import abort
from flask_login import UserMixin, current_user

class DBUser(UserMixin):
    def __init__(self, row):
        # row é sqlite3.Row
        self._row = row
        self.id = str(row["id"])  # Flask-Login usa string

    @property
    def email(self):
        return self._row["email"]

    @property
    def name(self):
        return self._row["name"]

    @property
    def role(self):
        return self._row["role"]

    @property
    def is_active_flag(self):
        return bool(self._row["is_active"])

    def is_active(self):
        return self.is_active_flag

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            abort(401)
        if getattr(current_user, "role", None) != "admin":
            abort(403)
        return fn(*args, **kwargs)
    return wrapper
