from flask_login import UserMixin

class AdminUser(UserMixin):
    def __init__(self, email: str):
        self.id = email
        self.email = email
