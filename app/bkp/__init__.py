import os
from flask import Flask
from flask_login import LoginManager
from dotenv import load_dotenv

from .config import Config
from .db import close_db
from .auth import AdminUser

login_manager = LoginManager()
login_manager.login_view = "main.login"

def create_app():
    load_dotenv()

    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    templates_dir = os.path.join(base_dir, "templates")
    static_dir = os.path.join(base_dir, "static")

    app = Flask(__name__, template_folder=templates_dir, static_folder=static_dir)
    app.config.from_object(Config)
    app.secret_key = app.config["SECRET_KEY"]

    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id: str):
        if user_id == app.config["ADMIN_EMAIL"]:
            return AdminUser(user_id)
        return None

    from .routes import main_bp
    app.register_blueprint(main_bp)

    app.teardown_appcontext(close_db)

    return app
