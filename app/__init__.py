# # import os
# # from flask import Flask
# # from flask_login import LoginManager
# # from dotenv import load_dotenv

# # from .config import Config
# # from .db import close_db
# # from .auth import AdminUser

# # login_manager = LoginManager()
# # login_manager.login_view = "main.login"

# # def create_app():
# #     load_dotenv()

# #     base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
# #     templates_dir = os.path.join(base_dir, "templates")
# #     static_dir = os.path.join(base_dir, "static")

# #     app = Flask(__name__, template_folder=templates_dir, static_folder=static_dir)
# #     app.config.from_object(Config)
# #     app.secret_key = app.config["SECRET_KEY"]

# #     login_manager.init_app(app)

# #     @login_manager.user_loader
# #     def load_user(user_id: str):
# #         if user_id == app.config["ADMIN_EMAIL"]:
# #             return AdminUser(user_id)
# #         return None

# #     from .routes import main_bp
# #     app.register_blueprint(main_bp)

# #     app.teardown_appcontext(close_db)

# #     return app


# import os
# from flask import Flask
# from flask_login import LoginManager
# from dotenv import load_dotenv

# from .config import Config
# from .db import close_db
# from .auth import DBUser

# login_manager = LoginManager()
# login_manager.login_view = "main.login"

# def create_app():
#     load_dotenv()

#     base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
#     templates_dir = os.path.join(base_dir, "templates")
#     static_dir = os.path.join(base_dir, "static")

#     app = Flask(__name__, template_folder=templates_dir, static_folder=static_dir)
#     app.config.from_object(Config)
#     app.secret_key = app.config["SECRET_KEY"]

#     login_manager.init_app(app)

#     @login_manager.user_loader
#     def load_user(user_id: str):
#         # busca usuário por ID no banco
#         try:
#             from .db import get_db
#             db = get_db()
#             row = db.execute("SELECT * FROM users WHERE id = ? AND is_active = 1", (user_id,)).fetchone()
#             if row:
#                 return DBUser(row)
#         except Exception:
#             return None
#         return None

#     from .routes import main_bp
#     app.register_blueprint(main_bp)

#     app.teardown_appcontext(close_db)
#     return app


import os
from flask import Flask
from flask_login import LoginManager
from dotenv import load_dotenv

from .config import Config
from .db import close_db
from .auth import DBUser

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

    # ✅ Ajuste do SQLite: caminho vem do Azure (DB_PATH) ou usa padrão local
    db_path = os.getenv("DB_PATH") or app.config.get("DB_PATH")
    if not db_path:
        db_path = os.path.join(base_dir, "data", "app.db")

    db_dir = os.path.dirname(db_path) or "."
    os.makedirs(db_dir, exist_ok=True)
    app.config["DB_PATH"] = db_path

    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id: str):
        # busca usuário por ID no banco
        try:
            from .db import get_db
            db = get_db()
            row = db.execute(
                "SELECT * FROM users WHERE id = ? AND is_active = 1",
                (user_id,),
            ).fetchone()
            if row:
                return DBUser(row)
        except Exception:
            return None
        return None

    from .routes import main_bp
    app.register_blueprint(main_bp)

    app.teardown_appcontext(close_db)

    # (opcional mas recomendado) cria tabelas/migrações/seed admin
    try:
        from .db import init_db
        with app.app_context():
            init_db()
    except Exception:
        pass

    return app
