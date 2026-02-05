import os

class Config:
    SECRET_KEY = os.getenv("APP_SECRET", "dev-secret-change-me")
    DB_PATH = os.getenv("DB_PATH", "mvp.db")
    BASE_URL = os.getenv("BASE_URL", "http://127.0.0.1:5000")
    ##BASE_URL = os.getenv("BASE_URL", " 192.168.0.122:5000")

    ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@demo.com")
    ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")
