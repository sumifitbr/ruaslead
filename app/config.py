# app/config.py
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

class Config:
    # Segurança
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")

    # Banco SQLite
    DB_PATH = os.getenv(
        "DB_PATH",
        str(BASE_DIR / "data" / "app.db")  # local
    )

    # URL base (QR / redirects)
    BASE_URL = os.getenv(
        "BASE_URL",
        "http://127.0.0.1:5000"
    )

    # Bootstrap admin (MVP)
    ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "")
    ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
