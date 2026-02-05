import sqlite3
from flask import g, current_app

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DB_PATH"])
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(_=None):
    db = g.pop("db", None)
    if db:
        db.close()

def init_db():
    db = get_db()
    db.executescript("""
    CREATE TABLE IF NOT EXISTS qr_codes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      code TEXT UNIQUE NOT NULL,
      current_url TEXT,
      status TEXT NOT NULL DEFAULT 'active',
      description TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_qr_codes_code ON qr_codes(code);

    CREATE TABLE IF NOT EXISTS qr_access_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      qr_code_id INTEGER NOT NULL,
      accessed_at TEXT NOT NULL,
      ip_address TEXT,
      user_agent TEXT,
      referer TEXT,
      FOREIGN KEY(qr_code_id) REFERENCES qr_codes(id)
    );

    CREATE INDEX IF NOT EXISTS idx_logs_qr_code_id ON qr_access_logs(qr_code_id);
    """)
    db.commit()
