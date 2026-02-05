import sqlite3
from flask import g, current_app
from werkzeug.security import generate_password_hash


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DB_PATH"])
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(_=None):
    db = g.pop("db", None)
    if db:
        db.close()


def _table_exists(db, table: str) -> bool:
    r = db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone()
    return r is not None


def _column_exists(db, table: str, col: str) -> bool:
    # Se a tabela não existe, a coluna também não
    if not _table_exists(db, table):
        return False
    rows = db.execute(f"PRAGMA table_info({table})").fetchall()
    return any(r["name"] == col for r in rows)


def init_db():
    db = get_db()

    # 1) Cria tabelas BASE (sem assumir owner_user_id já existente)
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      is_active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

    CREATE TABLE IF NOT EXISTS qr_codes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      code TEXT UNIQUE NOT NULL,
      current_url TEXT,
      status TEXT NOT NULL DEFAULT 'active',
      description TEXT,
      template_type TEXT NOT NULL DEFAULT 'Aluguel',
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

    # 2) Migração segura: adiciona owner_user_id se não existir
    if not _column_exists(db, "qr_codes", "owner_user_id"):
        try:
            db.execute("ALTER TABLE qr_codes ADD COLUMN owner_user_id INTEGER")
            db.commit()
        except Exception:
            # Se já existe (condição de corrida), ignora
            pass

    # Migração segura: adiciona template_type se não existir
    if not _column_exists(db, "qr_codes", "template_type"):
        try:
            # Adiciona com valor padrão para registros existentes
            db.execute("ALTER TABLE qr_codes ADD COLUMN template_type TEXT NOT NULL DEFAULT 'Aluguel'")
            db.commit()
        except Exception:
            pass

    # 3) Índice do owner_user_id (só agora, com coluna garantida)
    try:
        db.execute("CREATE INDEX IF NOT EXISTS idx_qr_codes_owner_user_id ON qr_codes(owner_user_id)")
        db.commit()
    except Exception:
        pass

    # 4) Seed / upsert do admin do .env (bootstrap)
    admin_email = (current_app.config.get("ADMIN_EMAIL") or "").strip().lower()
    admin_password = current_app.config.get("ADMIN_PASSWORD") or ""

    if admin_email and admin_password:
        row = db.execute("SELECT id FROM users WHERE email = ?", (admin_email,)).fetchone()
        pw_hash = generate_password_hash(admin_password)

        if row:
            db.execute("""
              UPDATE users
              SET password_hash = ?, role = 'admin', is_active = 1
              WHERE email = ?
            """, (pw_hash, admin_email))
            admin_id = row["id"]
        else:
            db.execute("""
              INSERT INTO users (name, email, password_hash, role, is_active)
              VALUES (?, ?, ?, 'admin', 1)
            """, ("Admin", admin_email, pw_hash))
            admin_id = db.execute("SELECT id FROM users WHERE email = ?", (admin_email,)).fetchone()["id"]

        db.commit()

        # 5) Backfill: QRs antigos sem dono -> admin
        try:
            db.execute("""
                UPDATE qr_codes
                SET owner_user_id = ?
                WHERE owner_user_id IS NULL
            """, (admin_id,))
            db.commit()
        except Exception:
            pass
