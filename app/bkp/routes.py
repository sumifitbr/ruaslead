from datetime import datetime
from urllib.parse import urlparse
import os

from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, send_file
from flask_login import login_user, login_required, logout_user

import qrcode

from .db import get_db, init_db
from .auth import AdminUser

main_bp = Blueprint("main", __name__)

def _now_utc():
    return datetime.utcnow().isoformat()

def is_valid_http_url(u: str) -> bool:
    if not u:
        return False
    try:
        p = urlparse(u)
        return p.scheme in ("http", "https") and bool(p.netloc)
    except Exception:
        return False

def get_client_ip():
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr

@main_bp.before_app_request
def ensure_db():
    init_db()

# ---------------- AUTH ----------------
@main_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        if email == current_app.config["ADMIN_EMAIL"] and password == current_app.config["ADMIN_PASSWORD"]:
            login_user(AdminUser(email))
            return redirect(url_for("main.dashboard"))

        flash("Login inválido.")
    return render_template("login.html")

@main_bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("main.login"))

# ---------------- PORTAL ----------------
@main_bp.route("/")
@login_required
def dashboard():
    db = get_db()
    rows = db.execute("""
      SELECT q.*,
             (SELECT COUNT(*) FROM qr_access_logs l WHERE l.qr_code_id = q.id) AS scans
      FROM qr_codes q
      ORDER BY q.id DESC
    """).fetchall()
    return render_template("dashboard.html", rows=rows)

@main_bp.route("/qr/new", methods=["POST"])
@login_required
def new_qr():
    code = request.form.get("code", "").strip()
    description = request.form.get("description", "").strip()

    if not code:
        flash("Informe um código (ex: QR-001).")
        return redirect(url_for("main.dashboard"))

    db = get_db()
    try:
        db.execute("""
          INSERT INTO qr_codes (code, current_url, status, description, created_at, updated_at)
          VALUES (?, NULL, 'active', ?, ?, ?)
        """, (code, description, _now_utc(), _now_utc()))
        db.commit()
        flash("QR criado com sucesso.")
    except Exception:
        flash("Esse código já existe.")
    return redirect(url_for("main.dashboard"))

@main_bp.route("/qr/<int:qr_id>/edit", methods=["GET", "POST"])
@login_required
def edit_qr(qr_id: int):
    db = get_db()
    qr = db.execute("SELECT * FROM qr_codes WHERE id = ?", (qr_id,)).fetchone()
    if not qr:
        return ("QR não encontrado", 404)

    if request.method == "POST":
        current_url = request.form.get("current_url", "").strip()
        description = request.form.get("description", "").strip()
        status = request.form.get("status", "active").strip()

        if current_url and not is_valid_http_url(current_url):
            flash("URL inválida. Use http:// ou https:// (com domínio).")
            return render_template("edit_qr.html", qr=qr)

        if status not in ("active", "inactive"):
            flash("Status inválido.")
            return render_template("edit_qr.html", qr=qr)

        db.execute("""
          UPDATE qr_codes
          SET current_url = ?, description = ?, status = ?, updated_at = ?
          WHERE id = ?
        """, (current_url if current_url else None, description, status, _now_utc(), qr_id))
        db.commit()
        flash("Atualizado.")
        return redirect(url_for("main.dashboard"))

    return render_template("edit_qr.html", qr=qr)

@main_bp.route("/qr/<int:qr_id>/stats")
@login_required
def qr_stats(qr_id: int):
    db = get_db()
    qr = db.execute("SELECT * FROM qr_codes WHERE id = ?", (qr_id,)).fetchone()
    if not qr:
        return ("QR não encontrado", 404)

    total = db.execute(
        "SELECT COUNT(*) AS c FROM qr_access_logs WHERE qr_code_id = ?",
        (qr_id,)
    ).fetchone()["c"]

    last = db.execute("""
        SELECT accessed_at, ip_address, user_agent, referer
        FROM qr_access_logs
        WHERE qr_code_id = ?
        ORDER BY id DESC
        LIMIT 20
    """, (qr_id,)).fetchall()

    return render_template("stats.html", qr=qr, total=total, last=last)

@main_bp.route("/qr/<code>/png")
@login_required
def qr_png(code: str):
    base_url = current_app.config["BASE_URL"].rstrip("/")
    qr_url = f"{base_url}/r/{code}"

    img = qrcode.make(qr_url)

    # Windows-friendly temp
    tmp_dir = os.path.join(os.getcwd(), "_tmp")
    os.makedirs(tmp_dir, exist_ok=True)
    tmp_path = os.path.join(tmp_dir, f"{code}.png")

    img.save(tmp_path)

    return send_file(tmp_path, mimetype="image/png", as_attachment=True, download_name=f"{code}.png")

# ---------------- PUBLIC REDIRECT ----------------
@main_bp.route("/r/<code>")
def redirect_qr(code: str):
    db = get_db()
    qr = db.execute("SELECT * FROM qr_codes WHERE code = ?", (code,)).fetchone()

    if not qr:
        return ("QR Code não encontrado.", 404)

    # loga acesso
    db.execute("""
      INSERT INTO qr_access_logs (qr_code_id, accessed_at, ip_address, user_agent, referer)
      VALUES (?, ?, ?, ?, ?)
    """, (
        qr["id"],
        _now_utc(),
        get_client_ip(),
        request.headers.get("User-Agent", ""),
        request.headers.get("Referer", "")
    ))
    db.commit()

    if qr["status"] != "active":
        return ("Este QR está desativado.", 410)

    if not is_valid_http_url(qr["current_url"] or ""):
        return ("Este imóvel não está disponível no momento.", 200)

    return redirect(qr["current_url"], code=302)
