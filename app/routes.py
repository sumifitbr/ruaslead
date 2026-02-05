from datetime import datetime
from urllib.parse import urlparse
import os

from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, send_file, abort, after_this_request
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import check_password_hash, generate_password_hash

import qrcode

from .db import get_db, init_db
from .auth import DBUser, admin_required

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

def is_admin() -> bool:
    return bool(getattr(current_user, "role", None) == "admin")

def _fetch_qr_or_404(db, qr_id: int):
    """Admin pode ver tudo. User só o que é dele."""
    if is_admin():
        qr = db.execute("SELECT * FROM qr_codes WHERE id = ?", (qr_id,)).fetchone()
    else:
        qr = db.execute(
            "SELECT * FROM qr_codes WHERE id = ? AND owner_user_id = ?",
            (qr_id, current_user.id),
        ).fetchone()

    if not qr:
        abort(404)
    return qr

def _fetch_qr_by_code_for_png(db, code: str):
    """Para PNG: admin tudo; user só dele."""
    if is_admin():
        return db.execute("SELECT * FROM qr_codes WHERE code = ?", (code,)).fetchone()
    return db.execute(
        "SELECT * FROM qr_codes WHERE code = ? AND owner_user_id = ?",
        (code, current_user.id),
    ).fetchone()

@main_bp.before_app_request
def ensure_db():
    init_db()

# ---------------- AUTH ----------------
@main_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        db = get_db()
        user_row = db.execute(
            "SELECT * FROM users WHERE email = ? AND is_active = 1",
            (email,),
        ).fetchone()

        # bootstrap admin (caso DB ainda não tenha o admin)
        if (
            not user_row
            and email == current_app.config["ADMIN_EMAIL"].strip().lower()
            and password == current_app.config["ADMIN_PASSWORD"]):
            pw_hash = generate_password_hash(password)
            db.execute("""
              INSERT OR REPLACE INTO users (id, name, email, password_hash, role, is_active)
              VALUES (
                COALESCE((SELECT id FROM users WHERE email = ?), NULL),
                ?, ?, ?, 'admin', 1
              )
            """, (email, "Admin", email, pw_hash))
            db.commit()
            user_row = db.execute(
                "SELECT * FROM users WHERE email = ? AND is_active = 1",
                (email,),
            ).fetchone()

        if not user_row or not check_password_hash(user_row["password_hash"], password):
            flash("Login inválido.")
            return render_template("login.html")

        login_user(DBUser(user_row))
        return redirect(url_for("main.dashboard"))

    return render_template("login.html")

@main_bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("main.login"))

# ---------------- ADMIN USERS ----------------
@main_bp.route("/admin/users", methods=["GET", "POST"])
@login_required
@admin_required
def admin_users():
    db = get_db()

    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        role = (request.form.get("role") or "user").strip().lower()

        if not email or not password:
            flash("Email e senha são obrigatórios.")
            return redirect(url_for("main.admin_users"))

        if role not in ("admin", "user"):
            role = "user"

        exists = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if exists:
            flash("Já existe um usuário com esse email.")
            return redirect(url_for("main.admin_users"))

        db.execute("""
          INSERT INTO users (name, email, password_hash, role, is_active)
          VALUES (?, ?, ?, ?, 1)
        """, (name, email, generate_password_hash(password), role))
        db.commit()
        flash("Usuário criado com sucesso!")
        return redirect(url_for("main.admin_users"))

    users = db.execute("""
      SELECT
        id, name, email, role, is_active, created_at
      FROM users
      ORDER BY id DESC
    """).fetchall()

    return render_template("admin_users.html", users=users)

# ---------------- PORTAL ----------------
@main_bp.route("/")
@login_required
def dashboard():
    db = get_db()

    if is_admin():
        rows = db.execute("""
          SELECT
            q.*,
            u.name  AS owner_name,
            u.email AS owner_email,
            (SELECT COUNT(*) FROM qr_access_logs l WHERE l.qr_code_id = q.id) AS scans
          FROM qr_codes q
          LEFT JOIN users u ON u.id = q.owner_user_id
          ORDER BY q.id DESC
        """,).fetchall()
        scope_label = "Todos os QRs (admin)"
    else:
        rows = db.execute("""
          SELECT
            q.*,
            (SELECT COUNT(*) FROM qr_access_logs l WHERE l.qr_code_id = q.id) AS scans
          FROM qr_codes q
          WHERE q.owner_user_id = ?
          ORDER BY q.id DESC
        """, (current_user.id,)).fetchall()
        scope_label = "Seus QRs"

    return render_template("dashboard.html", rows=rows, scope_label=scope_label)

@main_bp.route("/qr/new", methods=["POST"])
@login_required
def new_qr():
    raw_code = request.form.get("code", "").strip()
    description = request.form.get("description", "").strip()
    template_type = request.form.get("template_type", "Aluguel")

    if not raw_code:
        flash("Informe um código.")
        return redirect(url_for("main.dashboard"))

    if template_type not in ("Aluguel", "Venda"):
        template_type = "Aluguel"

    current_year = datetime.now().year
    code = f"QR-{current_year}-{raw_code}"

    db = get_db()
    try:
        db.execute("""
          INSERT INTO qr_codes (code, current_url, status, description, template_type, owner_user_id, created_at, updated_at)
          VALUES (?, NULL, 'Pendente', ?, ?, ?, ?, ?)
        """, (code, description, template_type, current_user.id, _now_utc(), _now_utc()))
        db.commit()
        flash("QR criado com sucesso.")
    except Exception as e:
        current_app.logger.error(f"Erro ao criar QR: {e}")
        flash("Esse código já existe.")
    return redirect(url_for("main.dashboard"))


@main_bp.route("/qr/<int:qr_id>/edit", methods=["GET", "POST"])
@login_required
def edit_qr(qr_id: int):
    db = get_db()
    qr = _fetch_qr_or_404(db, qr_id)

    if request.method == "POST":
        current_url = request.form.get("current_url", "").strip()
        description = request.form.get("description", "").strip()
        status_from_form = request.form.get("status", "active").strip()
        template_type = request.form.get("template_type", "Aluguel")

        # Validações
        if current_url and not is_valid_http_url(current_url):
            flash("URL inválida. Use http:// ou https:// (com domínio).")
            return render_template("edit_qr.html", qr=qr)

        if status_from_form not in ("active", "inactive", "Pendente"):
            status_from_form = "active"

        if template_type not in ("Aluguel", "Venda"):
            template_type = "Aluguel"

        # Lógica de status
        new_status = status_from_form
        if not (current_url or "").strip():
            # Se não há URL, força o status para pendente
            new_status = "Pendente"
        elif qr["status"] == "Pendente" and status_from_form == "Pendente":
            # Se tinha status pendente, ganhou uma URL e o usuário não mudou o status no form,
            # o status é ativado automaticamente.
            new_status = "active"

        db.execute("""
          UPDATE qr_codes
          SET current_url = ?, description = ?, status = ?, template_type = ?, updated_at = ?
          WHERE id = ?
        """, (current_url if current_url else None, description, new_status, template_type, _now_utc(), qr_id))
        db.commit()
        flash("Atualizado com sucesso.")
        # Redireciona de volta para a pág de edição para ver as mudanças
        return redirect(url_for("main.edit_qr", qr_id=qr_id))

    public_url = f"{current_app.config['BASE_URL'].rstrip('/')}/r/{qr['code']}"
    return render_template("edit_qr.html", qr=qr, public_url=public_url)


@main_bp.route("/qr/<int:qr_id>/delete", methods=["POST"])
@login_required
def delete_qr(qr_id: int):
    db = get_db()
    # Garante que o usuário tem permissão para deletar
    qr = _fetch_qr_or_404(db, qr_id)

    # Deleta logs e depois o QR
    db.execute("DELETE FROM qr_access_logs WHERE qr_code_id = ?", (qr_id,))
    db.execute("DELETE FROM qr_codes WHERE id = ?", (qr_id,))
    db.commit()

    flash(f"QR Code \"{qr['code']}\" excluído com sucesso.")
    return redirect(url_for("main.dashboard"))


@main_bp.route("/qr/<string:code>/png")
@login_required
def qr_png(code: str):
    db = get_db()
    qr = _fetch_qr_by_code_for_png(db, code)

    if not qr:
        abort(404)

    # Cria o objeto QR Code
    qr_img = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    public_url = f"{current_app.config['BASE_URL'].rstrip('/')}/r/{qr['code']}"
    qr_img.add_data(public_url)
    qr_img.make(fit=True)

    img = qr_img.make_image(fill_color="black", back_color="white")

    # Salva a imagem temporariamente
    # current_app.config["TEMP_DIR"] deve apontar para o diretório _tmp
    temp_dir = current_app.config.get("TEMP_DIR", "/tmp") # Fallback para /tmp
    os.makedirs(temp_dir, exist_ok=True) # Garante que o diretório existe
    temp_file_path = os.path.join(temp_dir, f"qr_{code}.png")
    img.save(temp_file_path)

    # Envia o arquivo e depois o apaga. after_request_callbacks para garantir que o arquivo seja apagado.
    @after_this_request
    def remove_file(response):
        try:
            os.remove(temp_file_path)
        except Exception as e:
            current_app.logger.error(f"Erro ao remover arquivo temporário: {e}")
        return response

    return send_file(temp_file_path, mimetype="image/png", as_attachment=True, download_name=f"qr_{code}.png")


@main_bp.route("/qr/<int:qr_id>/stats")
@login_required
def qr_stats(qr_id: int):
    db = get_db()
    qr = _fetch_qr_or_404(db, qr_id)

    # Total de scans
    total_scans = db.execute(
        "SELECT COUNT(*) FROM qr_access_logs WHERE qr_code_id = ?", (qr_id,)
    ).fetchone()[0]

    # Últimos acessos
    last_accesses = db.execute(
        """
        SELECT accessed_at, ip_address, user_agent, referer
        FROM qr_access_logs
        WHERE qr_code_id = ?
        ORDER BY accessed_at DESC
        LIMIT 50
        """, (qr_id,)
    ).fetchall()

    # Dados para o gráfico
    group_by = request.args.get("group", "day")
    if group_by not in ("day", "week", "month"):
        group_by = "day"

    chart_title = "Scans por Dia"
    date_format = "%Y-%m-%d"
    if group_by == "week":
        chart_title = "Scans por Semana"
        date_format = "%Y-%W" # %W for week number (00-53)
    elif group_by == "month":
        chart_title = "Scans por Mês"
        date_format = "%Y-%m"

    # SQLite strftime for grouping
    chart_data = db.execute(
        f"""
        SELECT strftime('{date_format}', accessed_at) AS period, COUNT(*) AS count
        FROM qr_access_logs
        WHERE qr_code_id = ?
        GROUP BY period
        ORDER BY period ASC
        """, (qr_id,)
    ).fetchall()

    chart_labels = [row["period"] for row in chart_data]
    chart_values = [row["count"] for row in chart_data]

    return render_template(
        "stats.html",
        qr=qr,
        total=total_scans,
        last=last_accesses,
        chart_title=chart_title,
        group=group_by,
        labels=chart_labels,
        values=chart_values,
    )

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

@main_bp.route("/land")
def land():
    return render_template("land.html")

@main_bp.route("/landing")
def landing():
    return render_template("landing.html")

@main_bp.route("/landing_new")
def landing_new():
    return render_template("landing_new.html")
