import os
import secrets
import psycopg
from psycopg.rows import dict_row
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, g
from flask_cors import CORS
from werkzeug.security import check_password_hash, generate_password_hash

# --- Настройки ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_URL = os.environ.get("DATABASE_URL")

app = Flask(__name__, static_folder=None)
CORS(app, supports_credentials=True)

SESSIONS = {}
SESSION_TTL_HOURS = 24 * 7

def get_db():
    conn = psycopg.connect(DATABASE_URL, autocommit=True)
    return conn

# Переводим время в Киев (UTC+3)
def now_iso():
    kyiv_tz = timezone(timedelta(hours=3))
    return datetime.now(kyiv_tz).isoformat()

def init_db():
    conn = get_db()
    c = conn.cursor()
    
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY, username VARCHAR(255) UNIQUE NOT NULL,
        email VARCHAR(255), password_hash VARCHAR(255) NOT NULL, role VARCHAR(50) NOT NULL DEFAULT 'admin',
        lang VARCHAR(10) NOT NULL DEFAULT 'uk', active INTEGER NOT NULL DEFAULT 1,
        locked INTEGER NOT NULL DEFAULT 0, created_at VARCHAR(255) NOT NULL
    )""")
    
    c.execute("""CREATE TABLE IF NOT EXISTS clients (
        id SERIAL PRIMARY KEY, order_number VARCHAR(255) UNIQUE NOT NULL,
        full_name VARCHAR(255) NOT NULL, phone VARCHAR(50) NOT NULL, telegram VARCHAR(255), viber VARCHAR(50),
        preferred_messenger VARCHAR(50) DEFAULT 'phone', city VARCHAR(100), district VARCHAR(100), address TEXT,
        tech_type VARCHAR(100), tech_model VARCHAR(255), problem TEXT, company VARCHAR(255), edrpou VARCHAR(50), notes TEXT,
        source VARCHAR(50) NOT NULL, status VARCHAR(50) DEFAULT 'active', created_by VARCHAR(100),
        created_at VARCHAR(255) NOT NULL, updated_at VARCHAR(255) NOT NULL
    )""")
    
    c.execute("""CREATE TABLE IF NOT EXISTS photos (
        id SERIAL PRIMARY KEY, client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
        data TEXT NOT NULL, created_at VARCHAR(255) NOT NULL
    )""")
    
    c.execute("""CREATE TABLE IF NOT EXISTS interactions (
        id SERIAL PRIMARY KEY, client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
        channel VARCHAR(50), subject VARCHAR(255), body TEXT, user_name VARCHAR(100), created_at VARCHAR(255) NOT NULL
    )""")
    
    c.execute("""CREATE TABLE IF NOT EXISTS audit (
        id SERIAL PRIMARY KEY, action VARCHAR(50) NOT NULL, entity VARCHAR(255),
        details TEXT, user_name VARCHAR(100), ip VARCHAR(50), created_at VARCHAR(255) NOT NULL
    )""")
    
    c.execute("""CREATE TABLE IF NOT EXISTS order_counters (
        prefix VARCHAR(10) PRIMARY KEY, counter INTEGER NOT NULL DEFAULT 0
    )""")
    
    c.execute("SELECT id FROM users WHERE username='root'")
    if not c.fetchone():
        c.execute("""INSERT INTO users (username,email,password_hash,role,lang,active,locked,created_at)
                     VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
                  ('root', 'root@qerner.local', generate_password_hash('qerner123'),
                   'root', 'uk', 1, 1, now_iso()))
    conn.close()

init_db()

def json_error(msg, code=400):
    return jsonify({"ok": False, "error": msg}), code

def current_session():
    tok = request.headers.get("X-Session-Token")
    if not tok: return None
    s = SESSIONS.get(tok)
    if not s: return None
    if s["expires"] < datetime.utcnow():
        SESSIONS.pop(tok, None)
        return None
    return s

def require_auth(f):
    @wraps(f)
    def wrapper(*a, **kw):
        sess = current_session()
        if not sess: return json_error("Unauthorized", 401)
        g.user = sess
        return f(*a, **kw)
    return wrapper

def get_real_ip():
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr or "unknown"

def log_action(action, entity="", details="", user="system"):
    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT INTO audit (action,entity,details,user_name,ip,created_at) VALUES (%s,%s,%s,%s,%s,%s)",
                 (action, entity, details, user, get_real_ip(), now_iso()))
    conn.close()

def next_order_number(prefix):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT counter FROM order_counters WHERE prefix=%s", (prefix,))
    row = c.fetchone()
    if row:
        v = row[0] + 1
        c.execute("UPDATE order_counters SET counter=%s WHERE prefix=%s", (v, prefix))
    else:
        v = 1
        c.execute("INSERT INTO order_counters (prefix, counter) VALUES (%s,%s)", (prefix, v))
    conn.close()
    return f"{prefix}-{v:06d}"

def prefix_for_source(s):
    return {"walkin": "X", "site": "D", "ad": "S", "repeat": "X1"}.get(s, "X")

@app.route("/")
def index():
    return send_from_directory(BASE_DIR, "admin.html")

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    u = (data.get("username") or "").strip()
    p = data.get("password") or ""
    if not u or not p: return json_error("Заповніть поля")
    conn = get_db()
    c = conn.cursor(row_factory=dict_row)
    c.execute("SELECT * FROM users WHERE username=%s", (u,))
    user = c.fetchone()
    
    if not user or not user["active"] or not check_password_hash(user["password_hash"], p):
        log_action("login_fail", "user", u, u)
        conn.close()
        return json_error("Невірний логін або пароль", 401)
    
    tok = secrets.token_hex(32)
    SESSIONS[tok] = {
        "user_id": user["id"], "username": user["username"],
        "role": user["role"], "lang": user["lang"],
        "expires": datetime.utcnow() + timedelta(hours=SESSION_TTL_HOURS)
    }
    log_action("login", "user", u, u)
    conn.close()
    return jsonify({"ok": True, "token": tok, "user": {"username": user["username"], "email": user["email"], "role": user["role"], "lang": user["lang"]}})

@app.route("/api/logout", methods=["POST"])
@require_auth
def logout():
    tok = request.headers.get("X-Session-Token")
    s = SESSIONS.pop(tok, None)
    if s: log_action("logout", "user", s["username"], s["username"])
    return jsonify({"ok": True})

@app.route("/api/me", methods=["GET"])
@require_auth
def me():
    conn = get_db()
    c = conn.cursor(row_factory=dict_row)
    c.execute("SELECT * FROM users WHERE id=%s", (g.user["user_id"],))
    u = c.fetchone()
    conn.close()
    return jsonify({"username": u["username"], "email": u["email"], "role": u["role"], "lang": u["lang"]})

@app.route("/api/me/password", methods=["POST"])
@require_auth
def change_password():
    d = request.get_json() or {}
    if len(d.get("new", "")) < 8: return json_error("Мін. 8 символів")
    conn = get_db()
    c = conn.cursor(row_factory=dict_row)
    c.execute("SELECT * FROM users WHERE id=%s", (g.user["user_id"],))
    u = c.fetchone()
    if not check_password_hash(u["password_hash"], d.get("current", "")):
        conn.close()
        return json_error("Поточний пароль невірний")
    c.execute("UPDATE users SET password_hash=%s WHERE id=%s", (generate_password_hash(d["new"]), u["id"]))
    conn.close()
    log_action("password_change", "user", u["username"], g.user["username"])
    return jsonify({"ok": True})

@app.route("/api/me/lang", methods=["POST"])
@require_auth
def set_lang():
    d = request.get_json() or {}
    lang = d.get("lang", "uk")
    if lang not in ("uk", "ru", "en"): return json_error("Невірна мова")
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE users SET lang=%s WHERE id=%s", (lang, g.user["user_id"]))
    conn.close()
    g.user["lang"] = lang
    log_action("lang_change", "user", lang, g.user["username"])
    return jsonify({"ok": True, "lang": lang})

CLIENT_FIELDS = ["full_name", "phone", "telegram", "viber", "preferred_messenger", "city", "district", "address", "tech_type", "tech_model", "problem", "company", "edrpou", "notes", "source", "status"]

@app.route("/api/clients", methods=["GET"])
@require_auth
def list_clients():
    conn = get_db()
    c = conn.cursor(row_factory=dict_row)
    c.execute("SELECT * FROM clients ORDER BY updated_at DESC")
    rows = c.fetchall()
    out = []
    for r in rows:
        c.execute("SELECT data FROM photos WHERE client_id=%s ORDER BY id", (r["id"],))
        photos = [p["data"] for p in c.fetchall()]
        d = dict(r)
        d["photos"] = photos
        out.append(d)
    conn.close()
    return jsonify(out)

@app.route("/api/clients", methods=["POST"])
@require_auth
def create_client():
    d = request.get_json() or {}
    if not d.get("full_name") or not d.get("phone"): return json_error("ПІБ та телефон обов'язкові")
    if not d.get("source"): return json_error("Оберіть джерело")
    if not d.get("tech_type"): return json_error("Оберіть техніку")
    order = next_order_number(prefix_for_source(d["source"]))
    now = now_iso()
    conn = get_db()
    c = conn.cursor()
    c.execute("""INSERT INTO clients
        (order_number, full_name, phone, telegram, viber, preferred_messenger, city, district, address, tech_type, tech_model, problem, company, edrpou, notes, source, status, created_by, created_at, updated_at)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
        (order, d.get("full_name", ""), d.get("phone", ""), d.get("telegram", ""), d.get("viber", ""), d.get("preferred_messenger", "phone"), d.get("city", ""), d.get("district", ""), d.get("address", ""), d.get("tech_type", ""), d.get("tech_model", ""), d.get("problem", ""), d.get("company", ""), d.get("edrpou", ""), d.get("notes", ""), d.get("source", ""), d.get("status", "active"), g.user["username"], now, now))
    cid = c.fetchone()["id"]
    
    for photo in d.get("photos", []):
        try:
            c.execute("INSERT INTO photos (client_id, data, created_at) VALUES (%s,%s,%s)", (cid, photo, now))
        except Exception as e:
            print(f"Ошибка сохранения фото: {e}")
            continue
            
    conn.close()
    log_action("client_create", order, f"{d.get('full_name')}", g.user["username"])
    return jsonify({"ok": True, "id": cid, "order_number": order})

@app.route("/api/clients/<int:cid>", methods=["PUT"])
@require_auth
def update_client(cid):
    d = request.get_json() or {}
    conn = get_db()
    c = conn.cursor(row_factory=dict_row)
    c.execute("SELECT * FROM clients WHERE id=%s", (cid,))
    row = c.fetchone()
    if not row:
        conn.close()
        return json_error("Не знайдено", 404)
    
    updates, values = [], []
    for f in CLIENT_FIELDS:
        if f in d:
            updates.append(f"{f}=%s")
            values.append(d[f])
    if updates:
        updates.append("updated_at=%s")
        values.append(now_iso())
        values.append(cid)
        query = f"UPDATE clients SET {', '.join(updates)} WHERE id=%s"
        c.execute(query, values)
    
    if "photos" in d:
        c.execute("DELETE FROM photos WHERE client_id=%s", (cid,))
        for photo in d["photos"]:
            try:
                c.execute("INSERT INTO photos (client_id, data, created_at) VALUES (%s,%s,%s)", (cid, photo, now_iso()))
            except Exception as e:
                print(f"Ошибка сохранения фото: {e}")
                continue
                
    conn.close()
    log_action("client_update", row["order_number"], f"{d.get('full_name')}", g.user["username"])
    return jsonify({"ok": True})

@app.route("/api/clients/<int:cid>", methods=["DELETE"])
@require_auth
def delete_client(cid):
    if g.user["role"] != "root": return json_error("Тільки root", 403)
    conn = get_db()
    c = conn.cursor(row_factory=dict_row)
    c.execute("SELECT order_number, full_name FROM clients WHERE id=%s", (cid,))
    row = c.fetchone()
    if not row:
        conn.close()
        return json_error("Не знайдено", 404)
    c.execute("DELETE FROM clients WHERE id=%s", (cid,))
    conn.close()
    log_action("client_delete", row["order_number"], row["full_name"], g.user["username"])
    return jsonify({"ok": True})

@app.route("/api/clients/<int:cid>/interactions", methods=["GET"])
@require_auth
def list_interactions(cid):
    conn = get_db()
    c = conn.cursor(row_factory=dict_row)
    c.execute("SELECT * FROM interactions WHERE client_id=%s ORDER BY created_at DESC", (cid,))
    rows = c.fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/clients/<int:cid>/interactions", methods=["POST"])
@require_auth
def add_interaction(cid):
    d = request.get_json() or {}
    if not d.get("subject") and not d.get("body"): return json_error("Заповніть")
    conn = get_db()
    c = conn.cursor(row_factory=dict_row)
    c.execute("SELECT order_number FROM clients WHERE id=%s", (cid,))
    row = c.fetchone()
    c.execute("INSERT INTO interactions (client_id,channel,subject,body,user_name,created_at) VALUES (%s,%s,%s,%s,%s,%s)", (cid, d.get("channel", "note"), d.get("subject", ""), d.get("body", ""), g.user["username"], now_iso()))
    conn.close()
    log_action("interaction_add", row["order_number"] if row else "", d.get("channel", ""), g.user["username"])
    return jsonify({"ok": True})

@app.route("/api/users", methods=["GET"])
@require_auth
def list_users():
    if g.user["role"] != "root": return json_error("Тільки root", 403)
    conn = get_db()
    c = conn.cursor(row_factory=dict_row)
    c.execute("SELECT id,username,email,role,lang,active,locked,created_at FROM users ORDER BY id")
    rows = c.fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/users", methods=["POST"])
@require_auth
def create_user():
    if g.user["role"] != "root": return json_error("Тільки root", 403)
    d = request.get_json() or {}
    u = (d.get("username") or "").strip()
    p = d.get("password") or ""
    if not u or not p: return json_error("Логін і пароль")
    if len(p) < 6: return json_error("Пароль мін. 6")
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE username=%s", (u,))
    if c.fetchone():
        conn.close()
        return json_error("Логін існує")
    c.execute("INSERT INTO users (username,email,password_hash,role,lang,active,locked,created_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)", (u, d.get("email", ""), generate_password_hash(p), "admin", "uk", 1, 0, now_iso()))
    conn.close()
    log_action("user_create", u, "admin", g.user["username"])
    return jsonify({"ok": True})

@app.route("/api/users/<int:uid>", methods=["DELETE"])
@require_auth
def delete_user(uid):
    if g.user["role"] != "root": return json_error("Тільки root", 403)
    conn = get_db()
    c = conn.cursor(row_factory=dict_row)
    c.execute("SELECT username, role FROM users WHERE id=%s", (uid,))
    row = c.fetchone()
    if not row:
        conn.close()
        return json_error("Не знайдено", 404)
    if row["role"] == "root":
        conn.close()
        return json_error("Root не можна видалити")
    c.execute("DELETE FROM users WHERE id=%s", (uid,))
    conn.close()
    log_action("user_delete", row["username"], "", g.user["username"])
    return jsonify({"ok": True})

@app.route("/api/audit", methods=["GET"])
@require_auth
def list_audit():
    conn = get_db()
    c = conn.cursor(row_factory=dict_row)
    c.execute("SELECT * FROM audit ORDER BY created_at DESC LIMIT 500")
    rows = c.fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/audit/clear", methods=["POST"])
@require_auth
def clear_audit():
    if g.user["username"] != "root":
        return json_error("Тільки головний адміністратор (root) може очищати журнал", 403)
    
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM audit")
    conn.close()
    
    log_action("audit_clear", "system", "Журнал було очищено", g.user["username"])
    return jsonify({"ok": True})

@app.route("/api/health")
def health():
    return jsonify({"ok": True, "time": now_iso()})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
