import os
import secrets
import sqlite3
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, g
from flask_cors import CORS
from werkzeug.security import check_password_hash, generate_password_hash

# --- ЖЕСТКАЯ ПРИВЯЗКА К ДИСКУ RENDER ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_DIR = "/var/data" if os.path.exists("/var/data") else BASE_DIR
DB_PATH = os.path.join(DB_DIR, "qerner.db")

# Принудительно создаем папку, если ее нет
os.makedirs(DB_DIR, exist_ok=True)

app = Flask(__name__, static_folder=None)
CORS(app, supports_credentials=True)

SESSIONS = {}
SESSION_TTL_HOURS = 24 * 7

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def now_iso():
    return datetime.utcnow().isoformat()

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
        email TEXT, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'admin',
        lang TEXT NOT NULL DEFAULT 'uk', active INTEGER NOT NULL DEFAULT 1,
        locked INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS clients (
        id INTEGER PRIMARY KEY AUTOINCREMENT, order_number TEXT UNIQUE NOT NULL,
        full_name TEXT NOT NULL, phone TEXT NOT NULL, telegram TEXT, viber TEXT,
        preferred_messenger TEXT DEFAULT 'phone', city TEXT, district TEXT, address TEXT,
        tech_type TEXT, tech_model TEXT, problem TEXT, company TEXT, edrpou TEXT, notes TEXT,
        source TEXT NOT NULL, status TEXT DEFAULT 'active', created_by TEXT,
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS photos (
        id INTEGER PRIMARY KEY AUTOINCREMENT, client_id INTEGER NOT NULL,
        data TEXT NOT NULL, created_at TEXT NOT NULL,
        FOREIGN KEY(client_id) REFERENCES clients(id) ON DELETE CASCADE
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS interactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT, client_id INTEGER NOT NULL,
        channel TEXT, subject TEXT, body TEXT, user TEXT, created_at TEXT NOT NULL,
        FOREIGN KEY(client_id) REFERENCES clients(id) ON DELETE CASCADE
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL, entity TEXT,
        details TEXT, user TEXT, ip TEXT, created_at TEXT NOT NULL
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS order_counters (
        prefix TEXT PRIMARY KEY, counter INTEGER NOT NULL DEFAULT 0
    )""")
    if not c.execute("SELECT id FROM users WHERE username='root'").fetchone():
        c.execute("""INSERT INTO users (username,email,password_hash,role,lang,active,locked,created_at)
                     VALUES (?,?,?,?,?,?,?,?)""",
                  ('root', 'root@qerner.local', generate_password_hash('qerner123'),
                   'root', 'uk', 1, 1, now_iso()))
    conn.commit()
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

def log_action(action, entity="", details="", user="system"):
    conn = get_db()
    conn.execute("INSERT INTO audit (action,entity,details,user,ip,created_at) VALUES (?,?,?,?,?,?)",
                 (action, entity, details, user, request.remote_addr or "", now_iso()))
    conn.commit()
    conn.close()

def next_order_number(prefix):
    conn = get_db()
    row = conn.execute("SELECT counter FROM order_counters WHERE prefix=?", (prefix,)).fetchone()
    if row:
        v = row["counter"] + 1
        conn.execute("UPDATE order_counters SET counter=? WHERE prefix=?", (v, prefix))
    else:
        v = 1
        conn.execute("INSERT INTO order_counters (prefix, counter) VALUES (?,?)", (prefix, v))
    conn.commit()
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
    user = conn.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
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
    u = conn.execute("SELECT * FROM users WHERE id=?", (g.user["user_id"],)).fetchone()
    conn.close()
    return jsonify({"username": u["username"], "email": u["email"], "role": u["role"], "lang": u["lang"]})

@app.route("/api/me/password", methods=["POST"])
@require_auth
def change_password():
    d = request.get_json() or {}
    if len(d.get("new", "")) < 8: return json_error("Мін. 8 символів")
    conn = get_db()
    u = conn.execute("SELECT * FROM users WHERE id=?", (g.user["user_id"],)).fetchone()
    if not check_password_hash(u["password_hash"], d.get("current", "")):
        conn.close()
        return json_error("Поточний пароль невірний")
    conn.execute("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(d["new"]), u["id"]))
    conn.commit()
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
    conn.execute("UPDATE users SET lang=? WHERE id=?", (lang, g.user["user_id"]))
    conn.commit()
    conn.close()
    g.user["lang"] = lang
    log_action("lang_change", "user", lang, g.user["username"])
    return jsonify({"ok": True, "lang": lang})

CLIENT_FIELDS = ["full_name", "phone", "telegram", "viber", "preferred_messenger", "city", "district", "address", "tech_type", "tech_model", "problem", "company", "edrpou", "notes", "source", "status"]

@app.route("/api/clients", methods=["GET"])
@require_auth
def list_clients():
    conn = get_db()
    rows = conn.execute("SELECT * FROM clients ORDER BY updated_at DESC").fetchall()
    out = []
    for r in rows:
        photos = conn.execute("SELECT data FROM photos WHERE client_id=? ORDER BY id", (r["id"],)).fetchall()
        d = dict(r)
        d["photos"] = [p["data"] for p in photos]
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
    cur = conn.execute("""INSERT INTO clients
        (order_number, full_name, phone, telegram, viber, preferred_messenger, city, district, address, tech_type, tech_model, problem, company, edrpou, notes, source, status, created_by, created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (order, d.get("full_name", ""), d.get("phone", ""), d.get("telegram", ""), d.get("viber", ""), d.get("preferred_messenger", "phone"), d.get("city", ""), d.get("district", ""), d.get("address", ""), d.get("tech_type", ""), d.get("tech_model", ""), d.get("problem", ""), d.get("company", ""), d.get("edrpou", ""), d.get("notes", ""), d.get("source", ""), d.get("status", "active"), g.user["username"], now, now))
    cid = cur.lastrowid
    for photo in d.get("photos", []):
        conn.execute("INSERT INTO photos (client_id, data, created_at) VALUES (?,?,?)", (cid, photo, now))
    conn.commit()
    conn.close()
    log_action("client_create", "client", f"{d.get('full_name')} ({order})", g.user["username"])
    return jsonify({"ok": True, "id": cid, "order_number": order})

@app.route("/api/clients/<int:cid>", methods=["PUT"])
@require_auth
def update_client(cid):
    d = request.get_json() or {}
    conn = get_db()
    if not conn.execute("SELECT id FROM clients WHERE id=?", (cid,)).fetchone():
        conn.close()
        return json_error("Не знайдено", 404)
    updates, values = [], []
    for f in CLIENT_FIELDS:
        if f in d:
            updates.append(f"{f}=?")
            values.append(d[f])
    if updates:
        updates.append("updated_at=?")
        values.append(now_iso())
        values.append(cid)
        conn.execute(f"UPDATE clients SET {', '.join(updates)} WHERE id=?", values)
    if "photos" in d:
        conn.execute("DELETE FROM photos WHERE client_id=?", (cid,))
        for photo in d["photos"]:
            conn.execute("INSERT INTO photos (client_id, data, created_at) VALUES (?,?,?)", (cid, photo, now_iso()))
    conn.commit()
    conn.close()
    log_action("client_update", "client", d.get("full_name", ""), g.user["username"])
    return jsonify({"ok": True})

@app.route("/api/clients/<int:cid>", methods=["DELETE"])
@require_auth
def delete_client(cid):
    if g.user["role"] != "root": return json_error("Тільки root", 403)
    conn = get_db()
    row = conn.execute("SELECT full_name FROM clients WHERE id=?", (cid,)).fetchone()
    if not row:
        conn.close()
        return json_error("Не знайдено", 404)
    conn.execute("DELETE FROM clients WHERE id=?", (cid,))
    conn.commit()
    conn.close()
    log_action("client_delete", "client", row["full_name"], g.user["username"])
    return jsonify({"ok": True})

@app.route("/api/clients/<int:cid>/interactions", methods=["GET"])
@require_auth
def list_interactions(cid):
    conn = get_db()
    rows = conn.execute("SELECT * FROM interactions WHERE client_id=? ORDER BY created_at DESC", (cid,)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/clients/<int:cid>/interactions", methods=["POST"])
@require_auth
def add_interaction(cid):
    d = request.get_json() or {}
    if not d.get("subject") and not d.get("body"): return json_error("Заповніть")
    conn = get_db()
    conn.execute("INSERT INTO interactions (client_id,channel,subject,body,user,created_at) VALUES (?,?,?,?,?,?)", (cid, d.get("channel", "note"), d.get("subject", ""), d.get("body", ""), g.user["username"], now_iso()))
    conn.commit()
    conn.close()
    log_action("interaction_add", "client", d.get("channel", ""), g.user["username"])
    return jsonify({"ok": True})

@app.route("/api/users", methods=["GET"])
@require_auth
def list_users():
    if g.user["role"] != "root": return json_error("Тільки root", 403)
    conn = get_db()
    rows = conn.execute("SELECT id,username,email,role,lang,active,locked,created_at FROM users ORDER BY id").fetchall()
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
    if conn.execute("SELECT id FROM users WHERE username=?", (u,)).fetchone():
        conn.close()
        return json_error("Логін існує")
    conn.execute("INSERT INTO users (username,email,password_hash,role,lang,active,locked,created_at) VALUES (?,?,?,?,?,?,?,?)", (u, d.get("email", ""), generate_password_hash(p), "admin", "uk", 1, 0, now_iso()))
    conn.commit()
    conn.close()
    log_action("user_create", "user", u, g.user["username"])
    return jsonify({"ok": True})

@app.route("/api/users/<int:uid>", methods=["DELETE"])
@require_auth
def delete_user(uid):
    if g.user["role"] != "root": return json_error("Тільки root", 403)
    conn = get_db()
    row = conn.execute("SELECT username, role FROM users WHERE id=?", (uid,)).fetchone()
    if not row:
        conn.close()
        return json_error("Не знайдено", 404)
    if row["role"] == "root":
        conn.close()
        return json_error("Root не можна видалити")
    conn.execute("DELETE FROM users WHERE id=?", (uid,))
    conn.commit()
    conn.close()
    log_action("user_delete", "user", row["username"], g.user["username"])
    return jsonify({"ok": True})

@app.route("/api/audit", methods=["GET"])
@require_auth
def list_audit():
    conn = get_db()
    rows = conn.execute("SELECT * FROM audit ORDER BY created_at DESC LIMIT 500").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/health")
def health():
    return jsonify({"ok": True, "time": now_iso()})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
