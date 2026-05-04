"""
Intentionally vulnerable Flask app — used as a test target for the security
investigator agent. DO NOT DEPLOY. See README.md.
"""

import hashlib
import sqlite3
import subprocess
from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS

# === Vuln: hardcoded secrets in source ===
API_KEY = "sk-prod-7c4e9f2a1b8d3e6f5a9c0d4e8f1b2a7c"
DB_PASSWORD = "admin123"
JWT_SECRET = "supersecret"

# === Vuln: debug + permissive CORS ===
app = Flask(__name__)
app.config["DEBUG"] = True
app.config["SECRET_KEY"] = JWT_SECRET
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)


def get_db():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password_hash TEXT,
            role TEXT DEFAULT 'user'
        );
        INSERT OR IGNORE INTO users (username, password_hash, role)
        VALUES ('admin', '0192023a7bbd73250516f069df18b500', 'admin');
        """
    )
    conn.commit()
    conn.close()


@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username", "")
    password = request.json.get("password", "")

    # === Vuln: weak password hashing (MD5) ===
    password_hash = hashlib.md5(password.encode()).hexdigest()

    # === Vuln: SQL injection via string concatenation ===
    conn = get_db()
    query = (
        "SELECT * FROM users WHERE username = '"
        + username
        + "' AND password_hash = '"
        + password_hash
        + "'"
    )
    row = conn.execute(query).fetchone()
    conn.close()

    if row:
        return jsonify({"status": "ok", "user": dict(row)})
    return jsonify({"status": "invalid"}), 401


@app.route("/search")
def search():
    term = request.args.get("q", "")
    conn = get_db()
    # === Vuln: SQL injection (second instance, GET param) ===
    rows = conn.execute(
        "SELECT id, username FROM users WHERE username LIKE '%" + term + "%'"
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


# === Vuln: missing auth on admin endpoints ===
@app.route("/admin/users")
def admin_list_users():
    conn = get_db()
    rows = conn.execute("SELECT id, username, role FROM users").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/admin/delete/<int:user_id>", methods=["POST"])
def admin_delete_user(user_id):
    conn = get_db()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "deleted", "id": user_id})


@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")
    # === Vuln: command injection — user input passed to shell ===
    result = subprocess.run(
        f"ping -c 1 {host}", shell=True, capture_output=True, text=True
    )
    return jsonify({"output": result.stdout, "error": result.stderr})


@app.route("/render")
def render():
    name = request.args.get("name", "world")
    # === Vuln: server-side template injection ===
    template = "<h1>Hello, " + name + "!</h1>"
    return render_template_string(template)


@app.errorhandler(Exception)
def handle_error(e):
    import traceback

    # === Vuln: stack traces exposed to clients ===
    return (
        jsonify({"error": str(e), "trace": traceback.format_exc()}),
        500,
    )


if __name__ == "__main__":
    init_db()
    # === Vuln: binds 0.0.0.0 with debug on ===
    app.run(host="0.0.0.0", port=5000, debug=True)
