# Flask vulnerability patterns

Flask/Werkzeug-specific pitfalls to check for in addition to the general
data-flow analysis. Each pattern lists what to grep for, why it is dangerous,
the safe equivalent, and severity guidance.

---

## 1. Routes missing `@login_required` on Blueprint handlers

A `Blueprint` does not inherit auth from its parent app. Each handler under a
sensitive blueprint must either:

- carry an explicit `@login_required` (or equivalent) decorator, or
- be covered by a blueprint-level `@bp.before_request` guard that rejects
  unauthenticated requests.

Pattern to grep for:

```bash
grep -nE "^(admin_bp|api_bp|.*_bp)\s*=\s*Blueprint\(" .
grep -nE "@\w+\.route\(" .   # then check the next decorator line
```

**Vulnerable** — admin routes registered on a blueprint with no auth:

```python
admin_bp = Blueprint("admin", __name__, url_prefix="/admin")

@admin_bp.route("/users")
def list_users():                       # ← no decorator above
    return jsonify([u.to_dict() for u in User.query.all()])
```

**Safe** — explicit decorator OR blueprint-wide guard:

```python
# Option A: per-route decorator
@admin_bp.route("/users")
@login_required
@admin_required
def list_users(): ...

# Option B: blueprint-wide
@admin_bp.before_request
def require_admin():
    if not (current_user.is_authenticated and current_user.is_admin):
        abort(403)
```

**Severity:** HIGH if the route reads sensitive data, CRITICAL if it
reads/writes admin-only data (user list, credentials, role changes).

Confirm reachability: is the blueprint actually registered with `app.register_blueprint(...)`? An unregistered blueprint is not exploitable.

---

## 2. Hardcoded `SECRET_KEY` / `app.secret_key`

The Flask `SECRET_KEY` signs session cookies, CSRF tokens, and `itsdangerous`
tokens. A known value lets an attacker forge sessions and CSRF tokens
trivially.

Pattern:

```bash
grep -nE "(secret_key|SECRET_KEY)\s*=" .
```

**Vulnerable:**

```python
app.secret_key = "dev"
app.config["SECRET_KEY"] = "change-me-in-production"
app.config.from_mapping(SECRET_KEY="hardcoded-string-literal")
```

**Safe** — load from environment or secrets manager:

```python
app.secret_key = os.environ["SECRET_KEY"]                # fail fast if unset
app.config["SECRET_KEY"] = secrets_client.get("flask-secret")
```

**Severity:** CRITICAL. A leaked or hardcoded `SECRET_KEY` in a deployed app
allows session forgery for any user, including admin.

Special case: a hardcoded value in a file like `config.dev.py` that is *only*
loaded in development is LOW — confirm it is not the value used in
production by checking the env-loading logic.

---

## 3. Misuse of `Markup` / `flask.escape` / `|safe` with user input

Flask's Jinja2 templates auto-escape by default, but escaping is bypassed when:

- output is wrapped in `Markup(...)` (or imported as `flask.Markup`),
- the template uses the `|safe` filter on user-controlled data,
- the developer builds an HTML string with f-strings then passes it to
  `render_template_string()` (the f-string interpolation happens *before*
  the template engine sees it, so user input lands in the template source).

Patterns:

```bash
grep -nE "Markup\(|markupsafe|render_template_string|\|\s*safe" .
```

**Vulnerable:**

```python
# Markup wraps the whole interpolation — `name` is NOT escaped
return Markup(f"<b>Hello {name}</b>")

# safe filter on user-controlled bio
return render_template("profile.html", bio=user.bio)
# template:  <div>{{ bio | safe }}</div>

# f-string lands user input in the template source itself
return render_template_string(f"<h1>{title}</h1>")
```

**Safe:**

```python
# Let auto-escape handle it
return render_template("profile.html", name=name)
# template:  <b>Hello {{ name }}</b>

# If you must mix HTML + user input, escape the user part first
return Markup("<b>Hello </b>") + escape(name)

# Pass user data as a template variable, never via f-string
return render_template_string("<h1>{{ title }}</h1>", title=title)
```

**Severity:** HIGH (stored XSS) or MEDIUM (reflected XSS), depending on the
input source.

---

## 4. Missing CSRF protection on POST / PUT / DELETE / PATCH

Flask does not include CSRF protection by default. A session-cookie-authenticated
state-changing endpoint is vulnerable unless one of:

- `flask-wtf` `CSRFProtect(app)` is configured globally and the route does
  not have `@csrf.exempt`,
- the route requires a non-cookie credential (e.g. `Authorization: Bearer`
  with a token NOT also stored as a cookie),
- the route enforces a custom CSRF check.

Patterns:

```bash
grep -nE "CSRFProtect|csrf_token|csrf\.exempt" .
grep -nE "methods\s*=\s*\[.*(POST|PUT|DELETE|PATCH)" .
```

**Vulnerable:**

```python
# No CSRFProtect anywhere in the app, session auth in use
@app.route("/account/email", methods=["POST"])
@login_required
def change_email():
    user.email = request.form["email"]
    db.session.commit()
    return "ok"

# OR an explicit exemption on a state-changing route
@csrf.exempt
@app.route("/admin/delete_user", methods=["POST"])
def delete_user(): ...
```

**Safe:**

```python
# At app init
csrf = CSRFProtect(app)

# Templates render the token automatically with WTForms / {{ csrf_token() }}.
# No per-route work needed unless you intentionally exempt.
```

**Severity:** HIGH for routes that mutate user-owned data, CRITICAL for
admin/permissions endpoints. Drop to LOW if the app uses pure
`Authorization: Bearer` token auth (no cookie session).

---

## 5. Debug mode enabled in production

The Werkzeug debugger exposed to the network grants RCE via the in-browser
console once the PIN is bypassed (and the PIN derivation has been weak in past
versions). Even without the debugger, debug mode leaks full stack traces and
local variables.

Patterns:

```bash
grep -nE "app\.run\(.*debug\s*=\s*True" .
grep -nE "(DEBUG|FLASK_DEBUG|FLASK_ENV)\s*=\s*['\"]?(True|true|1|development)" .
grep -nE "app\.config\[['\"]DEBUG['\"]\]\s*=\s*True" .
```

**Vulnerable:**

```python
if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)        # debugger exposed publicly

app.config["DEBUG"] = True                      # set unconditionally

# Even this — the default falsy fallback is a string "True"
app.run(debug=os.environ.get("DEBUG", "True"))
```

**Safe:**

```python
# Debug only in local dev, never on a publicly-bound host
debug = os.environ.get("FLASK_ENV") == "development"
app.run(host="127.0.0.1", debug=debug)
```

**Severity:** CRITICAL when bound to `0.0.0.0` or any non-loopback address.
HIGH when bound to localhost but the deployment is a production environment
(stack traces in logs, PII leakage). Confirm the binding host before assigning.

---

## 6. Unvalidated redirects (`open redirect` via `?next=...`)

A handler that takes a URL from request input and feeds it directly to
`redirect(...)` lets an attacker craft a phishing link on the trusted domain
that redirects to a hostile one. Most often seen in login flows.

Patterns:

```bash
grep -nE "redirect\(.*request\.(args|form|values)" .
grep -nE "(next_url|next_page)\s*=\s*request\." .
```

**Vulnerable:**

```python
@app.route("/login", methods=["POST"])
def login():
    if authenticate(request.form):
        next_url = request.args.get("next") or "/"
        return redirect(next_url)               # any URL accepted
```

An attacker links `https://trusted.app/login?next=https://attacker.example/`
and lands the victim on `attacker.example` post-login.

**Safe** — restrict to relative URLs on the same host:

```python
from urllib.parse import urlparse, urljoin

def is_safe_url(target: str) -> bool:
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ("http", "https") and ref_url.netloc == test_url.netloc

@app.route("/login", methods=["POST"])
def login():
    if authenticate(request.form):
        next_url = request.args.get("next")
        if next_url and is_safe_url(next_url):
            return redirect(next_url)
        return redirect(url_for("index"))
```

**Severity:** MEDIUM. The vulnerability does not directly disclose data, but
it materially boosts phishing campaigns and is often a chained step in
account-takeover flows.

---

## Notes for the auditor

- These are *patterns*, not findings. Confirm reachability before assigning a
  severity: an admin blueprint that is never `register_blueprint`'d, or a
  debug flag that only fires when `__name__ == "__main__"` and the file is
  imported as a module in production, are not exploitable.
- If you find a finding from this list, cite the file:line of the *use*, not
  the import. Quote the actual code in `evidence`.
- The general data-flow / auth / crypto checks in your main mandate still
  apply — these patterns supplement them, do not replace them.
