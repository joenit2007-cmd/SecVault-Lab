# Security Remediation Guide

This guide documents the concrete code-level and configuration-level fixes implemented in **SecVault (`--mode secure`)** for each vulnerability discovered during assessment.

---

## 1. Remediating SQL Injection → Parameterized Queries

### Vulnerable Pattern (`app/routes/auth.py`, `app/routes/dashboard.py`)
```python
# UNSAFE: User input concatenated directly into SQL
raw_query = (
    f"SELECT id, username, email, password_hash, role "
    f"FROM users WHERE username = '{username}' AND password_hash = '{password}'"
)
user = db.execute(raw_query).fetchone()
```

### Secure Implementation
```python
# SAFE: Parameterized query separates SQL syntax from untrusted data
user = db.execute(
    "SELECT id, username, email, password_hash, role FROM users WHERE username = ?",
    (username,),
).fetchone()
```
**Why It Works:** SQLite compiles the SQL statement first and binds the `?` parameters strictly as literal values, making it impossible for user input to alter SQL logic.

---

## 2. Remediating XSS → Output Encoding, Validation & CSP

### Vulnerable Pattern (`app/templates/dashboard.html`)
```html
<!-- UNSAFE: |safe disables Jinja2 HTML escaping -->
<span>{{ search_query | safe }}</span>
<p>{{ note.content | safe }}</p>
```

### Secure Implementation
1. **Jinja2 Auto-Escaping:** Render all user-controlled values normally (`{{ search_query }}`, `{{ note.content }}`), converting `<`, `>`, `"`, `'`, and `&` into harmless HTML entities (`&lt;`, `&gt;`, etc.).
2. **Input Validation (`app/security.py`):** Enforce length bounds and allowlisted categories (`validate_note_input`).
3. **Defense-in-Depth CSP (`app/security.py`):**
   ```http
   Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; frame-ancestors 'none'
   ```
   All legitimate client scripts reside in `static/js/app.js`, so even if an encoding mistake ever occurred, inline scripts would still be blocked by the browser.

---

## 3. Remediating Broken Access Control → Server-Side Ownership & RBAC

### Vulnerable Pattern
- `/notes/<id>` queried `WHERE id = ?` without verifying `note.user_id == g.user["id"]`.
- `/admin` verified only login, not role.

### Secure Implementation (`app/security.py`, `app/routes/dashboard.py`, `app/routes/admin.py`)
1. **Object-Level Ownership Check:**
   ```python
   if note["user_id"] != g.user["id"] and g.user["role"] != "admin":
       log_security_event(action="IDOR_BLOCKED", ...)
       abort(403, description="You do not have permission to view this note.")
   ```
2. **Database-Backed RBAC Decorator (`@role_required("admin")`):**
   ```python
   # g.user is loaded freshly from SQLite on every request (before_request)
   if g.user["role"] != required_role:
       log_security_event(action="ACCESS_DENIED_RBAC", ...)
       abort(403, description="You do not have permission to access this administrative resource.")
   ```

---

## 4. Remediating Authentication Failures → Salted Hashing, Policy, Lockout & Session Hygiene

### Implemented Controls (`app/security.py`, `app/routes/auth.py`)
1. **Salted Password Hashing:**
   ```python
   generate_password_hash(raw_password, method="pbkdf2:sha256:600000", salt_length=16)
   ```
   Each user receives a unique 16-byte salt and 600,000 PBKDF2-HMAC-SHA256 iterations, verified in constant time via `check_password_hash`.
2. **Strong Password Policy:** Minimum 10 characters with uppercase, lowercase, digit, and special character.
3. **Generic Error Messages:** Return `"Invalid username or password."` for both unknown usernames and wrong passwords to stop account enumeration.
4. **Brute-Force Rate Limiting:** Track failed attempts in `login_attempts`; lock out with HTTP `429 Too Many Requests` after 5 failures in 15 minutes.
5. **Session Regeneration & Timeout:** Call `session.clear()` on login, rotate the CSRF token, set `session.permanent = True` with `PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)`.

---

## 5. Remediating Security Misconfiguration → Hardened Config, Headers & Error Handling

### Implemented Controls (`app/config.py`, `app/security.py`, `app/__init__.py`)
1. **Hardened Session Cookies:**
   - `SESSION_COOKIE_HTTPONLY = True`
   - `SESSION_COOKIE_SAMESITE = "Lax"`
   - `SESSION_COOKIE_SECURE = True` when deployed behind HTTPS (configurable via `.env`)
   - High-entropy 256-bit `SECRET_KEY` from environment or runtime `secrets.token_hex(32)` (never hardcoded in Git).
2. **Protective HTTP Response Headers:**
   - `Content-Security-Policy`
   - `X-Content-Type-Options: nosniff`
   - `X-Frame-Options: DENY`
   - `Referrer-Policy: strict-origin-when-cross-origin`
   - `Permissions-Policy: geolocation=(), microphone=(), camera=()`
   - `Cross-Origin-Opener-Policy: same-origin`
   - `Cache-Control: no-store, no-cache, must-revalidate, private` on authenticated pages
   - Remove verbose `X-Powered-By` headers.
3. **Disable Debug Endpoints & Stack Traces:**
   - `EXPOSE_DEBUG_ENDPOINTS = False` (`/debug/info` and `/debug/error-test` return `404`).
   - `VERBOSE_ERRORS = False` (custom `403`, `404`, `429`, `500` templates show no file paths or tracebacks).
   - `app.run(..., debug=False)`.

---

## 6. Remediating CSRF → Synchronizer Token Pattern + SameSite Cookies

### Implemented Controls (`app/security.py`)
1. **Per-Session Cryptographic Token:** Generated via `secrets.token_urlsafe(32)` and injected into every HTML `<form method="post">` as `<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">`.
2. **Server-Side Verification (`@csrf_protect`):**
   ```python
   session_token = session.get("_csrf_token")
   submitted_token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
   return bool(session_token and submitted_token and hmac.compare_digest(str(session_token), str(submitted_token)))
   ```
   Missing or mismatched tokens return HTTP `403 Forbidden` and write a `CSRF_BLOCKED` entry to `audit_logs`.
3. **Defense-in-Depth Cookie Attribute:** `SESSION_COOKIE_SAMESITE = "Lax"` prevents browsers from sending the session cookie on cross-site POST form submissions.
