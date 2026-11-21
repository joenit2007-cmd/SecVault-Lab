# OWASP Vulnerability Analysis

This document maps all six web application security weaknesses demonstrated in **SecVault** to the **OWASP Top 10 (2021)** and **CWE (Common Weakness Enumeration)** standards, explaining how each flaw works under the hood and why it matters in real-world systems.

---

## 1. SQL Injection (SQLi)
- **OWASP Category:** A03:2021 – Injection
- **CWE:** CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)
- **How It Works:** When user input is concatenated directly into an SQL query string (e.g., `WHERE username = '{username}'`), SQL metacharacters such as single quotes (`'`), boolean operators (`OR`), and comment tokens (`--`) alter the syntax of the query itself.
- **Demonstrated Vectors in SecVault:**
  1. **Authentication Bypass (`/login`):** Submitting `' OR '1'='1' --` forces the `WHERE` predicate to evaluate to `TRUE` and comments out the password check, returning the first user record (often `admin`).
  2. **Unauthorized Data Extraction (`/dashboard?q=`):** Submitting `' OR '1'='1' --` breaks out of the `LIKE '%...%'` clause and bypasses the `user_id` ownership predicate, returning private notes belonging to other accounts.
- **Real-World Impact:** Complete authentication bypass, mass disclosure of confidential data, unauthorized modification or deletion of database records.

---

## 2. Cross-Site Scripting (XSS)
- **OWASP Category:** A03:2021 – Injection
- **CWE:** CWE-79 (Improper Neutralization of Input During Web Page Generation)
- **How It Works:** When untrusted user data is embedded into an HTML document without context-aware output encoding (such as using Jinja2's `| safe` filter on user strings), the victim's browser parses the input as executable HTML/JavaScript instead of plain text.
- **Demonstrated Vectors in SecVault:**
  1. **Reflected XSS (`/dashboard?q=<script>...</script>`):** The search query is reflected directly into the HTML response unescaped.
  2. **Stored XSS (`/notes/create` → `/dashboard` & `/notes/<id>`):** Malicious markup (e.g., `<img src=x onerror=...>`) is persisted in SQLite and executes whenever the note is viewed.
- **Real-World Impact:** Session hijacking (especially when `HttpOnly` is missing), account takeover, phishing/UI defacement, and unauthorized actions executed in the victim's browser context.

---

## 3. Broken Access Control (IDOR & Missing RBAC)
- **OWASP Category:** A01:2021 – Broken Access Control
- **CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key / IDOR), CWE-862 (Missing Authorization)
- **How It Works:** Authentication verifies *who* a user is, while authorization verifies *what* that user is permitted to access. Broken Access Control occurs when the backend checks only that a user is logged in—or trusts client-supplied IDs—without enforcing object ownership or role permissions.
- **Demonstrated Vectors in SecVault:**
  1. **Horizontal Privilege Escalation / IDOR (`/notes/<id>`, `/notes/<id>/delete`):** Authenticated user `bob` directly requests `/notes/1` (owned by `alice` or `admin`) and reads or deletes it.
  2. **Vertical Privilege Escalation (`/admin`, `/admin/users/<id>/role`):** Standard user `bob` navigates directly to `/admin`, views all user records and audit logs, and submits a POST request promoting himself to `admin`.
- **Real-World Impact:** Exposure of private customer records, unauthorized data deletion, and full administrative takeover of the platform.

---

## 4. Identification and Authentication Failures
- **OWASP Category:** A07:2021 – Identification and Authentication Failures
- **CWE:** CWE-256 (Plaintext Storage of a Password), CWE-521 (Weak Password Requirements), CWE-307 (Improper Restriction of Excessive Authentication Attempts), CWE-204 (Observable Response Discrepancy / Enumeration), CWE-384 (Session Fixation)
- **How It Works:** Weaknesses in credential creation, storage, verification, or session lifecycle allow attackers to compromise accounts without exploiting code injection.
- **Demonstrated Vectors in SecVault:**
  1. **Plaintext Password Storage:** Compromising the SQLite file immediately exposes every user's raw password.
  2. **No Password Policy:** Users can register passwords like `123`.
  3. **Username Enumeration:** Distinct error messages reveal valid usernames (`"username does not exist"` vs `"incorrect password"`).
  4. **No Brute-Force Protection:** Attackers can try unlimited password guesses against `/login`.
  5. **No Session Regeneration:** Pre-login session keys persist across authentication, exposing users to session fixation.
- **Real-World Impact:** Account compromise via credential stuffing, brute force, database leaks, or session hijacking.

---

## 5. Security Misconfiguration
- **OWASP Category:** A05:2021 – Security Misconfiguration
- **CWE:** CWE-16 (Configuration), CWE-209 (Generation of Error Message Containing Sensitive Information), CWE-693 (Protection Mechanism Failure)
- **How It Works:** Even well-written business logic becomes vulnerable if the server, framework, cookies, or HTTP headers are left in an insecure or debug configuration.
- **Demonstrated Vectors in SecVault:**
  1. **Missing Security Response Headers:** Absence of `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, and `Permissions-Policy`, combined with a verbose `X-Powered-By` fingerprint header.
  2. **Insecure Session Cookie Flags:** Missing `HttpOnly` (allows JavaScript to read cookies via XSS) and missing `SameSite` (increases CSRF exposure).
  3. **Exposed Debug Endpoint (`/debug/info`):** Reveals Python version, local database file path, session settings, and every registered route.
  4. **Verbose Stack Trace Disclosure (`/debug/error-test`):** Reveals internal exception traces and file paths on HTTP 500 responses.
- **Real-World Impact:** Facilitates reconnaissance, clickjacking, MIME-sniffing attacks, XSS escalation, and targeted exploit chaining.

---

## 6. Cross-Site Request Forgery (CSRF)
- **OWASP Category:** A01:2021 – Broken Access Control (Historically OWASP A8:2013)
- **CWE:** CWE-352 (Cross-Site Request Forgery)
- **How It Works:** Browsers automatically attach session cookies to requests sent to a domain where the user is already authenticated. If a state-changing endpoint relies *solely* on the session cookie for authorization, an external page can silently submit a forged form (e.g., changing the victim's email address) using the victim's active session.
- **Demonstrated Vector in SecVault:**
  - Opening `/lab/csrf-demo` while authenticated and submitting a forged `POST /profile/update` without an anti-CSRF token silently overwrites the victim's email address in `vulnerable` mode.
- **Real-World Impact:** Unauthorized email/password changes, account takeover, fraudulent transactions, or unauthorized administrative actions triggered simply by visiting a crafted webpage.
