# Web Application Security – Vulnerability Assessment and Secure Implementation

A complete, practical, locally-runnable **Flask + SQLite** cybersecurity internship project demonstrating six core **OWASP Top 10** web application vulnerabilities, safe local exploitation/testing, secure code remediation, and automated verification with **Pytest**.

> **Disclaimer & Ethical Use:** This project is built strictly for **local academic education and authorized security testing** on `127.0.0.1` (localhost). Never run vulnerability tests against external websites or systems without explicit written authorization.

---

## Project Features

### 1. Functional Web Application (**SecVault Lab**)
- **User Registration & Login** backed by SQLite (`users` table).
- **Session Management** with login/logout lifecycle and role tracking.
- **Authenticated Dashboard** to create, search, view, and delete personal security notes (`notes` table).
- **Profile Management** to inspect account details and update email addresses.
- **Role-Based Access Control (RBAC) & Admin Panel** (`/admin`) to view registered users, manage roles (`user` / `admin`), and inspect security audit logs (`audit_logs` table).

### 2. Dual-Mode Architecture (`secure` vs. `vulnerable`)
SecVault defaults to **`secure`** mode and can be launched in **`vulnerable`** mode at startup for side-by-side local comparison:

| # | OWASP Category | Vulnerable Mode (`--mode vulnerable`) | Secure Mode (`--mode secure`, Default) |
| :-: | :--- | :--- | :--- |
| 1 | **SQL Injection (A03)** | Raw SQL string concatenation in `/login` & `/dashboard` search | Parameterized SQLite `?` queries everywhere |
| 2 | **Cross-Site Scripting / XSS (A03)** | Unescaped `\| safe` rendering on search & notes, no CSP | Jinja2 auto-escaping, input validation & strict `CSP` |
| 3 | **Broken Access Control (A01)** | IDOR on `/notes/<id>` and no role check on `/admin` | Object ownership validation + DB-backed `@role_required("admin")` |
| 4 | **Authentication Failures (A07)** | Plaintext passwords, weak policy, user enumeration, no lockout | PBKDF2-SHA256 salted hashing, strong policy, generic errors, 5-attempt `429` lockout, session regeneration |
| 5 | **Security Misconfiguration (A05)** | Missing headers, weak cookies, `/debug/info` & stack traces exposed | Full security headers, `HttpOnly` + `SameSite=Lax`, debug disabled, sanitized errors |
| 6 | **CSRF (A01 / CWE-352)** | No CSRF tokens on state-changing POST routes | Per-session cryptographic Synchronizer Token (`hmac.compare_digest`) + `SameSite=Lax` |

---

## Repository Structure

```text
WebApp-Security-Assessment/
├── .env.example                    # Template environment variables (no real secrets)
├── .gitignore                      # Excludes *.db, instance/, .env, caches, venvs
├── README.md                       # Project overview, setup, and demo instructions
├── requirements.txt                # Python dependencies
├── run.py                          # CLI entry point (--mode secure | vulnerable)
├── app/
│   ├── __init__.py                 # Flask app factory, headers, error handlers
│   ├── config.py                   # Secure vs Vulnerable configuration builder
│   ├── db.py                       # SQLite schema initialization & audit logger
│   ├── security.py                 # PBKDF2 hashing, CSRF, RBAC, rate limiter, validators
│   ├── routes/
│   │   ├── main.py                 # Home, /lab-guide, /lab/csrf-demo, /debug/*
│   │   ├── auth.py                 # /register, /login, /logout
│   │   ├── dashboard.py            # /dashboard, /notes/*, /profile
│   │   └── admin.py                # /admin, /admin/users/<id>/role
│   ├── templates/                  # Jinja2 HTML views + custom error pages
│   └── static/                     # CSS theme + CSP-compliant external JavaScript
├── scripts/
│   └── seed_demo_data.py           # Optional local demo seeder (generates random passwords)
├── tests/                          # Automated Pytest functional & security test suite
├── docs/                           # Architecture, OWASP analysis, VA report, remediation, test results
└── screenshots/                    # Screenshot capture checklist & storage folder
```

---

## Quick Start (Local Setup)

### Prerequisites
- Python **3.10+** (verified on Python 3.13)
- `pip`

### 1. Create a Virtual Environment & Install Dependencies
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```
*(On macOS/Linux, activate with `source .venv/bin/activate`.)*

### 2. Optional: Seed Local Demo Accounts
No passwords or databases are committed to this repository. To quickly create local demo accounts (`admin`, `alice`, `bob`) with sample notes and **randomly generated ephemeral passwords** printed once to your terminal:

```powershell
# Seed the vulnerable lab database
python scripts/seed_demo_data.py --mode vulnerable

# Seed the secure database
python scripts/seed_demo_data.py --mode secure
```
*(Alternatively, skip seeding and register fresh accounts directly on `/register`.)*

### 3. Run the Application Locally

**Run in Secure Mode (default):**
```powershell
python run.py
```

**Run in Vulnerable Lab Mode (local testing only):**
```powershell
python run.py --mode vulnerable
```

Open your browser to: **http://127.0.0.1:5000**

---

## Running Automated Security Tests (Pytest)

Run the full automated test suite comparing both **Vulnerable** and **Secure** implementations against isolated temporary SQLite databases:

```powershell
pytest -v
```

---

## Documentation Index

- **[Project Architecture](docs/architecture.md)** — System diagrams, SQLite schema, and component breakdown.
- **[Vulnerability Assessment Report](docs/vulnerability_assessment_report.md)** — Scope, severity matrix, safe test cases, expected vs. actual results.
- **[OWASP Vulnerability Analysis](docs/owasp_analysis.md)** — Technical mapping to OWASP Top 10 (2021) & CWE.
- **[Remediation Guide](docs/remediation_guide.md)** — Vulnerable vs. secure code comparisons and hardening recommendations.
- **[Testing Results](docs/testing_results.md)** — Verified Pytest execution logs and live server verification.
- **[Screenshots Guide](screenshots/README.md)** — Checklist of recommended screenshots to capture for internship submission.

---

## Security & Git Hygiene
- **Zero hardcoded secrets:** No passwords, API keys, or static `SECRET_KEY` values are committed to source control.
- **No committed databases:** Runtime SQLite databases are stored in `instance/` and excluded via `.gitignore`.
- **Localhost binding:** `run.py` binds to `127.0.0.1` by default with `debug=False`.
