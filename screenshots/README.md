# Screenshots Capture Guide

Use this folder to store the screenshots you capture during your local demonstration for your cybersecurity internship report and GitHub portfolio.

> **Important:** Capture all screenshots strictly from your local instance (`http://127.0.0.1:5000`). Do not include personal passwords, real email addresses, or private system information.

## Recommended Screenshot Checklist

Save your screenshots inside this `screenshots/` folder using the suggested filenames below:

| # | Suggested Filename | Mode | What to Capture |
| :-: | :--- | :---: | :--- |
| 1 | `01_home_secure_mode.png` | Secure | Landing page (`/`) showing the green **SECURE MODE** banner and all 6 controls marked `PROTECTED`. |
| 2 | `02_home_vulnerable_mode.png` | Vulnerable | Landing page (`/`) showing the red **VULNERABLE LAB MODE** banner for side-by-side comparison. |
| 3 | `03_sqli_login_bypass_vulnerable.png` | Vulnerable | Entering `' OR '1'='1' --` on `/login` and resulting unauthorized redirect into `admin`'s dashboard. |
| 4 | `04_sqli_login_blocked_secure.png` | Secure | Same `' OR '1'='1' --` payload on `/login` rejected with `"Invalid username or password."`. |
| 5 | `05_xss_vulnerable_vs_secure.png` | Both | Reflected/Stored XSS executing in Vulnerable mode vs. safely rendered as plain text in Secure mode (with CSP header visible in DevTools). |
| 6 | `06_broken_access_control_idor_admin.png` | Both | Normal user accessing `/admin` or `/notes/1` in Vulnerable mode vs. `403 Forbidden` page in Secure mode. |
| 7 | `07_auth_lockout_429_secure.png` | Secure | Password strength rejection on `/register` and `HTTP 429 Too Many Requests` lockout after 5 failed logins. |
| 8 | `08_misconfig_debug_and_headers.png` | Both | `/debug/info` exposure in Vulnerable mode vs. `404 Not Found` + hardened security headers in Browser DevTools (Network tab) in Secure mode. |
| 9 | `09_csrf_demo_vulnerable_vs_blocked.png` | Both | `/lab/csrf-demo` overwriting email in Vulnerable mode vs. `403 Forbidden (CSRF token missing)` in Secure mode. |
| 10 | `10_admin_audit_logs.png` | Secure | Admin Panel (`/admin`) logged in as `admin`, showing recorded `IDOR_BLOCKED`, `ACCESS_DENIED_RBAC`, and `CSRF_BLOCKED` audit events. |
| 11 | `11_pytest_passing_results.png` | Terminal | Terminal output showing `pytest -v` with all automated functional and security tests passing. |

## Tip for Capturing HTTP Headers (Screenshot #8)
1. Open Chrome or Edge DevTools (`F12`) → **Network** tab.
2. Refresh `http://127.0.0.1:5000/`.
3. Click the first document request (`127.0.0.1`) → **Headers** → **Response Headers**.
4. Capture `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, and `Set-Cookie` (`HttpOnly; SameSite=Lax`).
