# Automated & Live Verification Testing Results

This document records the **actual verified results** from running the Pytest automated test suite and live local server smoke tests on **SecVault**.

---

## 1. Test Environment

- **Operating System:** Windows (`win32`)
- **Python Version:** `3.13.5`
- **Flask Version:** `3.1.3`
- **Werkzeug Version:** `3.1.9`
- **Pytest Version:** `9.2.0`
- **Database Engine:** SQLite 3 (isolated temporary databases per test via pytest `tmp_path`)

---

## 2. Automated Pytest Suite Summary

**Command Executed:**
```powershell
pytest -v
```

**Overall Result:** **27 passed, 0 failed** in **13.62s**.

### Test Case Breakdown

| Test File | Test Function | Security Scope | Status |
| :--- | :--- | :--- | :---: |
| `tests/test_functional.py` | `test_public_pages_render` | Core public routes (`/`, `/lab-guide`, `/lab/csrf-demo`) | PASSED |
| `tests/test_functional.py` | `test_full_user_lifecycle_register_login_notes_profile_logout` | Registration, login, sessions, note CRUD, search, profile update, logout | PASSED |
| `tests/test_functional.py` | `test_admin_can_access_admin_panel_and_update_roles` | Legitimate admin RBAC workflow & role management | PASSED |
| `tests/test_sqli.py` | `test_sqli_login_bypass_succeeds_in_vulnerable_mode` | SQLi login bypass (`' OR '1'='1' --`) verified in vulnerable mode | PASSED |
| `tests/test_sqli.py` | `test_sqli_login_bypass_blocked_in_secure_mode` | SQLi login bypass rejected (`401`) by parameterized query | PASSED |
| `tests/test_sqli.py` | `test_sqli_search_leaks_other_users_notes_in_vulnerable_mode` | SQLi dashboard search leaks foreign note in vulnerable mode | PASSED |
| `tests/test_sqli.py` | `test_sqli_search_isolated_in_secure_mode` | Parameterized search isolates notes strictly to logged-in user | PASSED |
| `tests/test_xss.py` | `test_reflected_xss_present_in_vulnerable_mode` | Unescaped `<script>` reflected in vulnerable mode | PASSED |
| `tests/test_xss.py` | `test_reflected_xss_encoded_and_csp_enforced_in_secure_mode` | Output encoded as `&lt;script&gt;` + `script-src 'self'` CSP enforced | PASSED |
| `tests/test_xss.py` | `test_stored_xss_present_in_vulnerable_mode` | Unescaped `<img onerror=...>` stored & rendered in vulnerable mode | PASSED |
| `tests/test_xss.py` | `test_stored_xss_output_encoded_in_secure_mode` | Stored XSS HTML-encoded safely in secure mode | PASSED |
| `tests/test_access_control.py` | `test_idor_read_and_delete_exploitable_in_vulnerable_mode` | Cross-user note read & delete succeeds in vulnerable mode | PASSED |
| `tests/test_access_control.py` | `test_idor_read_and_delete_blocked_in_secure_mode` | Cross-user note read & delete returns `403` + `IDOR_BLOCKED` audit log | PASSED |
| `tests/test_access_control.py` | `test_vertical_privilege_escalation_exploitable_in_vulnerable_mode` | Normal user opens `/admin` & self-promotes to `admin` in vulnerable mode | PASSED |
| `tests/test_access_control.py` | `test_rbac_blocks_non_admin_in_secure_mode` | DB-backed RBAC returns `403` + `ACCESS_DENIED_RBAC` audit log | PASSED |
| `tests/test_auth_failures.py` | `test_weak_password_and_plaintext_storage_in_vulnerable_mode` | Weak password `123` accepted & stored plaintext in vulnerable mode | PASSED |
| `tests/test_auth_failures.py` | `test_strong_password_policy_and_pbkdf2_hashing_in_secure_mode` | Weak password rejected (`400`); strong password stored as `pbkdf2:sha256:` | PASSED |
| `tests/test_auth_failures.py` | `test_username_enumeration_in_vulnerable_vs_generic_in_secure` | Distinct errors in vulnerable mode vs. identical generic error in secure mode | PASSED |
| `tests/test_auth_failures.py` | `test_brute_force_allowed_in_vulnerable_and_locked_out_in_secure` | Unlimited retries in vulnerable mode vs. `429` lockout after 5 failures | PASSED |
| `tests/test_auth_failures.py` | `test_session_cleared_on_login_in_secure_mode` | Pre-login session marker cleared on login in secure mode | PASSED |
| `tests/test_misconfiguration.py` | `test_security_headers_missing_in_vulnerable_and_enforced_in_secure` | Missing headers + `X-Powered-By` in vulnerable vs. full headers in secure | PASSED |
| `tests/test_misconfiguration.py` | `test_session_cookie_flags_weak_in_vulnerable_and_hardened_in_secure` | Missing cookie flags in vulnerable vs. `HttpOnly; SameSite=Lax` in secure | PASSED |
| `tests/test_misconfiguration.py` | `test_debug_info_endpoint_exposed_in_vulnerable_and_disabled_in_secure` | `/debug/info` returns `200` in vulnerable vs. `404` in secure | PASSED |
| `tests/test_misconfiguration.py` | `test_error_disclosure_in_vulnerable_vs_hidden_in_secure` | Stack trace leaked in vulnerable mode vs. disabled (`404`) in secure mode | PASSED |
| `tests/test_csrf.py` | `test_csrf_profile_update_succeeds_without_token_in_vulnerable_mode` | Forged `POST /profile/update` overwrites email in vulnerable mode | PASSED |
| `tests/test_csrf.py` | `test_csrf_profile_update_blocked_without_token_in_secure_mode` | Missing/tampered CSRF token returns `403` + `CSRF_BLOCKED`; valid token succeeds | PASSED |
| `tests/test_csrf.py` | `test_csrf_note_creation_blocked_without_token_in_secure_mode` | Forged `POST /notes/create` without CSRF token returns `403` | PASSED |

### Captured Pytest Output
```text
============================= test session starts =============================
platform win32 -- Python 3.13.5, pytest-9.2.0, pluggy-1.7.0
collecting ... collected 27 items

tests/test_access_control.py::test_idor_read_and_delete_exploitable_in_vulnerable_mode PASSED [  3%]
tests/test_access_control.py::test_idor_read_and_delete_blocked_in_secure_mode PASSED [  7%]
tests/test_access_control.py::test_vertical_privilege_escalation_exploitable_in_vulnerable_mode PASSED [ 11%]
tests/test_access_control.py::test_rbac_blocks_non_admin_in_secure_mode PASSED [ 14%]
tests/test_auth_failures.py::test_weak_password_and_plaintext_storage_in_vulnerable_mode PASSED [ 18%]
tests/test_auth_failures.py::test_strong_password_policy_and_pbkdf2_hashing_in_secure_mode PASSED [ 22%]
tests/test_auth_failures.py::test_username_enumeration_in_vulnerable_vs_generic_in_secure PASSED [ 25%]
tests/test_auth_failures.py::test_brute_force_allowed_in_vulnerable_and_locked_out_in_secure PASSED [ 29%]
tests/test_auth_failures.py::test_session_cleared_on_login_in_secure_mode PASSED [ 33%]
tests/test_csrf.py::test_csrf_profile_update_succeeds_without_token_in_vulnerable_mode PASSED [ 37%]
tests/test_csrf.py::test_csrf_profile_update_blocked_without_token_in_secure_mode PASSED [ 40%]
tests/test_csrf.py::test_csrf_note_creation_blocked_without_token_in_secure_mode PASSED [ 44%]
tests/test_functional.py::test_public_pages_render PASSED                [ 48%]
tests/test_functional.py::test_full_user_lifecycle_register_login_notes_profile_logout PASSED [ 51%]
tests/test_functional.py::test_admin_can_access_admin_panel_and_update_roles PASSED [ 55%]
tests/test_misconfiguration.py::test_security_headers_missing_in_vulnerable_and_enforced_in_secure PASSED [ 59%]
tests/test_misconfiguration.py::test_session_cookie_flags_weak_in_vulnerable_and_hardened_in_secure PASSED [ 62%]
tests/test_misconfiguration.py::test_debug_info_endpoint_exposed_in_vulnerable_and_disabled_in_secure PASSED [ 66%]
tests/test_misconfiguration.py::test_error_disclosure_in_vulnerable_vs_hidden_in_secure PASSED [ 70%]
tests/test_sqli.py::test_sqli_login_bypass_succeeds_in_vulnerable_mode PASSED [ 74%]
tests/test_sqli.py::test_sqli_login_bypass_blocked_in_secure_mode PASSED [ 77%]
tests/test_sqli.py::test_sqli_search_leaks_other_users_notes_in_vulnerable_mode PASSED [ 81%]
tests/test_sqli.py::test_sqli_search_isolated_in_secure_mode PASSED      [ 85%]
tests/test_xss.py::test_reflected_xss_present_in_vulnerable_mode PASSED  [ 88%]
tests/test_xss.py::test_reflected_xss_encoded_and_csp_enforced_in_secure_mode PASSED [ 92%]
tests/test_xss.py::test_stored_xss_present_in_vulnerable_mode PASSED     [ 96%]
tests/test_xss.py::test_stored_xss_output_encoded_in_secure_mode PASSED  [100%]

============================= 27 passed in 13.62s =============================
```

---

## 3. Live Local HTTP Server Smoke Verification

Both modes were launched via `run.py` on `127.0.0.1` and probed over real local HTTP sockets:

| Mode | Endpoint | HTTP Status | Observed Response Headers |
| :--- | :--- | :---: | :--- |
| `secure` | `GET /` | `200 OK` | `Content-Security-Policy: default-src 'self'; script-src 'self'; ...`, `X-Frame-Options: DENY`, `X-Powered-By: (absent)` |
| `secure` | `GET /debug/info` | `404 Not Found` | Hardened headers enforced; debug route disabled |
| `vulnerable` | `GET /` | `200 OK` | `Content-Security-Policy: (absent)`, `X-Frame-Options: (absent)`, `X-Powered-By: SecVault-Lab-Vulnerable/1.0 (Flask/SQLite)` |
| `vulnerable` | `GET /debug/info` | `200 OK` | Leaks JSON runtime diagnostics (Python version, DB path, routes) |

Additionally, `scripts/seed_demo_data.py --mode secure` was executed and verified to initialize tables, seed demo users/notes, and print randomly generated ephemeral credentials without committing any secrets or database files to the repository.
