"""Security tests for Security Misconfiguration (OWASP A05:2021)."""

from __future__ import annotations

from tests.conftest import create_user_in_db, login_via_form


def test_security_headers_missing_in_vulnerable_and_enforced_in_secure(vulnerable_client, secure_client):
    vuln_resp = vulnerable_client.get("/")
    assert "Content-Security-Policy" not in vuln_resp.headers
    assert "X-Frame-Options" not in vuln_resp.headers
    assert "X-Content-Type-Options" not in vuln_resp.headers
    assert "X-Powered-By" in vuln_resp.headers

    sec_resp = secure_client.get("/")
    assert "default-src 'self'" in sec_resp.headers.get("Content-Security-Policy", "")
    assert sec_resp.headers.get("X-Frame-Options") == "DENY"
    assert sec_resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert sec_resp.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "Permissions-Policy" in sec_resp.headers
    assert "X-Powered-By" not in sec_resp.headers


def test_session_cookie_flags_weak_in_vulnerable_and_hardened_in_secure(
    vulnerable_app, vulnerable_client, secure_app, secure_client, passwords
):
    create_user_in_db(vulnerable_app, "alice", "alice@local.test", passwords["alice"])
    create_user_in_db(secure_app, "alice", "alice@local.test", passwords["alice"])

    v_resp = login_via_form(vulnerable_client, "alice", passwords["alice"], include_csrf=False)
    v_cookie = v_resp.headers.get("Set-Cookie", "")
    assert "HttpOnly" not in v_cookie
    assert "SameSite=Lax" not in v_cookie

    s_resp = login_via_form(secure_client, "alice", passwords["alice"], include_csrf=True)
    s_cookie = s_resp.headers.get("Set-Cookie", "")
    assert "HttpOnly" in s_cookie
    assert "SameSite=Lax" in s_cookie


def test_debug_info_endpoint_exposed_in_vulnerable_and_disabled_in_secure(vulnerable_client, secure_client):
    v_resp = vulnerable_client.get("/debug/info")
    assert v_resp.status_code == 200
    payload = v_resp.get_json()
    assert "database_path" in payload
    assert "python_version" in payload

    s_resp = secure_client.get("/debug/info")
    assert s_resp.status_code == 404


def test_error_disclosure_in_vulnerable_vs_hidden_in_secure(vulnerable_app, secure_app):
    # Disable Flask exception propagation so errorhandler(500) executes as in real server runs
    vulnerable_app.config["TESTING"] = False
    vulnerable_app.config["PROPAGATE_EXCEPTIONS"] = False
    v_client = vulnerable_app.test_client()

    v_resp = v_client.get("/debug/error-test")
    assert v_resp.status_code == 500
    assert b"RuntimeError" in v_resp.data
    assert b"Database:" in v_resp.data

    # In secure mode /debug/error-test is disabled (404)
    secure_app.config["TESTING"] = False
    secure_app.config["PROPAGATE_EXCEPTIONS"] = False
    s_client = secure_app.test_client()
    assert s_client.get("/debug/error-test").status_code == 404
