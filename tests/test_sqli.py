"""Security tests for SQL Injection (OWASP A03:2021) in vulnerable vs secure modes."""

from __future__ import annotations

from tests.conftest import create_note_in_db, create_user_in_db, login_via_form


def test_sqli_login_bypass_succeeds_in_vulnerable_mode(vulnerable_app, vulnerable_client, passwords):
    create_user_in_db(vulnerable_app, "admin", "admin@local.test", passwords["admin"], role="admin")

    # Classic boolean-based SQLi payload bypasses authentication without knowing password
    resp = login_via_form(
        vulnerable_client,
        username="' OR '1'='1' --",
        password="wrong",
        include_csrf=False,
    )
    assert resp.status_code == 302
    assert "/dashboard" in resp.headers["Location"]

    dash = vulnerable_client.get("/dashboard")
    assert dash.status_code == 200
    assert b"admin" in dash.data


def test_sqli_login_bypass_blocked_in_secure_mode(secure_app, secure_client, passwords):
    create_user_in_db(secure_app, "admin", "admin@local.test", passwords["admin"], role="admin")

    resp = login_via_form(
        secure_client,
        username="' OR '1'='1' --",
        password="wrong",
        include_csrf=True,
    )
    assert resp.status_code == 401
    assert b"Invalid username or password." in resp.data
    assert secure_client.get("/dashboard", follow_redirects=False).status_code == 302


def test_sqli_search_leaks_other_users_notes_in_vulnerable_mode(vulnerable_app, vulnerable_client, passwords):
    admin_id = create_user_in_db(vulnerable_app, "admin", "admin@local.test", passwords["admin"], role="admin")
    alice_id = create_user_in_db(vulnerable_app, "alice", "alice@local.test", passwords["alice"], role="user")

    create_note_in_db(vulnerable_app, admin_id, "SECRET_ADMIN_NOTE", "Confidential admin secret token.")
    create_note_in_db(vulnerable_app, alice_id, "Alice Public Note", "Normal note content.")

    login_via_form(vulnerable_client, "alice", passwords["alice"], include_csrf=False)
    resp = vulnerable_client.get("/dashboard?q=' OR '1'='1' --")
    assert resp.status_code == 200
    # Vulnerable SQL query leaks admin's private note to Alice
    assert b"SECRET_ADMIN_NOTE" in resp.data


def test_sqli_search_isolated_in_secure_mode(secure_app, secure_client, passwords):
    admin_id = create_user_in_db(secure_app, "admin", "admin@local.test", passwords["admin"], role="admin")
    alice_id = create_user_in_db(secure_app, "alice", "alice@local.test", passwords["alice"], role="user")

    create_note_in_db(secure_app, admin_id, "SECRET_ADMIN_NOTE", "Confidential admin secret token.")
    create_note_in_db(secure_app, alice_id, "Alice Normal Note", "Normal note content.")

    login_via_form(secure_client, "alice", passwords["alice"], include_csrf=True)
    resp = secure_client.get("/dashboard?q=' OR '1'='1' --")
    assert resp.status_code == 200
    assert b"SECRET_ADMIN_NOTE" not in resp.data
