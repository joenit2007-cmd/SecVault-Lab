"""Security tests for Identification & Authentication Failures (OWASP A07:2021)."""

from __future__ import annotations

from app.db import get_db
from tests.conftest import create_user_in_db, extract_csrf_token, login_via_form


def test_weak_password_and_plaintext_storage_in_vulnerable_mode(vulnerable_app, vulnerable_client):
    weak_pw = "123"
    resp = vulnerable_client.post(
        "/register",
        data={
            "username": "weak_user",
            "email": "weak@local.test",
            "password": weak_pw,
            "confirm_password": weak_pw,
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302

    with vulnerable_app.app_context():
        row = get_db().execute(
            "SELECT password_hash FROM users WHERE username = ?", ("weak_user",)
        ).fetchone()
        # Vulnerable mode stores raw plaintext password
        assert row["password_hash"] == weak_pw


def test_strong_password_policy_and_pbkdf2_hashing_in_secure_mode(secure_app, secure_client, passwords):
    reg_page = secure_client.get("/register")
    csrf = extract_csrf_token(reg_page.data)

    # Weak password rejected
    weak_resp = secure_client.post(
        "/register",
        data={
            "csrf_token": csrf,
            "username": "weak_user",
            "email": "weak@local.test",
            "password": "123",
            "confirm_password": "123",
        },
    )
    assert weak_resp.status_code == 400
    assert b"at least 10 characters" in weak_resp.data

    # Strong password accepted and hashed with PBKDF2-SHA256
    strong_pw = passwords["alice"]
    ok_resp = secure_client.post(
        "/register",
        data={
            "csrf_token": csrf,
            "username": "strong_user",
            "email": "strong@local.test",
            "password": strong_pw,
            "confirm_password": strong_pw,
        },
        follow_redirects=False,
    )
    assert ok_resp.status_code == 302

    with secure_app.app_context():
        row = get_db().execute(
            "SELECT password_hash FROM users WHERE username = ?", ("strong_user",)
        ).fetchone()
        assert row["password_hash"] != strong_pw
        assert row["password_hash"].startswith("pbkdf2:sha256:")


def test_username_enumeration_in_vulnerable_vs_generic_in_secure(
    vulnerable_app, vulnerable_client, secure_app, secure_client, passwords
):
    create_user_in_db(vulnerable_app, "alice", "alice@local.test", passwords["alice"])
    create_user_in_db(secure_app, "alice", "alice@local.test", passwords["alice"])

    # Vulnerable mode leaks whether username exists
    v_missing = login_via_form(vulnerable_client, "ghost_user", "wrong", include_csrf=False)
    v_wrong_pw = login_via_form(vulnerable_client, "alice", "wrong", include_csrf=False)
    assert b"does not exist" in v_missing.data
    assert b"incorrect password" in v_wrong_pw.data

    # Secure mode returns identical generic message
    s_missing = login_via_form(secure_client, "ghost_user", "wrong", include_csrf=True)
    s_wrong_pw = login_via_form(secure_client, "alice", "wrong", include_csrf=True)
    assert s_missing.status_code == 401
    assert s_wrong_pw.status_code == 401
    assert b"Invalid username or password." in s_missing.data
    assert b"Invalid username or password." in s_wrong_pw.data
    assert b"does not exist" not in s_missing.data


def test_brute_force_allowed_in_vulnerable_and_locked_out_in_secure(
    vulnerable_app, vulnerable_client, secure_app, secure_client, passwords
):
    create_user_in_db(vulnerable_app, "alice", "alice@local.test", passwords["alice"])
    create_user_in_db(secure_app, "alice", "alice@local.test", passwords["alice"])

    # Vulnerable mode never locks out after repeated failed attempts
    for _ in range(7):
        resp = login_via_form(vulnerable_client, "alice", "bad-guess", include_csrf=False)
        assert resp.status_code == 401

    # Secure mode allows 5 failed attempts and locks out with HTTP 429 on the 6th
    for _ in range(5):
        resp = login_via_form(secure_client, "alice", "bad-guess", include_csrf=True)
        assert resp.status_code == 401

    locked_resp = login_via_form(secure_client, "alice", passwords["alice"], include_csrf=True)
    assert locked_resp.status_code == 429


def test_session_cleared_on_login_in_secure_mode(vulnerable_app, vulnerable_client, secure_app, secure_client, passwords):
    create_user_in_db(vulnerable_app, "alice", "alice@local.test", passwords["alice"])
    create_user_in_db(secure_app, "alice", "alice@local.test", passwords["alice"])

    with vulnerable_client.session_transaction() as sess:
        sess["pre_login_marker"] = "persisted"
    login_via_form(vulnerable_client, "alice", passwords["alice"], include_csrf=False)
    with vulnerable_client.session_transaction() as sess:
        assert sess.get("pre_login_marker") == "persisted"

    with secure_client.session_transaction() as sess:
        sess["pre_login_marker"] = "should_be_cleared"
    login_via_form(secure_client, "alice", passwords["alice"], include_csrf=True)
    with secure_client.session_transaction() as sess:
        assert "pre_login_marker" not in sess
        assert sess.get("username") == "alice"
