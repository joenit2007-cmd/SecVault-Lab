"""Security tests for Cross-Site Request Forgery — CSRF (CWE-352)."""

from __future__ import annotations

from app.db import get_db
from tests.conftest import create_user_in_db, extract_csrf_token, login_via_form


def test_csrf_profile_update_succeeds_without_token_in_vulnerable_mode(
    vulnerable_app, vulnerable_client, passwords
):
    alice_id = create_user_in_db(vulnerable_app, "alice", "alice@local.test", passwords["alice"])
    login_via_form(vulnerable_client, "alice", passwords["alice"], include_csrf=False)

    # Forged POST without any CSRF token succeeds in vulnerable mode
    forged_resp = vulnerable_client.post(
        "/profile/update",
        data={"email": "forged-attacker@local.invalid"},
        follow_redirects=False,
    )
    assert forged_resp.status_code == 302

    with vulnerable_app.app_context():
        email = get_db().execute("SELECT email FROM users WHERE id = ?", (alice_id,)).fetchone()["email"]
        assert email == "forged-attacker@local.invalid"


def test_csrf_profile_update_blocked_without_token_in_secure_mode(secure_app, secure_client, passwords):
    alice_id = create_user_in_db(secure_app, "alice", "alice@local.test", passwords["alice"])
    login_via_form(secure_client, "alice", passwords["alice"], include_csrf=True)

    # 1. Forged POST missing CSRF token is blocked with 403
    forged_resp = secure_client.post(
        "/profile/update",
        data={"email": "forged-attacker@local.invalid"},
    )
    assert forged_resp.status_code == 403

    # 2. Forged POST with wrong CSRF token is also blocked with 403
    bad_token_resp = secure_client.post(
        "/profile/update",
        data={"csrf_token": "tampered-invalid-token", "email": "forged-attacker@local.invalid"},
    )
    assert bad_token_resp.status_code == 403

    # Verify email remained unchanged and CSRF_BLOCKED was audit-logged
    with secure_app.app_context():
        db = get_db()
        email = db.execute("SELECT email FROM users WHERE id = ?", (alice_id,)).fetchone()["email"]
        assert email == "alice@local.test"
        audit = db.execute("SELECT action FROM audit_logs WHERE action = 'CSRF_BLOCKED'").fetchone()
        assert audit is not None

    # 3. Legitimate request with valid session CSRF token succeeds
    profile_page = secure_client.get("/profile")
    valid_token = extract_csrf_token(profile_page.data)
    ok_resp = secure_client.post(
        "/profile/update",
        data={"csrf_token": valid_token, "email": "alice.legit@local.test"},
        follow_redirects=False,
    )
    assert ok_resp.status_code == 302
    with secure_app.app_context():
        email = get_db().execute("SELECT email FROM users WHERE id = ?", (alice_id,)).fetchone()["email"]
        assert email == "alice.legit@local.test"


def test_csrf_note_creation_blocked_without_token_in_secure_mode(secure_app, secure_client, passwords):
    create_user_in_db(secure_app, "alice", "alice@local.test", passwords["alice"])
    login_via_form(secure_client, "alice", passwords["alice"], include_csrf=True)

    forged = secure_client.post(
        "/notes/create",
        data={"title": "Forged Note", "category": "General", "content": "Injected by CSRF"},
    )
    assert forged.status_code == 403
