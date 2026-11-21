"""Security tests for Broken Access Control (OWASP A01:2021): IDOR and RBAC."""

from __future__ import annotations

from app.db import get_db
from tests.conftest import create_note_in_db, create_user_in_db, extract_csrf_token, login_via_form


def test_idor_read_and_delete_exploitable_in_vulnerable_mode(vulnerable_app, vulnerable_client, passwords):
    alice_id = create_user_in_db(vulnerable_app, "alice", "alice@local.test", passwords["alice"], role="user")
    create_user_in_db(vulnerable_app, "bob", "bob@local.test", passwords["bob"], role="user")
    alice_note_id = create_note_in_db(vulnerable_app, alice_id, "Alice Private Key", "Top secret alice data")

    # Bob logs in and reads Alice's note via direct object ID
    login_via_form(vulnerable_client, "bob", passwords["bob"], include_csrf=False)
    read_resp = vulnerable_client.get(f"/notes/{alice_note_id}")
    assert read_resp.status_code == 200
    assert b"Top secret alice data" in read_resp.data

    # Bob deletes Alice's note without ownership check
    del_resp = vulnerable_client.post(f"/notes/{alice_note_id}/delete", follow_redirects=False)
    assert del_resp.status_code == 302
    with vulnerable_app.app_context():
        remaining = get_db().execute("SELECT id FROM notes WHERE id = ?", (alice_note_id,)).fetchone()
        assert remaining is None


def test_idor_read_and_delete_blocked_in_secure_mode(secure_app, secure_client, passwords):
    alice_id = create_user_in_db(secure_app, "alice", "alice@local.test", passwords["alice"], role="user")
    create_user_in_db(secure_app, "bob", "bob@local.test", passwords["bob"], role="user")
    alice_note_id = create_note_in_db(secure_app, alice_id, "Alice Private Key", "Top secret alice data")

    login_via_form(secure_client, "bob", passwords["bob"], include_csrf=True)
    read_resp = secure_client.get(f"/notes/{alice_note_id}")
    assert read_resp.status_code == 403
    assert b"Top secret alice data" not in read_resp.data

    dash = secure_client.get("/dashboard")
    csrf = extract_csrf_token(dash.data)
    del_resp = secure_client.post(f"/notes/{alice_note_id}/delete", data={"csrf_token": csrf})
    assert del_resp.status_code == 403

    with secure_app.app_context():
        db = get_db()
        still_there = db.execute("SELECT id FROM notes WHERE id = ?", (alice_note_id,)).fetchone()
        assert still_there is not None
        audit = db.execute("SELECT action FROM audit_logs WHERE action = 'IDOR_BLOCKED'").fetchone()
        assert audit is not None


def test_vertical_privilege_escalation_exploitable_in_vulnerable_mode(vulnerable_app, vulnerable_client, passwords):
    bob_id = create_user_in_db(vulnerable_app, "bob", "bob@local.test", passwords["bob"], role="user")
    login_via_form(vulnerable_client, "bob", passwords["bob"], include_csrf=False)

    # Normal user accesses /admin panel
    admin_resp = vulnerable_client.get("/admin")
    assert admin_resp.status_code == 200
    assert b"Registered Users" in admin_resp.data

    # Normal user promotes himself to admin
    promote_resp = vulnerable_client.post(f"/admin/users/{bob_id}/role", data={"role": "admin"})
    assert promote_resp.status_code == 302
    with vulnerable_app.app_context():
        role = get_db().execute("SELECT role FROM users WHERE id = ?", (bob_id,)).fetchone()["role"]
        assert role == "admin"


def test_rbac_blocks_non_admin_in_secure_mode(secure_app, secure_client, passwords):
    bob_id = create_user_in_db(secure_app, "bob", "bob@local.test", passwords["bob"], role="user")
    login_via_form(secure_client, "bob", passwords["bob"], include_csrf=True)

    admin_resp = secure_client.get("/admin")
    assert admin_resp.status_code == 403

    dash = secure_client.get("/dashboard")
    csrf = extract_csrf_token(dash.data)
    promote_resp = secure_client.post(
        f"/admin/users/{bob_id}/role",
        data={"csrf_token": csrf, "role": "admin"},
    )
    assert promote_resp.status_code == 403

    with secure_app.app_context():
        db = get_db()
        role = db.execute("SELECT role FROM users WHERE id = ?", (bob_id,)).fetchone()["role"]
        assert role == "user"
        audit = db.execute("SELECT action FROM audit_logs WHERE action = 'ACCESS_DENIED_RBAC'").fetchone()
        assert audit is not None
