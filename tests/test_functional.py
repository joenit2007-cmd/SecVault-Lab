"""Functional tests verifying core web application workflows in secure mode."""

from __future__ import annotations

from app.db import get_db
from tests.conftest import create_user_in_db, extract_csrf_token, login_via_form


def test_public_pages_render(secure_client):
    assert secure_client.get("/").status_code == 200
    assert secure_client.get("/lab-guide").status_code == 200
    assert secure_client.get("/lab/csrf-demo").status_code == 200


def test_full_user_lifecycle_register_login_notes_profile_logout(secure_app, secure_client, passwords):
    # 1. Register new user
    reg_page = secure_client.get("/register")
    csrf = extract_csrf_token(reg_page.data)
    resp = secure_client.post(
        "/register",
        data={
            "csrf_token": csrf,
            "username": "intern_sam",
            "email": "sam@local.test",
            "password": passwords["alice"],
            "confirm_password": passwords["alice"],
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]

    # 2. Login
    login_resp = login_via_form(secure_client, "intern_sam", passwords["alice"])
    assert login_resp.status_code == 302
    assert "/dashboard" in login_resp.headers["Location"]

    # 3. Create security note on dashboard
    dash_page = secure_client.get("/dashboard")
    assert dash_page.status_code == 200
    assert b"intern_sam" in dash_page.data
    csrf = extract_csrf_token(dash_page.data)

    create_resp = secure_client.post(
        "/notes/create",
        data={
            "csrf_token": csrf,
            "title": "TLS Configuration Audit",
            "category": "Compliance",
            "content": "Verify HSTS and modern cipher suites before deployment.",
        },
        follow_redirects=True,
    )
    assert create_resp.status_code == 200
    assert b"TLS Configuration Audit" in create_resp.data

    # 4. Search note
    search_resp = secure_client.get("/dashboard?q=TLS")
    assert search_resp.status_code == 200
    assert b"TLS Configuration Audit" in search_resp.data

    # 5. View note detail & delete own note
    with secure_app.app_context():
        note_id = get_db().execute("SELECT id FROM notes WHERE title = ?", ("TLS Configuration Audit",)).fetchone()["id"]

    detail_resp = secure_client.get(f"/notes/{note_id}")
    assert detail_resp.status_code == 200
    assert b"Verify HSTS" in detail_resp.data
    csrf = extract_csrf_token(detail_resp.data)

    del_resp = secure_client.post(
        f"/notes/{note_id}/delete",
        data={"csrf_token": csrf},
        follow_redirects=True,
    )
    assert del_resp.status_code == 200
    assert b"TLS Configuration Audit" not in del_resp.data

    # 6. Update profile email
    prof_page = secure_client.get("/profile")
    csrf = extract_csrf_token(prof_page.data)
    upd_resp = secure_client.post(
        "/profile/update",
        data={"csrf_token": csrf, "email": "sam.updated@local.test"},
        follow_redirects=True,
    )
    assert upd_resp.status_code == 200
    assert b"sam.updated@local.test" in upd_resp.data

    # 7. Logout clears session
    logout_resp = secure_client.post("/logout", data={"csrf_token": csrf}, follow_redirects=False)
    assert logout_resp.status_code == 302
    assert secure_client.get("/dashboard", follow_redirects=False).status_code == 302


def test_admin_can_access_admin_panel_and_update_roles(secure_app, secure_client, passwords):
    create_user_in_db(secure_app, "admin", "admin@local.test", passwords["admin"], role="admin")
    bob_id = create_user_in_db(secure_app, "bob", "bob@local.test", passwords["bob"], role="user")

    login_resp = login_via_form(secure_client, "admin", passwords["admin"])
    assert login_resp.status_code == 302

    admin_page = secure_client.get("/admin")
    assert admin_page.status_code == 200
    assert b"bob@local.test" in admin_page.data

    csrf = extract_csrf_token(admin_page.data)
    promote_resp = secure_client.post(
        f"/admin/users/{bob_id}/role",
        data={"csrf_token": csrf, "role": "admin"},
        follow_redirects=True,
    )
    assert promote_resp.status_code == 200

    with secure_app.app_context():
        role = get_db().execute("SELECT role FROM users WHERE id = ?", (bob_id,)).fetchone()["role"]
        assert role == "admin"
