"""Security tests for Reflected and Stored XSS (OWASP A03:2021) in vulnerable vs secure modes."""

from __future__ import annotations

from tests.conftest import create_user_in_db, extract_csrf_token, login_via_form

REFLECTED_PAYLOAD = "<script>window.__xss_reflected=1;</script>"
STORED_PAYLOAD = "<img src=x onerror=window.__xss_stored=1>"


def test_reflected_xss_present_in_vulnerable_mode(vulnerable_app, vulnerable_client, passwords):
    create_user_in_db(vulnerable_app, "alice", "alice@local.test", passwords["alice"])
    login_via_form(vulnerable_client, "alice", passwords["alice"], include_csrf=False)

    resp = vulnerable_client.get(f"/dashboard?q={REFLECTED_PAYLOAD}")
    assert resp.status_code == 200
    # Unescaped script tag is reflected directly into HTML response
    assert REFLECTED_PAYLOAD.encode() in resp.data
    assert "Content-Security-Policy" not in resp.headers


def test_reflected_xss_encoded_and_csp_enforced_in_secure_mode(secure_app, secure_client, passwords):
    create_user_in_db(secure_app, "alice", "alice@local.test", passwords["alice"])
    login_via_form(secure_client, "alice", passwords["alice"], include_csrf=True)

    resp = secure_client.get(f"/dashboard?q={REFLECTED_PAYLOAD}")
    assert resp.status_code == 200
    assert REFLECTED_PAYLOAD.encode() not in resp.data
    assert b"&lt;script&gt;window.__xss_reflected=1;&lt;/script&gt;" in resp.data
    assert "script-src 'self'" in resp.headers.get("Content-Security-Policy", "")


def test_stored_xss_present_in_vulnerable_mode(vulnerable_app, vulnerable_client, passwords):
    create_user_in_db(vulnerable_app, "alice", "alice@local.test", passwords["alice"])
    login_via_form(vulnerable_client, "alice", passwords["alice"], include_csrf=False)

    vulnerable_client.post(
        "/notes/create",
        data={"title": "XSS Note", "category": "Vulnerability", "content": STORED_PAYLOAD},
        follow_redirects=True,
    )
    dash = vulnerable_client.get("/dashboard")
    assert STORED_PAYLOAD.encode() in dash.data


def test_stored_xss_output_encoded_in_secure_mode(secure_app, secure_client, passwords):
    create_user_in_db(secure_app, "alice", "alice@local.test", passwords["alice"])
    login_via_form(secure_client, "alice", passwords["alice"], include_csrf=True)

    dash = secure_client.get("/dashboard")
    csrf = extract_csrf_token(dash.data)
    resp = secure_client.post(
        "/notes/create",
        data={
            "csrf_token": csrf,
            "title": "XSS Note",
            "category": "Vulnerability",
            "content": STORED_PAYLOAD,
        },
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert STORED_PAYLOAD.encode() not in resp.data
    assert b"&lt;img src=x onerror=window.__xss_stored=1&gt;" in resp.data
