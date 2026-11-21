"""Shared pytest fixtures and helpers for vulnerable vs secure testing."""

from __future__ import annotations

import re
import secrets
import string

import pytest

from app import create_app
from app.db import get_db, utc_now_iso
from app.security import hash_password

CSRF_INPUT_RE = re.compile(r'name="csrf_token"\s+value="([^"]+)"')


def make_strong_password(length: int = 16) -> str:
    """Generate an ephemeral strong password at test runtime (no hardcoded credentials)."""
    rng = secrets.SystemRandom()
    required = [
        rng.choice(string.ascii_uppercase),
        rng.choice(string.ascii_lowercase),
        rng.choice(string.digits),
        rng.choice("!@#$%^&*"),
    ]
    pool = string.ascii_letters + string.digits + "!@#$%^&*"
    required.extend(rng.choice(pool) for _ in range(length - len(required)))
    rng.shuffle(required)
    return "".join(required)


def extract_csrf_token(html_bytes: bytes) -> str:
    """Extract the hidden csrf_token value from rendered HTML."""
    text = html_bytes.decode("utf-8", errors="ignore")
    match = CSRF_INPUT_RE.search(text)
    assert match is not None, "Expected a csrf_token input in HTML response"
    return match.group(1)


def create_user_in_db(app, username: str, email: str, raw_password: str, role: str = "user") -> int:
    """Insert a test user directly into the app's isolated SQLite database."""
    with app.app_context():
        db = get_db()
        stored_pw = raw_password if app.config["IS_VULNERABLE"] else hash_password(raw_password)
        cur = db.execute(
            """
            INSERT INTO users (username, email, password_hash, role, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (username, email, stored_pw, role, utc_now_iso()),
        )
        db.commit()
        return int(cur.lastrowid)


def create_note_in_db(
    app,
    user_id: int,
    title: str,
    content: str,
    category: str = "General",
) -> int:
    """Insert a test security note into the app's isolated SQLite database."""
    with app.app_context():
        db = get_db()
        cur = db.execute(
            """
            INSERT INTO notes (user_id, title, content, category, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (user_id, title, content, category, utc_now_iso()),
        )
        db.commit()
        return int(cur.lastrowid)


def login_via_form(client, username: str, password: str, include_csrf: bool = True):
    """Submit the /login form using a test client."""
    form_data = {"username": username, "password": password}
    if include_csrf:
        page = client.get("/login")
        form_data["csrf_token"] = extract_csrf_token(page.data)
    return client.post("/login", data=form_data, follow_redirects=False)


@pytest.fixture
def passwords() -> dict[str, str]:
    """Fresh ephemeral strong passwords per test."""
    return {
        "admin": make_strong_password(),
        "alice": make_strong_password(),
        "bob": make_strong_password(),
    }


@pytest.fixture
def secure_app(tmp_path):
    """Isolated Flask application configured in SECURE mode."""
    app = create_app(
        test_config={
            "TESTING": True,
            "SECURITY_MODE": "secure",
            "DATABASE_PATH": str(tmp_path / "secure_test.db"),
            "SECRET_KEY": secrets.token_hex(32),
        }
    )
    return app


@pytest.fixture
def vulnerable_app(tmp_path):
    """Isolated Flask application configured in VULNERABLE mode."""
    app = create_app(
        test_config={
            "TESTING": True,
            "SECURITY_MODE": "vulnerable",
            "DATABASE_PATH": str(tmp_path / "vulnerable_test.db"),
            "SECRET_KEY": secrets.token_hex(4),
        }
    )
    return app


@pytest.fixture
def secure_client(secure_app):
    return secure_app.test_client()


@pytest.fixture
def vulnerable_client(vulnerable_app):
    return vulnerable_app.test_client()
