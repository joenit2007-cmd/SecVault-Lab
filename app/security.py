"""Security utilities: password hashing, validation, CSRF, RBAC, rate limiting, and headers."""

from __future__ import annotations

import hmac
import re
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Callable

from flask import Response, abort, current_app, flash, g, redirect, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from app.db import get_db, log_security_event

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
ALLOWED_NOTE_CATEGORIES = {"General", "Vulnerability", "Incident", "Compliance", "Remediation"}


# ---------------------------------------------------------------------------
# Password Hashing & Strength Validation
# ---------------------------------------------------------------------------

def hash_password(raw_password: str) -> str:
    """Hash a password using PBKDF2-HMAC-SHA256 with a random per-user salt."""
    return generate_password_hash(raw_password, method="pbkdf2:sha256:600000", salt_length=16)


def verify_password(stored_hash: str, candidate_password: str) -> bool:
    """Verify a password against its salted hash in constant time."""
    if not stored_hash or "$" not in stored_hash:
        return False
    return check_password_hash(stored_hash, candidate_password)


def validate_username(username: str) -> tuple[bool, str]:
    if not username or not USERNAME_RE.match(username):
        return (
            False,
            "Username must be 3-32 characters using only letters, numbers, underscores, dots, or hyphens.",
        )
    return True, ""


def validate_email(email: str) -> tuple[bool, str]:
    if not email or len(email) > 120 or not EMAIL_RE.match(email):
        return False, "Please enter a valid email address."
    return True, ""


def validate_password_strength(password: str) -> tuple[bool, str]:
    """Enforce strong password rules in secure mode."""
    if len(password) < 10:
        return False, "Password must be at least 10 characters long."
    if not any(ch.isupper() for ch in password):
        return False, "Password must include at least one uppercase letter."
    if not any(ch.islower() for ch in password):
        return False, "Password must include at least one lowercase letter."
    if not any(ch.isdigit() for ch in password):
        return False, "Password must include at least one number."
    if not any(ch in "!@#$%^&*()-_=+[]{}|;:',.<>?/" for ch in password):
        return False, "Password must include at least one special character (e.g., !@#$%^&*)."
    return True, ""


def validate_note_input(title: str, content: str, category: str) -> tuple[bool, str]:
    if not title or len(title.strip()) < 2 or len(title.strip()) > 120:
        return False, "Note title must be between 2 and 120 characters."
    if not content or len(content.strip()) < 2 or len(content.strip()) > 2000:
        return False, "Note content must be between 2 and 2000 characters."
    if category not in ALLOWED_NOTE_CATEGORIES:
        return False, "Invalid note category selected."
    return True, ""


# ---------------------------------------------------------------------------
# CSRF Protection (Synchronizer Token Pattern)
# ---------------------------------------------------------------------------

def get_csrf_token() -> str:
    """Return the current session's anti-CSRF token, generating one if absent."""
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def validate_csrf_token() -> bool:
    """Validate submitted CSRF token against the token bound to the user's session."""
    session_token = session.get("_csrf_token")
    submitted_token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    if not session_token or not submitted_token:
        return False
    return hmac.compare_digest(str(session_token), str(submitted_token))


def csrf_protect(view: Callable) -> Callable:
    """Enforce CSRF token verification on state-changing requests in secure mode."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_app.config["IS_VULNERABLE"] and request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            if not validate_csrf_token():
                user = getattr(g, "user", None)
                log_security_event(
                    action="CSRF_BLOCKED",
                    details=f"Invalid or missing CSRF token on {request.method} {request.path}",
                    user_id=user["id"] if user else None,
                    username=user["username"] if user else "anonymous",
                )
                abort(403, description="CSRF token is missing or invalid.")
        return view(*args, **kwargs)

    return wrapped


# ---------------------------------------------------------------------------
# Brute-Force / Login Rate Limiting
# ---------------------------------------------------------------------------

def record_login_attempt(username: str, success: bool) -> None:
    db = get_db()
    ip_addr = request.remote_addr or "127.0.0.1"
    now_iso = datetime.now(timezone.utc).isoformat()
    db.execute(
        """
        INSERT INTO login_attempts (username, ip_address, attempted_at, success)
        VALUES (?, ?, ?, ?)
        """,
        (username.lower(), ip_addr, now_iso, 1 if success else 0),
    )
    db.commit()


def clear_failed_attempts(username: str) -> None:
    db = get_db()
    db.execute(
        "DELETE FROM login_attempts WHERE username = ? AND success = 0",
        (username.lower(),),
    )
    db.commit()


def is_login_rate_limited(username: str) -> tuple[bool, int]:
    """Check if recent failed login attempts exceed the configured threshold."""
    max_attempts = current_app.config["MAX_FAILED_LOGINS"]
    window_minutes = current_app.config["LOCKOUT_WINDOW_MINUTES"]
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=window_minutes)).isoformat()
    ip_addr = request.remote_addr or "127.0.0.1"

    db = get_db()
    row = db.execute(
        """
        SELECT COUNT(*) AS fail_count
        FROM login_attempts
        WHERE (username = ? OR ip_address = ?)
          AND success = 0
          AND attempted_at >= ?
        """,
        (username.lower(), ip_addr, cutoff),
    ).fetchone()
    fail_count = row["fail_count"] if row else 0
    return fail_count >= max_attempts, fail_count


# ---------------------------------------------------------------------------
# Authentication & Role-Based Access Control (RBAC)
# ---------------------------------------------------------------------------

def load_logged_in_user() -> None:
    """Populate flask.g.user from the active session using a parameterized query."""
    user_id = session.get("user_id")
    if user_id is None:
        g.user = None
        return
    db = get_db()
    g.user = db.execute(
        "SELECT id, username, email, role, created_at FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    if g.user is None:
        session.clear()


def login_required(view: Callable) -> Callable:
    """Require an authenticated session."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            flash("Please sign in to access this page.", "warning")
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)

    return wrapped


def role_required(required_role: str) -> Callable:
    """Enforce server-side Role-Based Access Control (RBAC) verified against SQLite."""
    def decorator(view: Callable) -> Callable:
        @wraps(view)
        def wrapped(*args, **kwargs):
            if g.user is None:
                flash("Please sign in to access this page.", "warning")
                return redirect(url_for("auth.login"))

            if not current_app.config["IS_VULNERABLE"]:
                # Always verify the current role from the database record (g.user),
                # never trusting query parameters, cookies, or form fields.
                if g.user["role"] != required_role:
                    log_security_event(
                        action="ACCESS_DENIED_RBAC",
                        details=f"User '{g.user['username']}' (role={g.user['role']}) attempted to access {request.path} requiring '{required_role}'.",
                        user_id=g.user["id"],
                        username=g.user["username"],
                    )
                    abort(403, description="You do not have permission to access this administrative resource.")
            return view(*args, **kwargs)

        return wrapped

    return decorator


# ---------------------------------------------------------------------------
# Secure HTTP Response Headers
# ---------------------------------------------------------------------------

def apply_security_headers(response: Response) -> Response:
    """Attach security headers in secure mode, or expose misconfiguration in vulnerable mode."""
    if current_app.config["IS_VULNERABLE"]:
        # Intentionally omit protective headers and expose diagnostic metadata
        response.headers["X-Powered-By"] = "SecVault-Lab-Vulnerable/1.0 (Flask/SQLite)"
        return response

    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"

    # Prevent caching of sensitive authenticated pages
    if session.get("user_id") is not None:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        response.headers["Pragma"] = "no-cache"

    # Suppress verbose server fingerprinting where applicable
    response.headers.pop("X-Powered-By", None)
    return response
