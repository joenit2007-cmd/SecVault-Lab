"""Authentication routes: registration, login, and logout."""

from __future__ import annotations

import sqlite3

from flask import Blueprint, abort, current_app, flash, g, redirect, render_template, request, session, url_for

from app.db import get_db, log_security_event, utc_now_iso
from app.security import (
    clear_failed_attempts,
    csrf_protect,
    get_csrf_token,
    hash_password,
    is_login_rate_limited,
    record_login_attempt,
    validate_email,
    validate_password_strength,
    validate_username,
    verify_password,
)

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/register", methods=["GET", "POST"])
@csrf_protect
def register():
    """Register a new user account."""
    if g.user is not None:
        return redirect(url_for("dashboard.home"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        is_vulnerable = current_app.config["IS_VULNERABLE"]

        if not username or not email or not password:
            flash("All fields are required.", "danger")
            return render_template("register.html", username=username, email=email), 400

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("register.html", username=username, email=email), 400

        if not is_vulnerable:
            ok, msg = validate_username(username)
            if not ok:
                flash(msg, "danger")
                return render_template("register.html", username=username, email=email), 400

            ok, msg = validate_email(email)
            if not ok:
                flash(msg, "danger")
                return render_template("register.html", username=username, email=email), 400

            ok, msg = validate_password_strength(password)
            if not ok:
                flash(msg, "danger")
                return render_template("register.html", username=username, email=email), 400

        # Vulnerable mode stores plaintext password (Authentication Failure A07:2021).
        # Secure mode stores salted PBKDF2-HMAC-SHA256 hash.
        stored_password = password if is_vulnerable else hash_password(password)

        db = get_db()
        try:
            cursor = db.execute(
                """
                INSERT INTO users (username, email, password_hash, role, created_at)
                VALUES (?, ?, ?, 'user', ?)
                """,
                (username, email, stored_password, utc_now_iso()),
            )
            db.commit()
            log_security_event(
                action="USER_REGISTERED",
                details=f"New account created for '{username}' (mode={current_app.config['SECURITY_MODE']}).",
                user_id=cursor.lastrowid,
                username=username,
            )
            flash("Account created successfully. You may now sign in.", "success")
            return redirect(url_for("auth.login"))
        except sqlite3.IntegrityError:
            flash("Username or email is already registered.", "danger")
            return render_template("register.html", username=username, email=email), 409

    return render_template("register.html", username="", email="")


@auth_bp.route("/login", methods=["GET", "POST"])
@csrf_protect
def login():
    """Authenticate an existing user."""
    if g.user is not None:
        return redirect(url_for("dashboard.home"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        is_vulnerable = current_app.config["IS_VULNERABLE"]

        if is_vulnerable:
            return _handle_vulnerable_login(username, password)
        return _handle_secure_login(username, password)

    return render_template("login.html", username="")


def _handle_vulnerable_login(username: str, password: str):
    """INTENTIONALLY VULNERABLE login handler for local security assessment.

    Demonstrates:
    - SQL Injection (string concatenation in SQL query)
    - Plaintext password comparison
    - Username enumeration via distinct error messages
    - Missing brute-force rate limiting
    - Missing session regeneration
    """
    db = get_db()
    # VULNERABLE: direct string interpolation allows SQLi such as: ' OR '1'='1' --
    raw_query = (
        f"SELECT id, username, email, password_hash, role "
        f"FROM users WHERE username = '{username}' AND password_hash = '{password}'"
    )
    try:
        user = db.execute(raw_query).fetchone()
    except sqlite3.Error as exc:
        flash(f"SQL Error: {exc}", "danger")
        return render_template("login.html", username=username), 400

    if user is not None:
        # VULNERABLE: does not clear or regenerate prior session state
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["role"] = user["role"]
        log_security_event(
            action="LOGIN_SUCCESS_VULN",
            details=f"User '{user['username']}' logged in via vulnerable auth path.",
            user_id=user["id"],
            username=user["username"],
        )
        flash(f"Welcome back, {user['username']}!", "success")
        return redirect(url_for("dashboard.home"))

    # VULNERABLE: leaks whether username exists (User Enumeration)
    existing = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if existing is None:
        flash(f"Authentication failed: username '{username}' does not exist.", "danger")
    else:
        flash("Authentication failed: incorrect password for this user.", "danger")
    return render_template("login.html", username=username), 401


def _handle_secure_login(username: str, password: str):
    """HARDENED login handler implementing OWASP authentication best practices."""
    if not username or not password:
        flash("Invalid username or password.", "danger")
        return render_template("login.html", username=username), 401

    limited, fail_count = is_login_rate_limited(username)
    if limited:
        log_security_event(
            action="LOGIN_LOCKED_OUT",
            details=f"Rate limit triggered for username '{username}' after {fail_count} failed attempts.",
            username=username,
        )
        abort(
            429,
            description=(
                "Too many failed login attempts. This account or client is temporarily locked "
                "for 15 minutes to protect against brute-force attacks."
            ),
        )

    db = get_db()
    # SECURE: parameterized query prevents SQL Injection
    user = db.execute(
        "SELECT id, username, email, password_hash, role FROM users WHERE username = ?",
        (username,),
    ).fetchone()

    if user is None or not verify_password(user["password_hash"], password):
        record_login_attempt(username, success=False)
        log_security_event(
            action="LOGIN_FAILED",
            details=f"Failed authentication attempt for username '{username}'.",
            user_id=user["id"] if user else None,
            username=username,
        )
        # SECURE: generic message prevents username enumeration
        flash("Invalid username or password.", "danger")
        return render_template("login.html", username=username), 401

    # SECURE: clear old session state (prevents session fixation) and rotate CSRF token
    session.clear()
    session.permanent = True
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"]
    get_csrf_token()

    clear_failed_attempts(username)
    record_login_attempt(username, success=True)
    log_security_event(
        action="LOGIN_SUCCESS",
        details=f"User '{user['username']}' authenticated securely.",
        user_id=user["id"],
        username=user["username"],
    )
    flash(f"Welcome back, {user['username']}!", "success")
    return redirect(url_for("dashboard.home"))


@auth_bp.route("/logout", methods=["POST"])
@csrf_protect
def logout():
    """End the current user session."""
    if g.user is not None:
        log_security_event(
            action="LOGOUT",
            details=f"User '{g.user['username']}' signed out.",
            user_id=g.user["id"],
            username=g.user["username"],
        )
    session.clear()
    flash("You have been signed out.", "info")
    return redirect(url_for("auth.login"))
