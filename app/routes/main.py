"""Public routes, lab guide, security misconfiguration demos, and local CSRF harness."""

from __future__ import annotations

import platform
import sys

from flask import Blueprint, abort, current_app, g, jsonify, render_template

from app.db import get_db

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def index():
    """Landing page summarizing the application and active security posture."""
    db = get_db()
    user_count = db.execute("SELECT COUNT(*) AS cnt FROM users").fetchone()["cnt"]
    note_count = db.execute("SELECT COUNT(*) AS cnt FROM notes").fetchone()["cnt"]
    audit_count = db.execute("SELECT COUNT(*) AS cnt FROM audit_logs").fetchone()["cnt"]

    security_controls = [
        {
            "name": "SQL Injection Protection",
            "owasp": "A03:2021 Injection",
            "enabled": not current_app.config["IS_VULNERABLE"],
            "detail": "Parameterized SQLite queries" if not current_app.config["IS_VULNERABLE"] else "Raw SQL string interpolation active",
        },
        {
            "name": "XSS Output Encoding & CSP",
            "owasp": "A03:2021 Injection",
            "enabled": not current_app.config["IS_VULNERABLE"],
            "detail": "Jinja2 autoescaping + strict CSP" if not current_app.config["IS_VULNERABLE"] else "Unescaped |safe rendering, no CSP",
        },
        {
            "name": "RBAC & Object Ownership",
            "owasp": "A01:2021 Broken Access Control",
            "enabled": not current_app.config["IS_VULNERABLE"],
            "detail": "Server-side role & ownership checks" if not current_app.config["IS_VULNERABLE"] else "Missing ownership & admin role checks",
        },
        {
            "name": "Authentication Hardening",
            "owasp": "A07:2021 Auth Failures",
            "enabled": not current_app.config["IS_VULNERABLE"],
            "detail": "PBKDF2-SHA256 + strong policy + lockout" if not current_app.config["IS_VULNERABLE"] else "Plaintext storage, weak policy, no lockout",
        },
        {
            "name": "Hardened Config & Headers",
            "owasp": "A05:2021 Security Misconfiguration",
            "enabled": not current_app.config["IS_VULNERABLE"],
            "detail": "Security headers, HttpOnly/SameSite, debug off" if not current_app.config["IS_VULNERABLE"] else "Missing headers, /debug/info exposed",
        },
        {
            "name": "CSRF Protection",
            "owasp": "A01:2021 / CWE-352 CSRF",
            "enabled": not current_app.config["IS_VULNERABLE"],
            "detail": "Synchronizer token + SameSite=Lax" if not current_app.config["IS_VULNERABLE"] else "No CSRF token validation",
        },
    ]

    return render_template(
        "index.html",
        user_count=user_count,
        note_count=note_count,
        audit_count=audit_count,
        security_controls=security_controls,
    )


@main_bp.route("/lab-guide")
def lab_guide():
    """Interactive local testing checklist for all 6 OWASP vulnerability categories."""
    return render_template("lab_guide.html")


@main_bp.route("/lab/csrf-demo")
def csrf_demo():
    """Local educational page demonstrating a forged cross-site POST without a CSRF token."""
    return render_template("csrf_demo.html", current_user=g.user)


@main_bp.route("/debug/info")
def debug_info():
    """Security Misconfiguration demo endpoint.

    - Vulnerable mode: leaks runtime configuration, file paths, and routes.
    - Secure mode: disabled (returns 404 Not Found).
    """
    if not current_app.config.get("EXPOSE_DEBUG_ENDPOINTS"):
        abort(404)

    routes = sorted(str(rule) for rule in current_app.url_map.iter_rules())
    return jsonify(
        {
            "warning": "Exposed diagnostic endpoint (Security Misconfiguration demo)",
            "security_mode": current_app.config["SECURITY_MODE"],
            "python_version": sys.version,
            "platform": platform.platform(),
            "database_path": current_app.config["DATABASE_PATH"],
            "session_cookie_httponly": current_app.config["SESSION_COOKIE_HTTPONLY"],
            "session_cookie_samesite": current_app.config["SESSION_COOKIE_SAMESITE"],
            "registered_routes": routes,
        }
    )


@main_bp.route("/debug/error-test")
def debug_error_test():
    """Triggers an intentional server error to compare verbose vs sanitized 500 handling."""
    if not current_app.config.get("EXPOSE_DEBUG_ENDPOINTS"):
        abort(404)
    raise RuntimeError("Simulated database engine exception for Security Misconfiguration test")
