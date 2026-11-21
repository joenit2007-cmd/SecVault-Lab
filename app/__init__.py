"""Flask application factory for SecVault Web Application Security Lab."""

from __future__ import annotations

import traceback

from flask import Flask, render_template, request

from app.config import build_config
from app.db import close_db, init_db
from app.security import apply_security_headers, get_csrf_token, load_logged_in_user


def create_app(test_config: dict | None = None, mode: str | None = None) -> Flask:
    """Create and configure the Flask application instance."""
    app = Flask(__name__, instance_relative_config=True)

    resolved_mode = mode
    if test_config and "SECURITY_MODE" in test_config:
        resolved_mode = test_config["SECURITY_MODE"]

    app.config.from_mapping(build_config(mode=resolved_mode))
    if test_config:
        app.config.update(test_config)
        if "SECURITY_MODE" in test_config:
            app.config["IS_VULNERABLE"] = test_config["SECURITY_MODE"] == "vulnerable"

    # Ensure database schema exists at startup
    with app.app_context():
        init_db()

    # Lifecycle hooks
    app.teardown_appcontext(close_db)
    app.before_request(load_logged_in_user)
    app.after_request(apply_security_headers)

    # Jinja template globals
    @app.context_processor
    def inject_security_context():
        return {
            "csrf_token": get_csrf_token,
            "is_vulnerable": app.config["IS_VULNERABLE"],
            "security_mode": app.config["SECURITY_MODE"],
        }

    # Register blueprints
    from app.routes.admin import admin_bp
    from app.routes.auth import auth_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.main import main_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(admin_bp)

    # Custom error handlers
    @app.errorhandler(403)
    def handle_403(error):
        return (
            render_template(
                "errors/403.html",
                message=getattr(error, "description", "Access denied."),
            ),
            403,
        )

    @app.errorhandler(404)
    def handle_404(_error):
        return render_template("errors/404.html"), 404

    @app.errorhandler(429)
    def handle_429(error):
        return (
            render_template(
                "errors/429.html",
                message=getattr(error, "description", "Too many requests. Please try again later."),
            ),
            429,
        )

    @app.errorhandler(500)
    def handle_500(error):
        # Vulnerable mode leaks stack trace details (Security Misconfiguration).
        # Secure mode displays a generic user-friendly error page.
        debug_trace = None
        if app.config.get("VERBOSE_ERRORS"):
            debug_trace = (
                f"Path: {request.path}\n"
                f"Exception: {repr(error)}\n"
                f"Database: {app.config.get('DATABASE_PATH')}\n\n"
                f"{traceback.format_exc()}"
            )
        return render_template("errors/500.html", debug_trace=debug_trace), 500

    return app
