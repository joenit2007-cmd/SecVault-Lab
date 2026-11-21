"""Application configuration for Secure and Vulnerable educational modes.

IMPORTANT:
- No passwords, API keys, or production secrets are hardcoded in this file.
- By default, the application runs in SECURE mode.
- VULNERABLE mode is strictly intended for local, controlled academic testing.
"""

from __future__ import annotations

import os
import secrets
from datetime import timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
INSTANCE_DIR = BASE_DIR / "instance"


def load_local_env(env_path: Path | None = None) -> None:
    """Load simple KEY=VALUE pairs from a local .env file if present."""
    target = env_path or (BASE_DIR / ".env")
    if not target.is_file():
        return
    for raw_line in target.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def _resolve_secret_key(is_vulnerable: bool) -> str:
    """Return a runtime secret key from environment or generate one dynamically."""
    env_key = os.environ.get("FLASK_SECRET_KEY", "").strip()
    if env_key and not env_key.startswith("replace-with-"):
        return env_key
    if is_vulnerable:
        # Intentionally low-entropy ephemeral key to illustrate weak secret configuration
        # without hardcoding any static credential in source control.
        return secrets.token_hex(4)
    return secrets.token_hex(32)


def _str_to_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def build_config(mode: str | None = None) -> dict:
    """Build Flask configuration dictionary for the requested security mode."""
    load_local_env()

    resolved_mode = (mode or os.environ.get("APP_SECURITY_MODE", "secure")).strip().lower()
    if resolved_mode not in {"secure", "vulnerable"}:
        raise ValueError(f"Unsupported APP_SECURITY_MODE '{resolved_mode}'. Use 'secure' or 'vulnerable'.")

    is_vulnerable = resolved_mode == "vulnerable"
    default_db = INSTANCE_DIR / ("secvault_vulnerable.db" if is_vulnerable else "secvault.db")
    db_path = Path(os.environ.get("DATABASE_PATH", str(default_db)))
    if not db_path.is_absolute():
        db_path = BASE_DIR / db_path

    config = {
        "SECURITY_MODE": resolved_mode,
        "IS_VULNERABLE": is_vulnerable,
        "SECRET_KEY": _resolve_secret_key(is_vulnerable),
        "DATABASE_PATH": str(db_path),
        "MAX_CONTENT_LENGTH": 1 * 1024 * 1024,  # 1 MB request body limit
        # Authentication rate limiting (active in secure mode)
        "MAX_FAILED_LOGINS": 5,
        "LOCKOUT_WINDOW_MINUTES": 15,
    }

    if is_vulnerable:
        # Intentionally weak session & error settings for local vulnerability assessment
        config.update(
            {
                "SESSION_COOKIE_NAME": "secvault_vuln_session",
                "SESSION_COOKIE_HTTPONLY": False,
                "SESSION_COOKIE_SAMESITE": None,
                "SESSION_COOKIE_SECURE": False,
                "PERMANENT_SESSION_LIFETIME": timedelta(days=365),
                "EXPOSE_DEBUG_ENDPOINTS": True,
                "VERBOSE_ERRORS": True,
            }
        )
    else:
        # Hardened session and security settings
        config.update(
            {
                "SESSION_COOKIE_NAME": "secvault_session",
                "SESSION_COOKIE_HTTPONLY": True,
                "SESSION_COOKIE_SAMESITE": "Lax",
                "SESSION_COOKIE_SECURE": _str_to_bool(os.environ.get("SESSION_COOKIE_SECURE"), False),
                "PERMANENT_SESSION_LIFETIME": timedelta(minutes=30),
                "EXPOSE_DEBUG_ENDPOINTS": False,
                "VERBOSE_ERRORS": False,
            }
        )

    return config
