"""Optional local database seeder for classroom/internship demonstrations.

Security note:
- No passwords are hardcoded in this script.
- Supply DEMO_ADMIN_PASSWORD and DEMO_USER_PASSWORD via environment variables,
  or let the script generate ephemeral random passwords and print them once locally.
"""

from __future__ import annotations

import argparse
import os
import secrets
import string
import sys
from pathlib import Path

# Allow running directly as: python scripts/seed_demo_data.py
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app import create_app
from app.db import get_db, log_security_event, utc_now_iso
from app.security import hash_password


def generate_strong_password(length: int = 14) -> str:
    """Generate a random strong password satisfying secure password policy."""
    rng = secrets.SystemRandom()
    chars = [
        rng.choice(string.ascii_uppercase),
        rng.choice(string.ascii_lowercase),
        rng.choice(string.digits),
        rng.choice("!@#$%^&*"),
    ]
    pool = string.ascii_letters + string.digits + "!@#$%^&*"
    chars.extend(rng.choice(pool) for _ in range(length - len(chars)))
    rng.shuffle(chars)
    return "".join(chars)


def seed_database(mode: str) -> None:
    app = create_app(mode=mode)
    is_vulnerable = app.config["IS_VULNERABLE"]

    admin_pwd = os.environ.get("DEMO_ADMIN_PASSWORD") or generate_strong_password()
    alice_pwd = os.environ.get("DEMO_USER_PASSWORD") or generate_strong_password()
    bob_pwd = os.environ.get("DEMO_SECOND_USER_PASSWORD") or generate_strong_password()

    demo_users = [
        ("admin", "admin@secvault.local", admin_pwd, "admin"),
        ("alice", "alice@secvault.local", alice_pwd, "user"),
        ("bob", "bob@secvault.local", bob_pwd, "user"),
    ]

    with app.app_context():
        db = get_db()
        created_users = {}

        for username, email, raw_password, role in demo_users:
            existing = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
            if existing:
                created_users[username] = existing["id"]
                continue

            stored_pw = raw_password if is_vulnerable else hash_password(raw_password)
            cur = db.execute(
                """
                INSERT INTO users (username, email, password_hash, role, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (username, email, stored_pw, role, utc_now_iso()),
            )
            created_users[username] = cur.lastrowid

        sample_notes = [
            (
                created_users["admin"],
                "Admin Incident Checklist",
                "Confidential admin note: rotate session keys and review audit logs weekly.",
                "Compliance",
            ),
            (
                created_users["alice"],
                "Alice Private Assessment Note",
                "Confidential observation for Alice: verify parameterized queries on login and search.",
                "Vulnerability",
            ),
            (
                created_users["bob"],
                "Bob Remediation Plan",
                "Private note for Bob: enforce RBAC on /admin and add synchronizer CSRF tokens.",
                "Remediation",
            ),
        ]

        existing_notes = db.execute("SELECT COUNT(*) AS cnt FROM notes").fetchone()["cnt"]
        if existing_notes == 0:
            for user_id, title, content, category in sample_notes:
                db.execute(
                    """
                    INSERT INTO notes (user_id, title, content, category, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (user_id, title, content, category, utc_now_iso()),
                )

        db.commit()

        with app.test_request_context("/"):
            log_security_event(
                action="DB_SEEDED",
                details=f"Local demo dataset initialized for mode='{mode}'.",
                username="system",
            )

    print("=" * 64)
    print(f" Seeded local SQLite database for mode: {mode.upper()}")
    print(f" Database path: {app.config['DATABASE_PATH']}")
    print(" Generated local demo credentials (NOT stored in Git):")
    print(f"   admin -> {admin_pwd}")
    print(f"   alice -> {alice_pwd}")
    print(f"   bob   -> {bob_pwd}")
    print("=" * 64)


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed local demo users and notes.")
    parser.add_argument("--mode", choices=["secure", "vulnerable"], default="secure")
    args = parser.parse_args()
    seed_database(args.mode)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
