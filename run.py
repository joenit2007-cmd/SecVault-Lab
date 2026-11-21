"""Local entry point to run SecVault in either SECURE or VULNERABLE mode.

Examples:
    python run.py                     # Runs in SECURE mode (default) on 127.0.0.1:5000
    python run.py --mode vulnerable   # Runs in VULNERABLE LAB mode on 127.0.0.1:5000
    python run.py --port 5050         # Custom localhost port
"""

from __future__ import annotations

import argparse
import sys

from app import create_app


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the SecVault Web Application Security Assessment server locally."
    )
    parser.add_argument(
        "--mode",
        choices=["secure", "vulnerable"],
        default=None,
        help="Security mode to launch (defaults to APP_SECURITY_MODE env or 'secure').",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host interface to bind (default: 127.0.0.1 for local-only safety).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=5000,
        help="Port to listen on (default: 5000).",
    )
    return parser.parse_args(argv)


def main() -> int:
    args = parse_args()
    app = create_app(mode=args.mode)

    mode_label = app.config["SECURITY_MODE"].upper()
    print("=" * 68)
    print(f" SecVault Web Application Security Lab | Mode: {mode_label}")
    print(f" Listening on: http://{args.host}:{args.port}")
    print(f" SQLite DB   : {app.config['DATABASE_PATH']}")
    if app.config["IS_VULNERABLE"]:
        print(" WARNING     : Vulnerable mode active! Use ONLY on localhost for testing.")
    print("=" * 68)

    # Debug reloader is kept off by default to avoid Werkzeug PIN / remote debugger exposure.
    app.run(host=args.host, port=args.port, debug=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
