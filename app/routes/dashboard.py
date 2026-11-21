"""Authenticated user dashboard, security notes CRUD, search, and profile settings."""

from __future__ import annotations

import sqlite3

from flask import Blueprint, abort, current_app, flash, g, redirect, render_template, request, url_for

from app.db import get_db, log_security_event, utc_now_iso
from app.security import (
    ALLOWED_NOTE_CATEGORIES,
    csrf_protect,
    login_required,
    validate_email,
    validate_note_input,
)

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/dashboard")
@login_required
def home():
    """User dashboard displaying personal security notes and search functionality."""
    search_query = request.args.get("q", "").strip()
    is_vulnerable = current_app.config["IS_VULNERABLE"]
    db = get_db()
    sql_error = None

    if search_query:
        if is_vulnerable:
            # VULNERABLE: SQL Injection in search filter allows extracting other users' notes
            # e.g., payload: ' OR '1'='1' --
            raw_sql = (
                "SELECT n.id, n.user_id, n.title, n.content, n.category, n.created_at, u.username AS author "
                "FROM notes n JOIN users u ON n.user_id = u.id "
                f"WHERE n.user_id = {g.user['id']} "
                f"AND (n.title || ' ' || n.content) LIKE '%{search_query}%' "
                "ORDER BY n.id DESC"
            )
            try:
                notes = db.execute(raw_sql).fetchall()
            except sqlite3.Error as exc:
                notes = []
                sql_error = str(exc)
        else:
            # SECURE: parameterized query strictly scoped to current user's notes
            like_pattern = f"%{search_query}%"
            notes = db.execute(
                """
                SELECT n.id, n.user_id, n.title, n.content, n.category, n.created_at, u.username AS author
                FROM notes n
                JOIN users u ON n.user_id = u.id
                WHERE n.user_id = ?
                  AND (n.title LIKE ? OR n.content LIKE ?)
                ORDER BY n.id DESC
                """,
                (g.user["id"], like_pattern, like_pattern),
            ).fetchall()
    else:
        notes = db.execute(
            """
            SELECT n.id, n.user_id, n.title, n.content, n.category, n.created_at, u.username AS author
            FROM notes n
            JOIN users u ON n.user_id = u.id
            WHERE n.user_id = ?
            ORDER BY n.id DESC
            """,
            (g.user["id"],),
        ).fetchall()

    total_notes = db.execute(
        "SELECT COUNT(*) AS cnt FROM notes WHERE user_id = ?",
        (g.user["id"],),
    ).fetchone()["cnt"]

    recent_events = db.execute(
        """
        SELECT action, details, created_at
        FROM audit_logs
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 5
        """,
        (g.user["id"],),
    ).fetchall()

    return render_template(
        "dashboard.html",
        notes=notes,
        total_notes=total_notes,
        search_query=search_query,
        sql_error=sql_error,
        categories=sorted(ALLOWED_NOTE_CATEGORIES),
        recent_events=recent_events,
    )


@dashboard_bp.route("/notes/create", methods=["POST"])
@login_required
@csrf_protect
def create_note():
    """Create a new personal security note."""
    title = request.form.get("title", "").strip()
    content = request.form.get("content", "").strip()
    category = request.form.get("category", "General").strip()

    if not current_app.config["IS_VULNERABLE"]:
        ok, msg = validate_note_input(title, content, category)
        if not ok:
            flash(msg, "danger")
            return redirect(url_for("dashboard.home"))
    else:
        if not title or not content:
            flash("Title and content are required.", "danger")
            return redirect(url_for("dashboard.home"))
        if category not in ALLOWED_NOTE_CATEGORIES:
            category = "General"

    db = get_db()
    cursor = db.execute(
        """
        INSERT INTO notes (user_id, title, content, category, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (g.user["id"], title, content, category, utc_now_iso()),
    )
    db.commit()
    log_security_event(
        action="NOTE_CREATED",
        details=f"Created note #{cursor.lastrowid} in category '{category}'.",
        user_id=g.user["id"],
        username=g.user["username"],
    )
    flash("Security note created.", "success")
    return redirect(url_for("dashboard.home"))


@dashboard_bp.route("/notes/<int:note_id>")
@login_required
def view_note(note_id: int):
    """View a single note.

    - Vulnerable mode: IDOR — fetches note by ID without verifying ownership.
    - Secure mode: enforces strict object-level ownership (owner or admin only).
    """
    db = get_db()
    note = db.execute(
        """
        SELECT n.id, n.user_id, n.title, n.content, n.category, n.created_at, u.username AS author
        FROM notes n
        JOIN users u ON n.user_id = u.id
        WHERE n.id = ?
        """,
        (note_id,),
    ).fetchone()

    if note is None:
        abort(404)

    if not current_app.config["IS_VULNERABLE"]:
        if note["user_id"] != g.user["id"] and g.user["role"] != "admin":
            log_security_event(
                action="IDOR_BLOCKED",
                details=(
                    f"User '{g.user['username']}' attempted unauthorized read of note #{note_id} "
                    f"owned by user_id={note['user_id']}."
                ),
                user_id=g.user["id"],
                username=g.user["username"],
            )
            abort(403, description="You do not have permission to view this note.")

    return render_template("note_detail.html", note=note)


@dashboard_bp.route("/notes/<int:note_id>/delete", methods=["POST"])
@login_required
@csrf_protect
def delete_note(note_id: int):
    """Delete a note.

    - Vulnerable mode: IDOR + no CSRF protection.
    - Secure mode: verifies CSRF token AND object ownership before deletion.
    """
    db = get_db()
    note = db.execute("SELECT id, user_id, title FROM notes WHERE id = ?", (note_id,)).fetchone()
    if note is None:
        abort(404)

    if not current_app.config["IS_VULNERABLE"]:
        if note["user_id"] != g.user["id"] and g.user["role"] != "admin":
            log_security_event(
                action="IDOR_DELETE_BLOCKED",
                details=f"User '{g.user['username']}' attempted unauthorized deletion of note #{note_id}.",
                user_id=g.user["id"],
                username=g.user["username"],
            )
            abort(403, description="You do not have permission to delete this note.")

    db.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    db.commit()
    log_security_event(
        action="NOTE_DELETED",
        details=f"Deleted note #{note_id}.",
        user_id=g.user["id"],
        username=g.user["username"],
    )
    flash("Note deleted.", "info")
    return redirect(url_for("dashboard.home"))


@dashboard_bp.route("/profile")
@login_required
def profile():
    """Display user account profile and update form."""
    return render_template("profile.html")


@dashboard_bp.route("/profile/update", methods=["POST"])
@login_required
@csrf_protect
def update_profile():
    """Update the authenticated user's email address (primary CSRF demonstration target)."""
    new_email = request.form.get("email", "").strip().lower()

    if not current_app.config["IS_VULNERABLE"]:
        ok, msg = validate_email(new_email)
        if not ok:
            flash(msg, "danger")
            return redirect(url_for("dashboard.profile"))
    else:
        if not new_email:
            flash("Email is required.", "danger")
            return redirect(url_for("dashboard.profile"))

    db = get_db()
    try:
        db.execute(
            "UPDATE users SET email = ? WHERE id = ?",
            (new_email, g.user["id"]),
        )
        db.commit()
    except sqlite3.IntegrityError:
        flash("That email address is already in use.", "danger")
        return redirect(url_for("dashboard.profile"))

    log_security_event(
        action="PROFILE_EMAIL_UPDATED",
        details=f"Email updated to '{new_email}'.",
        user_id=g.user["id"],
        username=g.user["username"],
    )
    flash("Profile email updated successfully.", "success")
    return redirect(url_for("dashboard.profile"))
