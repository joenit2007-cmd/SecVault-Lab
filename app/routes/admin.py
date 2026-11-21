"""Administrative routes protected by Role-Based Access Control (RBAC) in secure mode."""

from __future__ import annotations

from flask import Blueprint, flash, g, redirect, render_template, request, url_for

from app.db import get_db, log_security_event
from app.security import csrf_protect, role_required

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


@admin_bp.route("")
@role_required("admin")
def panel():
    """Admin dashboard displaying all users and security audit logs.

    - Vulnerable mode: role_required bypasses role verification, demonstrating
      Vertical Privilege Escalation (Broken Access Control).
    - Secure mode: strictly enforces server-side database role == 'admin'.
    """
    db = get_db()
    users = db.execute(
        """
        SELECT u.id, u.username, u.email, u.role, u.created_at,
               (SELECT COUNT(*) FROM notes n WHERE n.user_id = u.id) AS note_count
        FROM users u
        ORDER BY u.id ASC
        """
    ).fetchall()

    audit_logs = db.execute(
        """
        SELECT id, username, action, details, ip_address, created_at
        FROM audit_logs
        ORDER BY id DESC
        LIMIT 50
        """
    ).fetchall()

    return render_template("admin.html", users=users, audit_logs=audit_logs)


@admin_bp.route("/users/<int:user_id>/role", methods=["POST"])
@role_required("admin")
@csrf_protect
def update_user_role(user_id: int):
    """Promote or demote a user between 'user' and 'admin' roles."""
    new_role = request.form.get("role", "").strip().lower()
    if new_role not in {"user", "admin"}:
        flash("Invalid role specified.", "danger")
        return redirect(url_for("admin.panel"))

    db = get_db()
    target = db.execute("SELECT id, username, role FROM users WHERE id = ?", (user_id,)).fetchone()
    if target is None:
        flash("User not found.", "danger")
        return redirect(url_for("admin.panel"))

    if target["id"] == g.user["id"] and new_role != "admin" and g.user["role"] == "admin":
        flash("Administrators cannot demote their own active account.", "warning")
        return redirect(url_for("admin.panel"))

    db.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
    db.commit()

    log_security_event(
        action="USER_ROLE_CHANGED",
        details=f"Changed role of '{target['username']}' from '{target['role']}' to '{new_role}'.",
        user_id=g.user["id"],
        username=g.user["username"],
    )
    flash(f"Updated role for {target['username']} to {new_role}.", "success")
    return redirect(url_for("admin.panel"))
