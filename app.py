
import os
import sqlite3
import secrets
import hashlib
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "societyfix-local-development-key-change-before-deployment"
)

app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False

DATABASE = "societyfix.db"


def get_db_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database():
    connection = get_db_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS complaints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            resident TEXT NOT NULL,
            flat TEXT NOT NULL,
            category TEXT NOT NULL,
            priority TEXT NOT NULL,
            description TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Pending',
            created_at TEXT NOT NULL
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            flat TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            expires_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # Add user_id to the existing complaints table safely.
    # Existing complaints and their IDs are preserved.
    complaint_columns = [
        column["name"]
        for column in connection.execute(
            "PRAGMA table_info(complaints)"
        ).fetchall()
    ]

    if "user_id" not in complaint_columns:
        connection.execute("""
            ALTER TABLE complaints
            ADD COLUMN user_id INTEGER REFERENCES users(id)
        """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            complaint_id INTEGER,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            is_read INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (complaint_id) REFERENCES complaints(id)
        )
    """)

    # Link older complaints to an account when both name and flat match.
    # Unmatched older complaints remain unchanged.
    connection.execute("""
        UPDATE complaints
        SET user_id = (
            SELECT u.id
            FROM users u
            WHERE LOWER(TRIM(u.name)) = LOWER(TRIM(complaints.resident))
              AND LOWER(TRIM(u.flat)) = LOWER(TRIM(complaints.flat))
            ORDER BY u.id
            LIMIT 1
        )
        WHERE user_id IS NULL
    """)

    connection.commit()
    connection.close()


def login_required(view_function):
    @wraps(view_function)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "error")
            return redirect(url_for("login"))
        return view_function(*args, **kwargs)
    return wrapped_view


def hash_reset_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_notification(
    connection, user_id, title, message, complaint_id=None
):
    connection.execute("""
        INSERT INTO notifications
        (user_id, complaint_id, title, message, is_read, created_at)
        VALUES (?, ?, ?, ?, 0, ?)
    """, (
        user_id,
        complaint_id,
        title,
        message,
        datetime.now().strftime("%d-%m-%Y %I:%M %p")
    ))


@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("home"))

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        flat = request.form.get("flat", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not all([name, email, flat, password, confirm_password]):
            flash("Please fill in all fields.", "error")
            return render_template("register.html")

        if len(password) < 8:
            flash("Password must contain at least 8 characters.", "error")
            return render_template("register.html")

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template("register.html")

        connection = get_db_connection()

        try:
            connection.execute("""
                INSERT INTO users
                (name, email, flat, password_hash, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (
                name,
                email,
                flat,
                generate_password_hash(password),
                datetime.now().strftime("%d-%m-%Y %I:%M %p")
            ))
            connection.commit()

        except sqlite3.IntegrityError:
            flash("An account with this email already exists.", "error")
            return render_template("register.html")

        finally:
            connection.close()

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("home"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        connection = get_db_connection()
        user = connection.execute(
            "SELECT * FROM users WHERE email = ?", (email,)
        ).fetchone()
        connection.close()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session.permanent = True
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            session["user_email"] = user["email"]
            session["user_flat"] = user["flat"]

            return redirect(url_for("home"))

        flash("Invalid email or password.", "error")

    return render_template("login.html")


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    reset_url = None

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()

        if not email:
            flash("Please enter your registered email address.", "error")
            return render_template("forgot_password.html", reset_url=None)

        connection = get_db_connection()
        user = connection.execute(
            "SELECT id FROM users WHERE email = ?", (email,)
        ).fetchone()

        if user:
            connection.execute(
                "DELETE FROM password_resets WHERE user_id = ?",
                (user["id"],)
            )

            token = secrets.token_urlsafe(32)
            token_hash = hash_reset_token(token)
            expiry = (
                datetime.now() + timedelta(minutes=15)
            ).isoformat(timespec="seconds")

            connection.execute("""
                INSERT INTO password_resets
                (user_id, token_hash, expires_at)
                VALUES (?, ?, ?)
            """, (user["id"], token_hash, expiry))

            connection.commit()
            reset_url = url_for(
                "reset_password", token=token, _external=True
            )

        connection.close()

        flash(
            "If that email is registered, a reset link is available "
            "below for local testing.",
            "success"
        )

    return render_template("forgot_password.html", reset_url=reset_url)


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    token_hash = hash_reset_token(token)
    now = datetime.now()

    connection = get_db_connection()
    reset_record = connection.execute("""
        SELECT id, user_id, expires_at
        FROM password_resets
        WHERE token_hash = ?
    """, (token_hash,)).fetchone()

    if not reset_record:
        connection.close()
        flash(
            "This reset link is invalid or has already been used.",
            "error"
        )
        return redirect(url_for("forgot_password"))

    try:
        expiry = datetime.fromisoformat(reset_record["expires_at"])
    except ValueError:
        connection.execute(
            "DELETE FROM password_resets WHERE id = ?",
            (reset_record["id"],)
        )
        connection.commit()
        connection.close()
        flash("Invalid reset link. Please request another one.", "error")
        return redirect(url_for("forgot_password"))

    if now > expiry:
        connection.execute(
            "DELETE FROM password_resets WHERE id = ?",
            (reset_record["id"],)
        )
        connection.commit()
        connection.close()
        flash(
            "This reset link has expired. Please request a new one.",
            "error"
        )
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if len(password) < 8:
            connection.close()
            flash(
                "Password must contain at least 8 characters.",
                "error"
            )
            return render_template("reset_password.html", token=token)

        if password != confirm_password:
            connection.close()
            flash("Passwords do not match.", "error")
            return render_template("reset_password.html", token=token)

        connection.execute("""
            UPDATE users SET password_hash = ? WHERE id = ?
        """, (
            generate_password_hash(password),
            reset_record["user_id"]
        ))

        connection.execute(
            "DELETE FROM password_resets WHERE user_id = ?",
            (reset_record["user_id"],)
        )

        connection.commit()
        connection.close()

        flash(
            "Password reset successfully! Please log in with your new password.",
            "success"
        )
        return redirect(url_for("login"))

    connection.close()
    return render_template("reset_password.html", token=token)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out successfully.", "success")
    return redirect(url_for("login"))


@app.route("/")
@login_required
def home():
    connection = get_db_connection()

    complaints = connection.execute(
        "SELECT * FROM complaints ORDER BY id DESC"
    ).fetchall()

    total = len(complaints)
    pending = sum(1 for c in complaints if c["status"] == "Pending")
    in_progress = sum(
        1 for c in complaints if c["status"] == "In Progress"
    )
    resolved = sum(1 for c in complaints if c["status"] == "Resolved")

    unread_notifications = connection.execute("""
        SELECT COUNT(*) AS total
        FROM notifications
        WHERE user_id = ? AND is_read = 0
    """, (session["user_id"],)).fetchone()["total"]

    connection.close()

    return render_template(
        "index.html",
        total=total,
        pending=pending,
        in_progress=in_progress,
        resolved=resolved,
        unread_notifications=unread_notifications
    )


@app.route("/notifications")
@login_required
def notifications():
    connection = get_db_connection()

    user_notifications = connection.execute("""
        SELECT n.*, c.status AS current_status
        FROM notifications n
        LEFT JOIN complaints c ON c.id = n.complaint_id
        WHERE n.user_id = ?
        ORDER BY n.id DESC
    """, (session["user_id"],)).fetchall()

    unread_count = connection.execute("""
        SELECT COUNT(*) AS total
        FROM notifications
        WHERE user_id = ? AND is_read = 0
    """, (session["user_id"],)).fetchone()["total"]

    connection.close()

    return render_template(
        "notifications.html",
        notifications=user_notifications,
        unread_count=unread_count
    )


@app.route("/notifications/read/<int:notification_id>", methods=["POST"])
@login_required
def mark_notification_read(notification_id):
    connection = get_db_connection()

    connection.execute("""
        UPDATE notifications
        SET is_read = 1
        WHERE id = ? AND user_id = ?
    """, (notification_id, session["user_id"]))

    connection.commit()
    connection.close()

    return redirect(url_for("notifications"))


@app.route("/track", methods=["GET", "POST"])
@login_required
def track():
    complaints = []
    searched = False
    resident = ""
    flat = ""

    if request.method == "POST":
        resident = request.form.get("resident", "").strip()
        flat = request.form.get("flat", "").strip()
        searched = True

        if resident and flat:
            connection = get_db_connection()
            complaints = connection.execute("""
                SELECT * FROM complaints
                WHERE LOWER(TRIM(resident)) = LOWER(TRIM(?))
                AND LOWER(TRIM(flat)) = LOWER(TRIM(?))
                ORDER BY id DESC
            """, (resident, flat)).fetchall()
            connection.close()

    return render_template(
        "track.html",
        complaints=complaints,
        searched=searched,
        resident=resident,
        flat=flat
    )


@app.route("/complaint")
@login_required
def complaint():
    return render_template("complaint.html")


@app.route("/admin")
def admin():
    # Admin-only authentication has not yet been implemented.
    connection = get_db_connection()

    complaints = connection.execute(
        "SELECT * FROM complaints ORDER BY id DESC"
    ).fetchall()

    total = len(complaints)
    pending = sum(1 for c in complaints if c["status"] == "Pending")
    in_progress = sum(
        1 for c in complaints if c["status"] == "In Progress"
    )
    resolved = sum(1 for c in complaints if c["status"] == "Resolved")

    connection.close()

    return render_template(
        "admin.html",
        complaints=complaints,
        total=total,
        pending=pending,
        in_progress=in_progress,
        resolved=resolved
    )


@app.route("/submit-complaint", methods=["POST"])
@login_required
def submit_complaint():
    resident = request.form.get("resident", "").strip()
    flat = request.form.get("flat", "").strip()
    category = request.form.get("category", "").strip()
    priority = request.form.get("priority", "").strip()
    description = request.form.get("description", "").strip()

    if not all([resident, flat, category, priority, description]):
        return "Please complete all fields.", 400

    connection = get_db_connection()

    cursor = connection.execute("""
        INSERT INTO complaints
        (resident, flat, category, priority, description,
         status, created_at, user_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        resident,
        flat,
        category,
        priority,
        description,
        "Pending",
        datetime.now().strftime("%d-%m-%Y %I:%M %p"),
        session["user_id"]
    ))

    complaint_id = cursor.lastrowid

    create_notification(
        connection,
        session["user_id"],
        "Complaint Submitted",
        f"Your complaint #{complaint_id} has been submitted successfully. "
        "Current status: Pending.",
        complaint_id
    )

    connection.commit()
    connection.close()

    return redirect(url_for("success"))


@app.route("/success")
@login_required
def success():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Complaint Submitted | SocietyFix</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {
                font-family: Arial, sans-serif;
                background: #f1f5f9;
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
                margin: 0;
            }
            .card {
                background: white;
                padding: 40px;
                margin: 20px;
                border-radius: 16px;
                text-align: center;
                max-width: 420px;
                box-shadow: 0 8px 30px #0000000a;
            }
            .check { font-size: 55px; }
            h1 { color: #16a34a; }
            p { color: #64748b; line-height: 1.7; }
            a {
                display: inline-block;
                margin: 10px;
                padding: 13px 20px;
                border-radius: 8px;
                background: #2563eb;
                color: white;
                text-decoration: none;
            }
        </style>
    </head>
    <body>
        <div class="card">
            <div class="check">✅</div>
            <h1>Complaint Submitted!</h1>
            <p>Your complaint has been recorded successfully.
            Society management can review it.</p>
            <a href="/complaint">Submit Another</a>
            <a href="/notifications">View Notifications</a>
            <a href="/">Back to Home</a>
        </div>
    </body>
    </html>
    """


@app.route("/update-status/<int:complaint_id>", methods=["POST"])
def update_status(complaint_id):
    # Admin-only authentication has not yet been implemented.
    new_status = request.form.get("status", "")
    allowed_statuses = ["Pending", "In Progress", "Resolved"]

    if new_status not in allowed_statuses:
        return "Invalid complaint status.", 400

    connection = get_db_connection()

    complaint_record = connection.execute("""
        SELECT id, resident, flat, status, user_id
        FROM complaints
        WHERE id = ?
    """, (complaint_id,)).fetchone()

    if not complaint_record:
        connection.close()
        return "Complaint not found.", 404

    old_status = complaint_record["status"]

    if old_status != new_status:
        connection.execute(
            "UPDATE complaints SET status = ? WHERE id = ?",
            (new_status, complaint_id)
        )

        # Prefer the direct account link.
        resident_user_ids = []

        if complaint_record["user_id"] is not None:
            resident_user_ids = [complaint_record["user_id"]]
        else:
            # Fallback for older complaints that could not be linked.
            matching_users = connection.execute("""
                SELECT id FROM users
                WHERE LOWER(TRIM(name)) = LOWER(TRIM(?))
                  AND LOWER(TRIM(flat)) = LOWER(TRIM(?))
            """, (
                complaint_record["resident"],
                complaint_record["flat"]
            )).fetchall()

            resident_user_ids = [user["id"] for user in matching_users]

            # Save the link when a single unambiguous account is found.
            if len(resident_user_ids) == 1:
                connection.execute("""
                    UPDATE complaints SET user_id = ? WHERE id = ?
                """, (resident_user_ids[0], complaint_id))

        if new_status == "In Progress":
            title = "Complaint In Progress"
            message = (
                f"Work has started on your complaint #{complaint_id}."
            )
        elif new_status == "Resolved":
            title = "Complaint Resolved"
            message = (
                f"Your complaint #{complaint_id} has been marked as resolved."
            )
        else:
            title = "Complaint Status Updated"
            message = (
                f"Your complaint #{complaint_id} status changed to Pending."
            )

        for resident_user_id in resident_user_ids:
            create_notification(
                connection,
                resident_user_id,
                title,
                message,
                complaint_id
            )

    connection.commit()
    connection.close()

    return redirect(url_for("admin"))


if __name__ == "__main__":
    initialize_database()
    app.run(debug=True)
