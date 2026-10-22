from flask import Flask, render_template, request, redirect, url_for, session, flash
import mysql.connector
from mysql.connector import Error
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change-this-for-local-demo")

# Database connection
def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="cyber_threat_db"
    )

# Login protection
def login_required(route_function):
    @wraps(route_function)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return route_function(*args, **kwargs)
    return wrapper

# Home page
@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

# Register
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Username and password are required.")
            return render_template("register.html")

        if len(username) > 50 or len(password) < 8:
            flash("Username must be at most 50 characters and password at least 8 characters.")
            return render_template("register.html")

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (username, password) VALUES (%s, %s)",
                (username, generate_password_hash(password))
            )
            conn.commit()
            flash("Registration successful. Please log in.")
            return redirect(url_for("login"))

        except Error:
            flash("Registration failed. This username may already exist.")
        finally:
            if "cursor" in locals():
                cursor.close()
            if "conn" in locals() and conn.is_connected():
                conn.close()

    return render_template("register.html")

# Login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                "SELECT id, username, password FROM users WHERE username = %s",
                (username,)
            )
            user = cursor.fetchone()

            if user and check_password_hash(user["password"], password):
                session.clear()
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                return redirect(url_for("dashboard"))

            flash("Invalid username or password.")

        except Error:
            flash("Database connection error.")
        finally:
            if "cursor" in locals():
                cursor.close()
            if "conn" in locals() and conn.is_connected():
                conn.close()

    return render_template("login.html")

# Dashboard
@app.route("/dashboard")
@login_required
def dashboard():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT COUNT(*) AS total FROM threats")
        total = cursor.fetchone()["total"]

        cursor.execute("SELECT COUNT(*) AS open_count FROM threats WHERE status = 'Open'")
        open_count = cursor.fetchone()["open_count"]

        cursor.execute("SELECT COUNT(*) AS high_count FROM threats WHERE severity = 'High'")
        high_count = cursor.fetchone()["high_count"]

        cursor.execute("SELECT * FROM threats ORDER BY created_at DESC")
        threats = cursor.fetchall()

        return render_template(
            "dashboard.html",
            threats=threats,
            total=total,
            open_count=open_count,
            high_count=high_count
        )
    except Error:
        flash("Could not load threat reports.")
        return redirect(url_for("login"))
    finally:
        if "cursor" in locals():
            cursor.close()
        if "conn" in locals() and conn.is_connected():
            conn.close()

# Add threat
@app.route("/add", methods=["GET", "POST"])
@login_required
def add_threat():
    if request.method == "POST":
        threat_type = request.form.get("threat_type", "").strip()
        description = request.form.get("description", "").strip()
        severity = request.form.get("severity", "")
        allowed_severities = {"Low", "Medium", "High"}

        if not threat_type or not description:
            flash("Please fill in all required fields.")
        elif len(threat_type) > 100 or len(description) > 5000:
            flash("Threat type or description is too long.")
        elif severity not in allowed_severities:
            flash("Please select a valid severity.")
        else:
            try:
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute(
                    """INSERT INTO threats
                    (threat_type, description, severity, reported_by)
                    VALUES (%s, %s, %s, %s)""",
                    (threat_type, description, severity, session["username"])
                )
                conn.commit()
                flash("Threat report added successfully.")
                return redirect(url_for("dashboard"))
            except Error:
                flash("Could not save the report.")
            finally:
                if "cursor" in locals():
                    cursor.close()
                if "conn" in locals() and conn.is_connected():
                    conn.close()

    return render_template("add_threat.html")

# Edit threat
@app.route("/edit/<int:threat_id>", methods=["GET", "POST"])
@login_required
def edit_threat(threat_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        if request.method == "POST":
            threat_type = request.form.get("threat_type", "").strip()
            description = request.form.get("description", "").strip()
            severity = request.form.get("severity", "")
            status = request.form.get("status", "")
            if (not threat_type or not description or len(threat_type) > 100
                    or len(description) > 5000
                    or severity not in {"Low", "Medium", "High"}
                    or status not in {"Open", "In Progress", "Resolved"}):
                flash("Please check the submitted fields.")
            else:
                cursor.execute(
                    """UPDATE threats SET threat_type=%s, description=%s,
                    severity=%s, status=%s WHERE id=%s""",
                    (threat_type, description, severity, status, threat_id)
                )
                conn.commit()
                flash("Threat report updated.")
                return redirect(url_for("dashboard"))

        cursor.execute("SELECT * FROM threats WHERE id=%s", (threat_id,))
        threat = cursor.fetchone()
        if not threat:
            flash("Threat report not found.")
            return redirect(url_for("dashboard"))

        return render_template("edit_threat.html", threat=threat)
    except Error:
        flash("Could not update the report.")
        return redirect(url_for("dashboard"))
    finally:
        if "cursor" in locals():
            cursor.close()
        if "conn" in locals() and conn.is_connected():
            conn.close()

# Delete threat
@app.route("/delete/<int:threat_id>", methods=["POST"])
@login_required
def delete_threat(threat_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM threats WHERE id=%s", (threat_id,))
        conn.commit()
        flash("Threat report deleted.")
    except Error:
        flash("Could not delete the report.")
    finally:
        if "cursor" in locals():
            cursor.close()
        if "conn" in locals() and conn.is_connected():
            conn.close()
    return redirect(url_for("dashboard"))

# Logout
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)
