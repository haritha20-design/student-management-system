from functools import wraps
import os
import re
import secrets
from datetime import datetime, timedelta

from dotenv import load_dotenv
from flask import (
    Flask, render_template, request,
    redirect, url_for, flash, session
)
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash

from db import get_db_connection

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv(
    "FLASK_SECRET_KEY",
    "dev-only-change-this-secret-key"
)

app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")

mail = Mail(app)


# ---------------- DATABASE HELPER ----------------

def fetch_one(query, values=()):
    connection = get_db_connection()

    if not connection:
        return None

    cursor = None

    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(query, values)
        return cursor.fetchone()

    finally:
        if cursor:
            cursor.close()
        connection.close()


# ---------------- LOGIN PROTECTION ----------------

def login_required(route_function):
    @wraps(route_function)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))

        return route_function(*args, **kwargs)

    return wrapper


def admin_required(route_function):
    @wraps(route_function)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))

        if session.get("role") != "admin":
            flash("Admin access is required.", "danger")
            return redirect(url_for("dashboard"))

        return route_function(*args, **kwargs)

    return wrapper


# ---------------- HOME ----------------

@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


# ---------------- REGISTER ----------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not full_name or not email or not password:
            flash("Please fill in all required fields.", "danger")
            return redirect(url_for("register"))

        if not re.fullmatch(
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
            email
        ):
            flash("Please enter a valid email address.", "danger")
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("register"))

        if len(password) < 8:
            flash("Password must contain at least 8 characters.", "danger")
            return redirect(url_for("register"))

        connection = get_db_connection()

        if not connection:
            flash("Database connection failed.", "danger")
            return redirect(url_for("register"))

        cursor = None

        try:
            cursor = connection.cursor()

            cursor.execute(
                "SELECT id FROM users WHERE email = %s",
                (email,)
            )

            if cursor.fetchone():
                flash("This email is already registered.", "danger")
                return redirect(url_for("register"))

            cursor.execute(
                """
                INSERT INTO users
                    (full_name, email, password_hash, role)
                VALUES (%s, %s, %s, 'student')
                """,
                (
                    full_name,
                    email,
                    generate_password_hash(password)
                )
            )

            user_id = cursor.lastrowid

            cursor.execute(
                """
                INSERT INTO students (user_id, name, email)
                VALUES (%s, %s, %s)
                """,
                (user_id, full_name, email)
            )

            connection.commit()

            flash("Registration successful. Please log in.", "success")
            return redirect(url_for("login"))

        except Exception as error:
            connection.rollback()
            print("Registration error:", repr(error))
            flash("Registration failed. Please check your database.", "danger")
            return redirect(url_for("register"))

        finally:
            if cursor:
                cursor.close()
            connection.close()

    return render_template("register.html")


# ---------------- LOGIN ----------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = fetch_one(
            """
            SELECT id, full_name, email, password_hash, role
            FROM users
            WHERE email = %s
            """,
            (email,)
        )

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["full_name"] = user["full_name"]
            session["role"] = user["role"]

            flash("Welcome back!", "success")
            return redirect(url_for("dashboard"))

        flash("Invalid email or password.", "danger")
        return redirect(url_for("login"))

    return render_template("login.html")


# ---------------- LOGOUT ----------------

@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


# ---------------- DASHBOARD ----------------

@app.route("/dashboard")
@login_required
def dashboard():
    if session.get("role") == "admin":
        connection = get_db_connection()

        if not connection:
            flash("Database connection failed.", "danger")
            return render_template(
                "dashboard.html",
                total_students=0
            )

        cursor = None

        try:
            cursor = connection.cursor()
            cursor.execute("SELECT COUNT(*) FROM students")
            total_students = cursor.fetchone()[0]

        finally:
            if cursor:
                cursor.close()
            connection.close()

        return render_template(
            "dashboard.html",
            total_students=total_students
        )

    student = fetch_one(
        "SELECT * FROM students WHERE user_id = %s",
        (session["user_id"],)
    )

    return render_template(
        "dashboard.html",
        total_students=None,
        student=student
    )


# ---------------- VIEW STUDENTS ----------------

@app.route("/students")
@admin_required
def students():
    search = request.args.get("search", "").strip()

    connection = get_db_connection()

    if not connection:
        flash("Database connection failed.", "danger")
        return render_template(
            "students.html",
            students=[],
            search=search
        )

    cursor = None

    try:
        cursor = connection.cursor(dictionary=True)

        query = """
            SELECT id, name, email, phone, age, course, marks, created_at
            FROM students
        """

        values = ()

        if search:
            query += """
                WHERE name LIKE %s
                OR email LIKE %s
                OR course LIKE %s
            """

            keyword = f"%{search}%"
            values = (keyword, keyword, keyword)

        query += " ORDER BY id DESC"

        cursor.execute(query, values)
        student_list = cursor.fetchall()

        return render_template(
            "students.html",
            students=student_list,
            search=search
        )

    finally:
        if cursor:
            cursor.close()
        connection.close()


# ---------------- STUDENT FORM VALIDATION ----------------

def validate_student_form():
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    phone = request.form.get("phone", "").strip()
    age_text = request.form.get("age", "").strip()
    course = request.form.get("course", "").strip()
    marks_text = request.form.get("marks", "").strip()

    if not name or not email:
        return None, "Name and email are required."

    if not re.fullmatch(
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        email
    ):
        return None, "Please enter a valid email address."

    if phone and not re.fullmatch(r"[6-9][0-9]{9}", phone):
        return None, "Phone number must be a valid 10-digit number."

    age = None

    if age_text:
        try:
            age = int(age_text)

            if not 1 <= age <= 100:
                raise ValueError

        except ValueError:
            return None, "Age must be between 1 and 100."

    marks = None

    if marks_text:
        try:
            marks = float(marks_text)

            if not 0 <= marks <= 100:
                raise ValueError

        except ValueError:
            return None, "Marks must be between 0 and 100."

    return {
        "name": name,
        "email": email,
        "phone": phone or None,
        "age": age,
        "course": course or None,
        "marks": marks
    }, None


# ---------------- ADD STUDENT ----------------

@app.route("/add", methods=["GET", "POST"])
@admin_required
def add_student():
    if request.method == "POST":
        data, error_message = validate_student_form()

        if error_message:
            flash(error_message, "danger")
            return redirect(url_for("add_student"))

        connection = get_db_connection()

        if not connection:
            flash("Database connection failed.", "danger")
            return redirect(url_for("add_student"))

        cursor = None

        try:
            cursor = connection.cursor()

            cursor.execute(
                """
                INSERT INTO students
                    (name, email, phone, age, course, marks)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (
                    data["name"],
                    data["email"],
                    data["phone"],
                    data["age"],
                    data["course"],
                    data["marks"]
                )
            )

            connection.commit()
            flash("Student added successfully.", "success")
            return redirect(url_for("students"))

        except Exception as error:
            connection.rollback()
            print("Add student error:", repr(error))
            flash("Could not add student. Check the email details.", "danger")
            return redirect(url_for("add_student"))

        finally:
            if cursor:
                cursor.close()
            connection.close()

    return render_template("add_student.html")


# ---------------- EDIT STUDENT ----------------

@app.route("/edit/<int:student_id>", methods=["GET", "POST"])
@admin_required
def edit_student(student_id):
    student = fetch_one(
        "SELECT * FROM students WHERE id = %s",
        (student_id,)
    )

    if not student:
        flash("Student record not found.", "danger")
        return redirect(url_for("students"))

    if request.method == "POST":
        data, error_message = validate_student_form()

        if error_message:
            flash(error_message, "danger")
            return redirect(
                url_for("edit_student", student_id=student_id)
            )

        connection = get_db_connection()

        if not connection:
            flash("Database connection failed.", "danger")
            return redirect(
                url_for("edit_student", student_id=student_id)
            )

        cursor = None

        try:
            cursor = connection.cursor()

            cursor.execute(
                """
                UPDATE students
                SET name=%s, email=%s, phone=%s, age=%s,
                    course=%s, marks=%s
                WHERE id=%s
                """,
                (
                    data["name"],
                    data["email"],
                    data["phone"],
                    data["age"],
                    data["course"],
                    data["marks"],
                    student_id
                )
            )

            connection.commit()
            flash("Student updated successfully.", "success")
            return redirect(url_for("students"))

        except Exception as error:
            connection.rollback()
            print("Edit student error:", repr(error))
            flash("Could not update student. Check the email details.", "danger")
            return redirect(
                url_for("edit_student", student_id=student_id)
            )

        finally:
            if cursor:
                cursor.close()
            connection.close()

    return render_template("edit_student.html", student=student)


# ---------------- DELETE STUDENT ----------------

@app.route("/delete/<int:student_id>", methods=["POST"])
@admin_required
def delete_student(student_id):
    connection = get_db_connection()

    if not connection:
        flash("Database connection failed.", "danger")
        return redirect(url_for("students"))

    cursor = None

    try:
        cursor = connection.cursor()
        cursor.execute(
            "DELETE FROM students WHERE id = %s",
            (student_id,)
        )
        connection.commit()

        if cursor.rowcount:
            flash("Student deleted successfully.", "success")
        else:
            flash("Student record not found.", "warning")

    except Exception as error:
        connection.rollback()
        print("Delete student error:", repr(error))
        flash("Unable to delete student.", "danger")

    finally:
        if cursor:
            cursor.close()
        connection.close()

    return redirect(url_for("students"))


# ---------------- VIEW OWN PROFILE ----------------

@app.route("/my-profile")
@login_required
def my_profile():
    student = fetch_one(
        "SELECT * FROM students WHERE user_id = %s",
        (session["user_id"],)
    )

    return render_template(
        "student_details.html",
        student=student
    )


# ---------------- FORGOT PASSWORD ----------------

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "GET":
        return render_template("forgot_password.html")

    email = request.form.get("email", "").strip().lower()

    if not email:
        flash("Please enter your email address.", "danger")
        return redirect(url_for("forgot_password"))

    if not re.fullmatch(
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        email
    ):
        flash("Please enter a valid email address.", "danger")
        return redirect(url_for("forgot_password"))

    if not app.config["MAIL_USERNAME"] or not app.config["MAIL_PASSWORD"]:
        print("MAIL CONFIG ERROR: Check MAIL_USERNAME and MAIL_PASSWORD in .env")
        flash("Email settings are missing. Please check your .env file.", "danger")
        return redirect(url_for("forgot_password"))

    connection = get_db_connection()

    if not connection:
        flash("Database connection failed. Please try again.", "danger")
        return redirect(url_for("forgot_password"))

    cursor = None

    try:
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            "SELECT id, email FROM users WHERE email = %s",
            (email,)
        )

        user = cursor.fetchone()

        if not user:
            flash("No account was found for that email address.", "danger")
            return redirect(url_for("forgot_password"))

        otp = str(secrets.randbelow(900000) + 100000)
        otp_hash = generate_password_hash(otp)
        expires_at = datetime.now() + timedelta(minutes=5)

        cursor.execute(
            "DELETE FROM password_reset_tokens WHERE user_id = %s",
            (user["id"],)
        )

        cursor.execute(
            """
            INSERT INTO password_reset_tokens
                (user_id, otp_hash, expires_at, attempts)
            VALUES (%s, %s, %s, 0)
            """,
            (user["id"], otp_hash, expires_at)
        )

        connection.commit()

        message = Message(
            subject="StudentHub Password Reset OTP",
            sender=app.config["MAIL_USERNAME"],
            recipients=[user["email"]]
        )

        message.body = (
            f"Your StudentHub password reset OTP is: {otp}\n\n"
            "This code expires in 5 minutes."
        )

        try:
            mail.send(message)

        except Exception as mail_error:
            print("OTP EMAIL ERROR:", repr(mail_error))

            cursor.execute(
                "DELETE FROM password_reset_tokens WHERE user_id = %s",
                (user["id"],)
            )
            connection.commit()

            flash(
                "Unable to send email. Check Gmail app password and .env settings.",
                "danger"
            )
            return redirect(url_for("forgot_password"))

        # Save the email in the Flask session after the email is sent.
        session.pop("reset_email", None)
        session.pop("reset_user_id", None)
        session.pop("reset_token_id", None)

        session["reset_email"] = user["email"]
        session.modified = True

        print("OTP email sent; reset session saved.")

        flash("OTP sent to your registered email address.", "success")
        return redirect(url_for("verify_otp"))

    except Exception as error:
        connection.rollback()
        print("FORGOT PASSWORD ERROR:", repr(error))
        flash("Something went wrong. Please try again.", "danger")
        return redirect(url_for("forgot_password"))

    finally:
        if cursor:
            cursor.close()
        connection.close()


# ---------------- VERIFY OTP ----------------

@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    reset_email = session.get("reset_email")

    if not reset_email:
        flash("Please request a new OTP first.", "warning")
        return redirect(url_for("forgot_password"))

    if request.method == "GET":
        return render_template("verify_otp.html")

    otp = request.form.get("otp", "").strip()

    if not re.fullmatch(r"\d{6}", otp):
        flash("Please enter a valid 6-digit OTP.", "danger")
        return redirect(url_for("verify_otp"))

    connection = get_db_connection()

    if not connection:
        flash("Database connection failed.", "danger")
        return redirect(url_for("forgot_password"))

    cursor = None

    try:
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT prt.id, prt.otp_hash, prt.expires_at,
                   prt.attempts, u.id AS user_id
            FROM password_reset_tokens AS prt
            JOIN users AS u ON u.id = prt.user_id
            WHERE u.email = %s
            ORDER BY prt.id DESC
            LIMIT 1
            """,
            (reset_email,)
        )

        token = cursor.fetchone()

        if not token:
            session.pop("reset_email", None)
            flash("No active OTP found. Please request a new one.", "warning")
            return redirect(url_for("forgot_password"))

        if token["expires_at"] <= datetime.now():
            cursor.execute(
                "DELETE FROM password_reset_tokens WHERE id = %s",
                (token["id"],)
            )
            connection.commit()

            session.pop("reset_email", None)
            flash("OTP expired. Please request a new one.", "warning")
            return redirect(url_for("forgot_password"))

        if token["attempts"] >= 5:
            cursor.execute(
                "DELETE FROM password_reset_tokens WHERE id = %s",
                (token["id"],)
            )
            connection.commit()

            session.pop("reset_email", None)
            flash("Too many attempts. Please request a new OTP.", "danger")
            return redirect(url_for("forgot_password"))

        if not check_password_hash(token["otp_hash"], otp):
            cursor.execute(
                """
                UPDATE password_reset_tokens
                SET attempts = attempts + 1
                WHERE id = %s
                """,
                (token["id"],)
            )
            connection.commit()

            flash("Incorrect OTP. Please try again.", "danger")
            return redirect(url_for("verify_otp"))

        session["reset_user_id"] = token["user_id"]
        session["reset_token_id"] = token["id"]
        session.modified = True

        return redirect(url_for("reset_password"))

    except Exception as error:
        connection.rollback()
        print("OTP verification error:", repr(error))
        flash("OTP verification failed. Please try again.", "danger")
        return redirect(url_for("verify_otp"))

    finally:
        if cursor:
            cursor.close()
        connection.close()


# ---------------- RESET PASSWORD ----------------

@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    user_id = session.get("reset_user_id")
    token_id = session.get("reset_token_id")

    if not user_id or not token_id:
        flash("Please verify your OTP first.", "warning")
        return redirect(url_for("forgot_password"))

    if request.method == "GET":
        return render_template("reset_password.html")

    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")

    if len(password) < 8:
        flash("Password must be at least 8 characters.", "danger")
        return redirect(url_for("reset_password"))

    if password != confirm_password:
        flash("Passwords do not match.", "danger")
        return redirect(url_for("reset_password"))

    connection = get_db_connection()

    if not connection:
        flash("Database connection failed. Please try again.", "danger")
        return redirect(url_for("reset_password"))

    cursor = None

    try:
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT id, user_id, expires_at
            FROM password_reset_tokens
            WHERE id = %s AND user_id = %s
            """,
            (token_id, user_id)
        )

        token = cursor.fetchone()

        if not token or token["expires_at"] <= datetime.now():
            if token:
                cursor.execute(
                    "DELETE FROM password_reset_tokens WHERE id = %s",
                    (token_id,)
                )
                connection.commit()

            session.pop("reset_email", None)
            session.pop("reset_user_id", None)
            session.pop("reset_token_id", None)

            flash("OTP expired. Please request a new one.", "warning")
            return redirect(url_for("forgot_password"))

        cursor.execute(
            "UPDATE users SET password_hash = %s WHERE id = %s",
            (generate_password_hash(password), user_id)
        )

        cursor.execute(
            "DELETE FROM password_reset_tokens WHERE user_id = %s",
            (user_id,)
        )

        connection.commit()

        session.pop("reset_email", None)
        session.pop("reset_user_id", None)
        session.pop("reset_token_id", None)

        flash("Password updated successfully. Please sign in.", "success")
        return redirect(url_for("login"))

    except Exception as error:
        connection.rollback()
        print("Password reset error:", repr(error))
        flash("Unable to update password. Please try again.", "danger")
        return redirect(url_for("reset_password"))

    finally:
        if cursor:
            cursor.close()
        connection.close()


# ---------------- RUN APPLICATION ----------------

if __name__ == "__main__":
    app.run(debug=True)