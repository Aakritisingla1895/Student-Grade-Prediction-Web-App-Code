from flask import Flask, render_template, request, redirect, url_for, session, flash
import psycopg2
from dotenv import load_dotenv
import os
import bcrypt

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

# Database connection
def get_db_connection():
    return psycopg2.connect(
        dbname=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        host=os.getenv("DB_HOST"),
        port=os.getenv("DB_PORT")
    )

# Hash password
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

# Check password
def check_password(hashed_password, user_password):
    return bcrypt.checkpw(user_password.encode('utf-8'), hashed_password.encode('utf-8'))

# Routes
@app.route("/")
def home():
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        role = request.form["role"]

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM students_users WHERE username = %s AND role = %s", (username, role))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if user and check_password(user[2], password):  # user[2] is the hashed password
            session["username"] = username
            session["role"] = role
            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid credentials. Please try again.", "danger")
    return render_template("login.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        role = request.form["role"]

        # Validate username uniqueness
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM students_users WHERE username = %s", (username,))
        if cur.fetchone():
            flash("Username already exists. Please choose a different username.", "danger")
            return redirect(url_for("signup"))

        # Hash password
        hashed_password = hash_password(password)

        # Insert new user
        cur.execute("INSERT INTO students_users (username, password, role) VALUES (%s, %s, %s)", (username, hashed_password.decode('utf-8'), role))
        conn.commit()
        cur.close()
        conn.close()

        flash("Signup successful! Please login.", "success")
        return redirect(url_for("login"))
    return render_template("signup.html")

@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        username = request.form["username"]
        new_password = request.form["new_password"]

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM students_users WHERE username = %s", (username,))
        user = cur.fetchone()

        if user:
            # Hash new password
            hashed_password = hash_password(new_password)
            cur.execute("UPDATE students_users SET password = %s WHERE username = %s", (hashed_password.decode('utf-8'), username))
            conn.commit()
            cur.close()
            conn.close()
            flash("Password updated successfully! Please login with your new password.", "success")
            return redirect(url_for("login"))
        else:
            flash("Username not found. Please try again.", "danger")
    return render_template("forgot_password.html")

@app.route("/user_form", methods=["GET", "POST"])
def user_form():
    if "username" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        answers = [request.form[f"q{i}"] for i in range(1, 6)]
        # Save answers to the database or process them for prediction
        flash("Form submitted successfully!", "success")
        return redirect(url_for("dashboard"))
    return render_template("user_form.html", username=session["username"])

@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", username=session["username"])

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)