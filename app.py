from flask import Flask, render_template, request, redirect, url_for, session, flash
import psycopg2
from dotenv import load_dotenv
import os
import bcrypt
from datetime import timedelta
import joblib  # For efficient model serialization
import numpy as np
import os

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")



app.permanent_session_lifetime = timedelta(days=1)  # Session expires after 1 day

# Database connection
def get_db_connection():
    return psycopg2.connect(
        dbname=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        host=os.getenv("DB_HOST"),
        port=os.getenv("DB_PORT")
    )

# Hash a password
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password.decode('utf-8')  # Decode to store as a string in the database

# Verify a password
def check_password(hashed_password, user_password):
    return bcrypt.checkpw(user_password.encode('utf-8'), hashed_password.encode('utf-8'))

# Before request handler
@app.before_request
def check_session():
    # Exclude login, signup, and static routes from session check
    if request.endpoint in ["login", "signup", "forgot_password", "static"]:
        return

    # Redirect to login if the user is not logged in
    if "username" not in session:
        flash("You need to log in first.", "danger")
        return redirect(url_for("login"))

# Routes
@app.route("/")
def home():
    if "username" in session:
        return redirect(url_for("dashboard"))
    else:
        return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        role = request.form["role"]
        identifier = request.form["identifier"]
        password = request.form["password"]

        conn = get_db_connection()
        cur = conn.cursor()

        if role == "student":
            cur.execute("SELECT * FROM students_users WHERE student_id = %s", (identifier,))
        elif role == "teacher":
            cur.execute("SELECT * FROM teachers_users WHERE username = %s", (identifier,))
        elif role == "admin":
            cur.execute("SELECT * FROM admin_users WHERE username = %s", (identifier,))

        user = cur.fetchone()
        cur.close()
        conn.close()

        if user and check_password(user[3], password):
            session.permanent = True
            session["username"] = identifier
            session["role"] = role
            session["first_name"] = user[1]
            session["last_name"] = user[2]
            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid credentials. Please try again.", "danger")
    return render_template("login.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        role = request.form["role"]
        identifier = request.form.get("student_id") or request.form.get("username")
        first_name = request.form.get("first_name")
        last_name = request.form.get("last_name")
        password = request.form["password"]

        conn = get_db_connection()
        cur = conn.cursor()

        # Validate uniqueness of the identifier
        if role == "student":
            cur.execute("SELECT * FROM students_users WHERE student_id = %s", (identifier,))
        elif role == "teacher":
            cur.execute("SELECT * FROM teachers_users WHERE username = %s", (identifier,))

        if cur.fetchone():
            flash("Identifier already exists. Please choose a different one.", "danger")
            return redirect(url_for("signup"))

        # Hash the password
        hashed_password = hash_password(password)

        # Insert into the appropriate table
        if role == "student":
            cur.execute(
                "INSERT INTO students_users (student_id, first_name, last_name, password, role) VALUES (%s, %s, %s, %s, %s)",
                (identifier, first_name, last_name, hashed_password, role)
            )
        elif role == "teacher":
            cur.execute(
                "INSERT INTO teachers_users (username, password, role) VALUES (%s, %s, %s)",
                (identifier, hashed_password, role)
            )

        conn.commit()
        cur.close()
        conn.close()

        flash("Signup successful! Please login.", "success")
        return redirect(url_for("login"))
    return render_template("signup.html")

@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        role = request.form["role"]
        identifier = request.form["identifier"]  # This will be student_id or username
        new_password = request.form["new_password"]

        conn = get_db_connection()
        cur = conn.cursor()

        # Query the appropriate table based on the role
        if role == "student":
            cur.execute("SELECT * FROM students_users WHERE student_id = %s", (identifier,))
        elif role == "teacher":
            cur.execute("SELECT * FROM teachers_users WHERE username = %s", (identifier,))
        elif role == "admin":
            cur.execute("SELECT * FROM admin_users WHERE username = %s", (identifier,))

        user = cur.fetchone()

        if user:
            # Hash new password
            hashed_password = hash_password(new_password)

            # Update password in the appropriate table
            if role == "student":
                cur.execute("UPDATE students_users SET password = %s WHERE student_id = %s", (hashed_password, identifier))
            elif role == "teacher":
                cur.execute("UPDATE teachers_users SET password = %s WHERE username = %s", (hashed_password, identifier))
            elif role == "admin":
                cur.execute("UPDATE admin_users SET password = %s WHERE username = %s", (hashed_password, identifier))

            conn.commit()
            cur.close()
            conn.close()
            flash("Password updated successfully! Please login with your new password.", "success")
            return redirect(url_for("login"))
        else:
            flash("Identifier not found. Please try again.", "danger")
    return render_template("forgot_password.html")

@app.route("/user_form", defaults={"subject": "english"}, methods=["GET", "POST"])
@app.route("/user_form/<subject>", methods=["GET", "POST"])
def user_form(subject):
    if "username" not in session:
        return redirect(url_for("login"))

    student_id = session.get("username")  # Assuming student_id is stored in session

    # Fetch student's first name and last name from students_users table
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT first_name, last_name FROM students_users WHERE student_id = %s", (student_id,))
    student_info = cur.fetchone()
    cur.close()
    conn.close()

    if not student_info:
        flash("Student information not found.", "danger")
        return redirect(url_for("dashboard"))

    first_name, last_name = student_info

    # Fetch subject-specific data
    conn = get_db_connection()
    cur = conn.cursor()

    # Determine the table based on the subject
    if subject == "english":
        cur.execute("SELECT * FROM english_dataset WHERE student_id = %s", (student_id,))
    elif subject == "physics":
        cur.execute("SELECT * FROM physics_dataset WHERE student_id = %s", (student_id,))
    elif subject == "mathematics":
        cur.execute("SELECT * FROM maths_dataset WHERE student_id = %s", (student_id,))
    elif subject == "computer_science":
        cur.execute("SELECT * FROM computer_science_dataset WHERE student_id = %s", (student_id,))

    student_data = cur.fetchone()
    cur.close()
    conn.close()

    if not student_data:
        flash("No data found for this student.", "danger")
        return redirect(url_for("dashboard"))

    # Pass the fetched data to the template
    return render_template("user_form.html", 
                           username=session["username"], 
                           student_id=student_id, 
                           first_name=first_name,
                           last_name=last_name,
                           age=student_data[3],  # Assuming age is at index 3
                           gender=student_data[2],  # Assuming gender is at index 2
                           subject=subject,
                           student_data=student_data)

@app.route("/predict_score/<subject>", methods=["POST"])
def predict_score(subject):
    if "username" not in session:
        return redirect(url_for("login"))

    # Load the appropriate model
    model_path = os.path.join('models', f'{subject}_updated_random_forest_model.pkl')
    if not os.path.exists(model_path):
        flash(f"Model for {subject} not found.", "danger")
        return redirect(url_for("dashboard"))

    try:
        # Use joblib to load the model (more efficient for large models)
        model = joblib.load(model_path)

        # Ensure the loaded object is a model
        if not hasattr(model, 'predict'):
            flash(f"Invalid model file for {subject}.", "danger")
            return redirect(url_for("dashboard"))

        # Get form data with default values
        g1 = float(request.form.get('g1', 0.0))
        g2 = float(request.form.get('g2', 0.0))
        g3 = float(request.form.get('g3', 0.0))
        average_grade = float(request.form.get('average_grade', 0.0))
        max_score = float(request.form.get('max_score', 0.0))
        studytime = float(request.form.get('studytime', 0.0))
        medu = float(request.form.get('medu', 0.0))
        going_out = float(request.form.get('going_out', 0.0))
        traveltime = float(request.form.get('traveltime', 0.0))
        activities = float(request.form.get('activities', 0.0))

        # Prepare the input for prediction
        input_data = [[g1, g2, g3, average_grade, max_score, studytime, medu, going_out, traveltime, activities]]

        # Make prediction
        predicted_g4 = model.predict(input_data)[0]

        # Redirect back to the test prediction page with results
        return redirect(url_for('test_prediction', 
                               subject=subject, 
                               predicted_g4=predicted_g4))

    except Exception as e:
        flash(f"Prediction failed: {str(e)}", "danger")
        return redirect(url_for('test_prediction', subject=subject))

@app.route("/test_prediction/<subject>", methods=["GET", "POST"])
def test_prediction(subject):
    if "username" not in session:
        return redirect(url_for("login"))

    student_id = session.get("username")

    # Determine the table name based on the subject
    if subject == "english":
        table_name = "english_dataset"
    elif subject == "physics":
        table_name = "physics_dataset"
    elif subject == "mathematics":
        table_name = "maths_dataset"
    elif subject == "computer_science":
        table_name = "computer_science_dataset"
    else:
        flash("Invalid subject.", "danger")
        return redirect(url_for("dashboard"))

    # Fetch subject-specific data from the database
    conn = get_db_connection()
    cur = conn.cursor()

    # Query the appropriate table
    query = f"SELECT * FROM {table_name} WHERE student_id = %s"
    cur.execute(query, (student_id,))
    student_data = cur.fetchone()
    cur.close()
    conn.close()

    if not student_data:
        flash(f"No data found for this student in {subject}.", "danger")
        return redirect(url_for("dashboard"))

    # Initialize variables with default values
    g1 = g2 = g3 = average_grade = max_score = g4 = predicted_g4 = 0
    accuracy = 95.15  # Example accuracy, replace with actual model accuracy
    ai_summary = ""

    # Fetch dynamic data from the database
    try:
        g1 = student_data[24]    # G1 (index 24)
        g2 = student_data[25]    # G2 (index 25)
        g3 = student_data[26]    # G3 (index 26)
        average_grade = student_data[28]  # Average Grade (index 28)
        max_score = student_data[29]      # Max Score (index 29)
        g4 = student_data[30]             # G4 (index 30)
    except IndexError as e:
        print(f"IndexError: {e}")
        flash(f"Data mismatch for {subject}.", "warning")
        return redirect(url_for("dashboard"))

    # Get predicted_g4 from query parameters if available
    predicted_g4 = request.args.get('predicted_g4', None)
    if predicted_g4 is not None:
        predicted_g4 = float(predicted_g4)
        # Generate AI-based summary and recommendations
        ai_summary = generate_ai_summary(predicted_g4)

    # Pass the fetched data to the template
    return render_template("test_prediction.html", 
                         subject=subject,
                         g1=g1,
                         g2=g2,
                         g3=g3,
                         average_grade=average_grade,
                         max_score=max_score,
                         g4=g4,
                         predicted_g4=predicted_g4,
                         accuracy=accuracy,
                         ai_summary=ai_summary,
                         student_data=student_data)

@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))

    first_name = session.get("first_name", "")
    last_name = session.get("last_name", "")
    role = session.get("role", "")

    return render_template("dashboard.html", first_name=first_name, last_name=last_name, role=role)

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)