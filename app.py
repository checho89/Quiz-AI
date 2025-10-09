import os
import json
import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash
from dotenv import load_dotenv
from pymongo import MongoClient, ASCENDING
from werkzeug.security import generate_password_hash, check_password_hash
from openai_client import get_client
from openai import OpenAI
from quiz_schema import Quiz
from utils import grade, badge_svg_datauri

# -----------------------------
# Load environment and Flask app
# -----------------------------
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-key")



# -----------------------------
# MongoDB Configuration
# -----------------------------
MONGO_URI = os.getenv(
    "MONGO_URI",
   "mongodb+srv://user1:Welcome1@database1.hjgtcut.mongodb.net/?retryWrites=true&w=majority&ssl=true&tlsAllowInvalidCertificates=true"

)

try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=10000)
    db = client["DataBase1"]
    client.server_info()  # Force connection test
    print("✅ MongoDB connection successful")
except Exception as e:
    print(f"❌ MongoDB connection failed: {e}")
    db = None

if db:
    users_collection = db["users"]
    attempts_collection = db["attempts"]

    # Create indexes for faster lookups
    users_collection.create_index([("username", ASCENDING)], unique=True)
    attempts_collection.create_index([("user_id", ASCENDING), ("timestamp", ASCENDING)])
else:
    users_collection = None
    attempts_collection = None

# -----------------------------
# Constants
# -----------------------------


TOPICS = [
    "AWS", "Azure", "GCP", "Kubernetes", "Docker", "Linux", "Python", "Git",
    "DevOps", "ITIL", "PMP", "Scrum", "CompTIA A+", "CompTIA Network+",
    "CompTIA Security+"
]
TYPES = ["multiple_choice", "true_false", "short_answer"]
DIFFICULTIES = ["beginner", "intermediate", "advanced"]

# -----------------------------
# Helper: Build JSON Schema for quiz
# -----------------------------
def build_json_schema(count: int, allowed_types):
    return {
        "name": "quiz_schema",
        "schema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "topic": {"type": "string"},
                "difficulty": {"type": "string", "enum": DIFFICULTIES},
                "questions": {
                    "type": "array",
                    "minItems": count,
                    "maxItems": count,
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {
                            "id": {"type": "string"},
                            "type": {"type": "string", "enum": allowed_types},
                            "prompt": {"type": "string"},
                            "choices": {"type": "array", "items": {"type": "string"}},
                            "answer": {"anyOf": [{"type": "string"}, {"type": "boolean"}]},
                            "explanation": {"type": "string"},
                        },
                        "required": ["id", "type", "prompt", "answer"],
                    },
                },
            },
            "required": ["topic", "difficulty", "questions"],
        },
    }

# -----------------------------
# User-related functions
# -----------------------------
def create_user(username, password):
    """Register a new user if username doesn't exist."""
    if users_collection.find_one({"username": username}):
        return False, "Username already exists."

    if len(password) < 4:
        return False, "Password must be at least 4 characters long."

    hashed_pw = generate_password_hash(password)
    users_collection.insert_one({
        "username": username,
        "password": hashed_pw,
        "created_at": datetime.datetime.utcnow()
    })
    return True, "Registration successful. Please login."

def authenticate_user(username, password):
    """Validate login credentials."""
    user = users_collection.find_one({"username": username})
    if user and check_password_hash(user["password"], password):
        return str(user["_id"])
    return None

def save_attempt(user_id, quiz, results):
    """Store quiz attempt."""
    record = {
        "user_id": user_id,
        "topic": quiz["topic"],
        "difficulty": quiz["difficulty"],
        "score_pct": results["pct"],
        "passed": results["passed"],
        "timestamp": datetime.datetime.utcnow(),
    }
    attempts_collection.insert_one(record)

# -----------------------------
# Routes
# -----------------------------

@app.route("/")
def home():
    """Redirect to login or index depending on session."""
    if "user_id" in session:
        return redirect(url_for("index"))
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        print(username, password)
        success, msg = create_user(username, password)
        flash(msg)
        if success:
            return redirect(url_for("login"))
        return redirect(url_for("register"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user_id = authenticate_user(username, password)
        if user_id:
            session["user_id"] = user_id
            session["username"] = username
            flash("Logged in successfully.")
            return redirect(url_for("index"))
        else:
            flash("Invalid username or password.")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.")
    return redirect(url_for("login"))

@app.get("/index")
def index():
    """Main quiz page — protected."""
    if "user_id" not in session:
        flash("Please log in to access the quizzes.")
        return redirect(url_for("login"))
    return render_template("index.html", topics=TOPICS, types=TYPES, difficulties=DIFFICULTIES)

@app.post("/generate")
def generate():
    """Generate a quiz tied to the current user session."""
    if "user_id" not in session:
        flash("You must be logged in to generate a quiz.")
        return redirect(url_for("login"))

    username = session.get("username")
    topic = request.form.get("topic", "").strip()
    difficulty = request.form.get("difficulty", "beginner")

    try:
        count = max(1, min(60, int(request.form.get("count", "10"))))
    except ValueError:
        count = 10

    omit = request.form.getlist("omit")
    allowed_types = [t for t in TYPES if t not in omit]
    if not allowed_types:
        flash("Please allow at least one question type.")
        return redirect(url_for("index"))

    system = (
        f"You are generating a certification-style quiz for {username}. "
        "The quiz should fit the chosen topic and difficulty. "
        "Topics include AWS, Azure, GCP, Kubernetes, Docker, Linux, etc. "
        "Only use the allowed question types."
    )

    user_prompt = (
        f"Create a quiz about: {topic}. "
        f"Difficulty: {difficulty}. "
        f"Number of questions: {count}. "
        f"Allowed types: {', '.join(allowed_types)}."
    )

    schema = build_json_schema(count, allowed_types)
    client = get_client()

    completion = client.chat.completions.create(
        model="gpt-4o-mini",
        response_format={"type": "json_schema", "json_schema": schema},
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user_prompt},
        ],
        temperature=0.7,
    )

    content = completion.choices[0].message.content if completion.choices else None
    if not content:
        flash("Model returned no content.")
        return redirect(url_for("index"))

    try:
        data = json.loads(content)
        quiz = Quiz.model_validate(data).model_dump()
    except Exception as e:
        flash(f"Model output invalid: {e}")
        return redirect(url_for("index"))

    # Save quiz and user info in session
    session["quiz"] = quiz
    session["generated_by"] = username
    session.modified = True

    flash(f"Quiz generated for {username}.")
    return redirect(url_for("quiz"))


@app.get("/quiz")
def quiz():
    """Display quiz page."""
    if "user_id" not in session:
        flash("Please log in to take a quiz.")
        return redirect(url_for("login"))

    quiz = session.get("quiz")
    if not quiz:
        return redirect(url_for("index"))
    return render_template("quiz.html", quiz=quiz)

@app.post("/submit")
def submit():
    """Submit quiz answers."""
    if "user_id" not in session:
        return redirect(url_for("login"))

    quiz = session.get("quiz")
    if not quiz:
        return redirect(url_for("index"))

    answers = {q["id"]: request.form.get(q["id"], "") for q in quiz["questions"]}
    results = grade(quiz, answers)
    badge = badge_svg_datauri(results["pct"], results["passed"])

    save_attempt(session["user_id"], quiz, results)

    hist = session.get("history", [])
    hist.insert(0, {
        "topic": quiz["topic"],
        "difficulty": quiz["difficulty"],
        "pct": round(results["pct"], 1),
    })
    session["history"] = hist[:20]

    return render_template("result.html", quiz=quiz, results=results, badge=badge)

# -----------------------------
# Run the app
# -----------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port)

