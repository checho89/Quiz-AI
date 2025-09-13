import os, json
from flask import Flask, render_template, request, redirect, url_for, session, flash
from dotenv import load_dotenv
from openai_client import get_client
from quiz_schema import Quiz
from utils import grade, badge_svg_datauri

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-key")
PORT = int(os.getenv("PORT", "5000"))

TOPICS = [
    "AWS", "Azure", "GCP", "Kubernetes", "Docker", "Linux", "Python", "Git", "DevOps",
    "ITIL", "PMP", "Scrum", "CompTIA A+", "CompTIA Network+", "CompTIA Security+"
]
TYPES = ["multiple_choice", "true_false", "short_answer"]
DIFFICULTIES = ["beginner", "intermediate", "advanced"]

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
                            "answer": {"anyOf": [{"type":"string"}, {"type":"boolean"}]},
                            "explanation": {"type": "string"}
                        },
                        "required": ["id", "type", "prompt", "answer"]
                    }
                }
            },
            "required": ["topic", "difficulty", "questions"]
        }
    }

@app.get("/")
def index():
    return render_template("index.html", topics=TOPICS, types=TYPES, difficulties=DIFFICULTIES)

@app.post("/generate")
def generate():
    topic = request.form.get("topic", "").strip()
    difficulty = request.form.get("difficulty", "beginner")
    try:
        count = max(1, min(60, int(request.form.get("count", "10"))))
    except ValueError:
        count = 10

    omit = request.form.getlist("omit")  # list of types to omit
    allowed_types = [t for t in TYPES if t not in omit]
    if not allowed_types:
        flash("Please allow at least one question type.")
        return redirect(url_for("index"))

    # Build prompts
    system = (
        "You generate certification-style quizzes for technology & productivity certifications "
        "(AWS, Azure, GCP, Kubernetes, Docker, Linux, Python, Git, Scrum, ITIL, PMP, CompTIA, etc.). "
        "Only use the allowed question types. "
        "For multiple_choice: include 3–5 plausible choices and one correct answer that exactly matches one choice. "
        "For true_false: answer must be a boolean. "
        "For short_answer: answer is concise (1–2 sentences or a key term). "
        "Provide brief explanations when helpful."
    )
    user = f"Create a quiz about: {topic}. Difficulty: {difficulty}. Number of questions: {count}. Allowed types: {', '.join(allowed_types)}."

    schema = build_json_schema(count, allowed_types)

    client = get_client()
    completion = client.chat.completions.create(
        model="gpt-4o-mini",
        response_format={"type": "json_schema", "json_schema": schema},
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user}
        ],
        temperature=0.7
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

    session["quiz"] = quiz
    return redirect(url_for("quiz"))

@app.get("/quiz")
def quiz():
    quiz = session.get("quiz")
    if not quiz:
        return redirect(url_for("index"))
    return render_template("quiz.html", quiz=quiz)

@app.post("/submit")
def submit():
    quiz = session.get("quiz")
    if not quiz:
        return redirect(url_for("index"))

    answers = {}
    for q in quiz["questions"]:
        answers[q["id"]] = request.form.get(q["id"], "")

    results = grade(quiz, answers)
    badge = badge_svg_datauri(results["pct"], results["passed"])

    # Save attempt history in session (last 20)
    hist = session.get("history", [])
    hist.insert(0, {"topic": quiz["topic"], "difficulty": quiz["difficulty"], "pct": round(results["pct"], 1)})
    session["history"] = hist[:20]

    return render_template("result.html", quiz=quiz, results=results, badge=badge)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=True)
