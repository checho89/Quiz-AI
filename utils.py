import math
from typing import Dict, Any

def normalize_true_false(v):
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    if s in ("true", "t", "1", "yes", "y"):
        return True
    if s in ("false", "f", "0", "no", "n"):
        return False
    return None

def grade(quiz: Dict[str, Any], answers: Dict[str, str]):
    correct = 0
    details = []
    for q in quiz["questions"]:
        qid = q["id"]
        qtype = q["type"]
        gold = q["answer"]
        user_raw = answers.get(qid, "")

        if qtype == "true_false":
            gold_norm = bool(gold)
            user_norm = normalize_true_false(user_raw)
            ok = (user_norm is not None) and (user_norm == gold_norm)
        elif qtype == "short_answer":
            a = str(user_raw).strip().lower()
            b = str(gold).strip().lower()
            ok = bool(a) and (a == b or a in b or b in a)
        else:  # multiple_choice
            ok = str(user_raw) == str(gold)

        correct += int(ok)
        details.append({
            "id": qid,
            "prompt": q["prompt"],
            "user": user_raw,
            "gold": gold,
            "ok": ok,
            "explanation": q.get("explanation", "")
        })

    total = len(quiz["questions"])
    pct = (correct / total) * 100 if total else 0
    return {"correct": correct, "total": total, "pct": pct, "passed": pct >= 70, "details": details}

def badge_svg_datauri(score_pct: float, passed: bool) -> str:
    pct = int(round(score_pct))
    ring = "#6dd6ff" if passed else "#b26dff"
    circ = math.pi * 2 * 130
    dashoffset = (1 - pct/100) * circ
    title = "PASSED" if passed else "TRY AGAIN"
    svg = f"""
<svg xmlns='http://www.w3.org/2000/svg' width='320' height='320' viewBox='0 0 320 320'>
  <defs>
    <linearGradient id='g' x1='0' x2='1'>
      <stop offset='0%' stop-color='{ring}'/>
      <stop offset='100%' stop-color='#ffffff'/>
    </linearGradient>
  </defs>
  <rect width='100%' height='100%' fill='#0b1220'/>
  <circle cx='160' cy='160' r='130' fill='none' stroke='#1e2a49' stroke-width='16'/>
  <circle cx='160' cy='160' r='130' fill='none' stroke='url(#g)' stroke-width='18' stroke-linecap='round'
    stroke-dasharray='{circ}' stroke-dashoffset='{dashoffset}' />
  <text x='160' y='150' fill='#e6eefc' font-size='72' font-family='Inter, Arial' text-anchor='middle' font-weight='700'>{pct}%</text>
  <text x='160' y='195' fill='#9fb3d1' font-size='18' font-family='Inter, Arial' text-anchor='middle'>Score</text>
  <rect x='90' y='215' rx='14' ry='14' width='140' height='36' fill='#151f38' stroke='#263357'/>
  <text x='160' y='240' fill='#e6eefc' font-size='16' font-family='Inter, Arial' text-anchor='middle' font-weight='700'>{title}</text>
</svg>
""".strip()
    import urllib.parse
    return "data:image/svg+xml;utf8," + urllib.parse.quote(svg)
