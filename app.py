"""School Schedule Tracker: subjects, subject codes, and a weekly timetable.

Run:  pip install flask
      python app.py
Open: http://127.0.0.1:5000
"""
import sqlite3
from datetime import datetime
from flask import Flask, flash, g, redirect, render_template_string, request, url_for

app = Flask(__name__)
app.secret_key = "change-me"
DB = "school.db"
DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]


# ---------- database ----------
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_):
    conn = g.pop("db", None)
    if conn:
        conn.close()


def init_db():
    with sqlite3.connect(DB) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS subjects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                teacher TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS slots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subject_id INTEGER NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
                day INTEGER NOT NULL,          -- 0 = Monday ... 6 = Sunday
                start TEXT NOT NULL,           -- "HH:MM"
                end TEXT NOT NULL,
                room TEXT DEFAULT ''
            );
            """
        )


def minutes(t):
    h, m = t.split(":")
    return int(h) * 60 + int(m)


def fmt_time(t):
    return datetime.strptime(t, "%H:%M").strftime("%I:%M %p").lstrip("0")


app.jinja_env.filters["time12"] = fmt_time


# ---------- routes ----------
@app.route("/")
def index():
    subjects = db().execute("SELECT * FROM subjects ORDER BY code").fetchall()
    slots = db().execute(
        """SELECT s.*, sub.code, sub.name FROM slots s
           JOIN subjects sub ON sub.id = s.subject_id
           ORDER BY s.day, s.start"""
    ).fetchall()

    week = {i: [] for i in range(7)}
    hours = {sub["id"]: 0 for sub in subjects}
    for s in slots:
        week[s["day"]].append(s)
        hours[s["subject_id"]] += minutes(s["end"]) - minutes(s["start"])

    totals = {k: f"{v // 60}h {v % 60:02d}m" for k, v in hours.items()}
    week_total = sum(hours.values())
    return render_template_string(
        PAGE,
        subjects=subjects,
        week=week,
        days=DAYS,
        totals=totals,
        week_total=f"{week_total // 60}h {week_total % 60:02d}m",
        today=datetime.now().weekday(),
    )


@app.post("/subjects")
def add_subject():
    code = request.form["code"].strip().upper()
    name = request.form["name"].strip()
    teacher = request.form.get("teacher", "").strip()
    if not code or not name:
        flash("Enter both a subject code and a subject name.")
    else:
        try:
            db().execute(
                "INSERT INTO subjects (code, name, teacher) VALUES (?, ?, ?)",
                (code, name, teacher),
            )
            db().commit()
            flash(f"Added {code}.")
        except sqlite3.IntegrityError:
            flash(f"Subject code {code} already exists. Use a different code.")
    return redirect(url_for("index"))


@app.post("/subjects/<int:sid>/delete")
def delete_subject(sid):
    db().execute("DELETE FROM subjects WHERE id = ?", (sid,))
    db().commit()
    flash("Subject and its class times were deleted.")
    return redirect(url_for("index"))


@app.post("/slots")
def add_slot():
    try:
        sid = int(request.form["subject_id"])
        day = int(request.form["day"])
        start, end = request.form["start"], request.form["end"]
        room = request.form.get("room", "").strip()
        if minutes(end) <= minutes(start):
            flash("End time must be after start time.")
            return redirect(url_for("index"))
    except (KeyError, ValueError):
        flash("Fill in every field to add a class time.")
        return redirect(url_for("index"))

    clash = db().execute(
        """SELECT sub.code, s.start, s.end FROM slots s
           JOIN subjects sub ON sub.id = s.subject_id
           WHERE s.day = ? AND ? < s.end AND ? > s.start""",
        (day, start, end),
    ).fetchone()
    if clash:
        flash(
            f"Clashes with {clash['code']} on {DAYS[day]} "
            f"({fmt_time(clash['start'])} to {fmt_time(clash['end'])})."
        )
    else:
        db().execute(
            "INSERT INTO slots (subject_id, day, start, end, room) VALUES (?,?,?,?,?)",
            (sid, day, start, end, room),
        )
        db().commit()
        flash("Class time added.")
    return redirect(url_for("index"))


@app.post("/slots/<int:slot_id>/delete")
def delete_slot(slot_id):
    db().execute("DELETE FROM slots WHERE id = ?", (slot_id,))
    db().commit()
    return redirect(url_for("index"))


# ---------- template ----------
PAGE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>School Schedule Tracker</title>
<style>
  :root {
    --paper: #f2f5f1; --ink: #1c2f3d; --muted: #5d6f7b; --line: #cfd8d2;
    --card: #ffffff; --accent: #2a6f6b; --chalk: #f1c84b; --danger: #a8402f;
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--paper); color: var(--ink);
         font: 16px/1.5 "Segoe UI", system-ui, -apple-system, sans-serif; }
  main { max-width: 1180px; margin: 0 auto; padding: 28px 20px 60px; }
  h1 { font-size: 1.9rem; margin: 0 0 4px; letter-spacing: -0.01em; }
  h2 { font-size: 1.15rem; margin: 0 0 12px; }
  .sub { color: var(--muted); margin: 0 0 24px; }
  .flash { background: var(--chalk); padding: 10px 14px; border-radius: 6px; margin-bottom: 8px; }
  .forms { display: grid; grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); gap: 16px; margin-bottom: 28px; }
  .panel { background: var(--card); border: 1px solid var(--line); border-radius: 8px; padding: 18px; }
  label { display: block; font-size: .85rem; color: var(--muted); margin-bottom: 10px; }
  input, select { width: 100%; padding: 8px 10px; margin-top: 3px; font: inherit;
                  border: 1px solid var(--line); border-radius: 6px; background: #fff; color: var(--ink); }
  .row { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
  button { font: inherit; cursor: pointer; border: 0; border-radius: 6px; padding: 9px 16px;
           background: var(--accent); color: #fff; }
  button:hover { background: #22595a; }
  button.link { background: none; color: var(--danger); padding: 2px 6px; font-size: .85rem; }
  button.link:hover { background: none; text-decoration: underline; }
  :focus-visible { outline: 3px solid var(--chalk); outline-offset: 2px; }

  .week { display: grid; grid-template-columns: repeat(7, minmax(150px, 1fr)); gap: 10px;
          overflow-x: auto; margin-bottom: 28px; padding-bottom: 6px; }
  .day { background: var(--card); border: 1px solid var(--line); border-radius: 8px; min-height: 170px; }
  .day h3 { margin: 0; padding: 10px 12px; font-size: .95rem; border-bottom: 1px solid var(--line); }
  .day.today h3 { background: var(--chalk); border-radius: 7px 7px 0 0; }
  .slot { padding: 9px 12px; border-bottom: 1px solid var(--line); border-left: 4px solid var(--accent); }
  .slot:last-child { border-bottom: 0; }
  .slot b { display: block; }
  .slot small { color: var(--muted); display: block; }
  .empty { color: var(--muted); padding: 12px; font-size: .9rem; }

  table { width: 100%; border-collapse: collapse; background: var(--card);
          border: 1px solid var(--line); border-radius: 8px; overflow: hidden; }
  th, td { text-align: left; padding: 10px 14px; border-bottom: 1px solid var(--line); }
  th { background: #e6ece8; font-size: .9rem; }
  tfoot td { font-weight: 600; border-bottom: 0; }
  form.inline { display: inline; }
</style>
</head>
<body>
<main>
  <h1>School Schedule Tracker</h1>
  <p class="sub">Your subjects, their codes, and when each one meets during the week.</p>

  {% for m in get_flashed_messages() %}<div class="flash" role="status">{{ m }}</div>{% endfor %}

  <section class="forms">
    <form class="panel" method="post" action="{{ url_for('add_subject') }}">
      <h2>Add a subject</h2>
      <div class="row">
        <label>Subject code<input name="code" placeholder="MATH101" required></label>
        <label>Teacher (optional)<input name="teacher" placeholder="Ms. Reyes"></label>
      </div>
      <label>Subject name<input name="name" placeholder="College Algebra" required></label>
      <button>Add subject</button>
    </form>

    <form class="panel" method="post" action="{{ url_for('add_slot') }}">
      <h2>Add a class time</h2>
      {% if subjects %}
      <label>Subject
        <select name="subject_id" required>
          {% for s in subjects %}<option value="{{ s.id }}">{{ s.code }}: {{ s.name }}</option>{% endfor %}
        </select>
      </label>
      <div class="row">
        <label>Day
          <select name="day">
            {% for d in days %}<option value="{{ loop.index0 }}" {{ 'selected' if loop.index0 == today }}>{{ d }}</option>{% endfor %}
          </select>
        </label>
        <label>Room (optional)<input name="room" placeholder="Room 204"></label>
      </div>
      <div class="row">
        <label>Starts<input type="time" name="start" value="08:00" required></label>
        <label>Ends<input type="time" name="end" value="09:00" required></label>
      </div>
      <button>Add class time</button>
      {% else %}
      <p class="empty">Add a subject first, then schedule its class times here.</p>
      {% endif %}
    </form>
  </section>

  <h2>This week</h2>
  <section class="week">
    {% for d in days %}
    <div class="day {{ 'today' if loop.index0 == today }}">
      <h3>{{ d }}</h3>
      {% for s in week[loop.index0] %}
      <div class="slot">
        <b>{{ s.code }}</b>
        <small>{{ s.name }}</small>
        <small>{{ s.start|time12 }} to {{ s.end|time12 }}{% if s.room %} in {{ s.room }}{% endif %}</small>
        <form class="inline" method="post" action="{{ url_for('delete_slot', slot_id=s.id) }}">
          <button class="link" aria-label="Remove {{ s.code }} on {{ d }}">Remove</button>
        </form>
      </div>
      {% else %}
      <div class="empty">No classes</div>
      {% endfor %}
    </div>
    {% endfor %}
  </section>

  <h2>Subjects and weekly time</h2>
  {% if subjects %}
  <table>
    <thead><tr><th>Code</th><th>Subject</th><th>Teacher</th><th>Time per week</th><th></th></tr></thead>
    <tbody>
      {% for s in subjects %}
      <tr>
        <td><b>{{ s.code }}</b></td><td>{{ s.name }}</td><td>{{ s.teacher or '-' }}</td>
        <td>{{ totals[s.id] }}</td>
        <td>
          <form class="inline" method="post" action="{{ url_for('delete_subject', sid=s.id) }}"
                onsubmit="return confirm('Delete {{ s.code }} and all its class times?')">
            <button class="link">Delete</button>
          </form>
        </td>
      </tr>
      {% endfor %}
    </tbody>
    <tfoot><tr><td colspan="3">Total class time</td><td colspan="2">{{ week_total }}</td></tr></tfoot>
  </table>
  {% else %}
  <p class="empty">No subjects yet. Add your first one above.</p>
  {% endif %}
</main>
</body>
</html>
"""

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
