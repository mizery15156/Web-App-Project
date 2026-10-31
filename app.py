"""School Schedule Tracker (online version).

Local:  pip install -r requirements.txt && python app.py
Online: set DATABASE_URL (PostgreSQL) and SECRET_KEY, run: gunicorn app:app
"""
import json
import os
import re
import smtplib
import urllib.request
from datetime import datetime
from email.message import EmailMessage
from functools import wraps
from secrets import token_hex

from flask import Flask, abort, flash, redirect, render_template, request, session, url_for
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import BadSignature, URLSafeTimedSerializer
from jinja2 import DictLoader
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-me")
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)  # correct https links behind a host proxy
tokens = URLSafeTimedSerializer(app.secret_key, salt="verify-email")

db_url = os.environ.get("DATABASE_URL", "sqlite:///schedule.db")
if db_url.startswith("postgres://"):  # some hosts still use the old prefix
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}
db = SQLAlchemy(app)

DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]


# ---------- models ----------
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    verified = db.Column(db.Boolean, nullable=False, default=False)


class Subject(db.Model):
    __tablename__ = "subjects"
    __table_args__ = (db.UniqueConstraint("user_id", "code"),)
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    code = db.Column(db.String(20), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    teacher = db.Column(db.String(120), default="")
    slots = db.relationship("Slot", backref="subject", cascade="all, delete-orphan")


class Slot(db.Model):
    __tablename__ = "slots"
    id = db.Column(db.Integer, primary_key=True)
    subject_id = db.Column(db.Integer, db.ForeignKey("subjects.id"), nullable=False)
    day = db.Column(db.Integer, nullable=False)  # 0 = Monday ... 6 = Sunday
    start = db.Column(db.String(5), nullable=False)  # "HH:MM"
    end = db.Column(db.String(5), nullable=False)
    room = db.Column(db.String(60), default="")


with app.app_context():
    # One-time upgrade: the old username-based tables cannot be altered in place, so they are
    # rebuilt once (this removes test data from the earlier version).
    insp = inspect(db.engine)
    if insp.has_table("users") and "email" not in [c["name"] for c in insp.get_columns("users")]:
        db.drop_all()
    db.create_all()


# ---------- helpers ----------
def minutes(t):
    h, m = t.split(":")
    return int(h) * 60 + int(m)


def time12(t):
    return datetime.strptime(t, "%H:%M").strftime("%I:%M %p").lstrip("0")


def login_required(view):
    @wraps(view)
    def wrapper(*a, **kw):
        if "uid" not in session:
            return redirect(url_for("login"))
        return view(*a, **kw)
    return wrapper


def own_subject(sid):
    s = db.session.get(Subject, sid)
    if not s or s.user_id != session["uid"]:
        abort(404)
    return s


def own_slot(slot_id):
    sl = db.session.get(Slot, slot_id)
    if not sl or sl.subject.user_id != session["uid"]:
        abort(404)
    return sl


@app.before_request
def csrf_protect():
    if request.method == "POST":
        if not session.get("csrf") or request.form.get("csrf") != session["csrf"]:
            abort(400)


@app.context_processor
def inject():
    session.setdefault("csrf", token_hex(16))
    return {"csrf": session["csrf"], "days": DAYS, "username": session.get("email"), "time12": time12}


# ---------- email ----------
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def send_email(to, subject, body):
    """Send via Brevo's web API (BREVO_API_KEY) or plain SMTP (SMTP_* settings)."""
    sender = os.environ.get("MAIL_FROM", "")
    try:
        if os.environ.get("BREVO_API_KEY"):
            data = json.dumps({"sender": {"email": sender}, "to": [{"email": to}],
                               "subject": subject, "textContent": body}).encode()
            req = urllib.request.Request(
                "https://api.brevo.com/v3/smtp/email", data=data, method="POST",
                headers={"api-key": os.environ["BREVO_API_KEY"],
                         "content-type": "application/json", "accept": "application/json"})
            urllib.request.urlopen(req, timeout=15).close()
        elif os.environ.get("SMTP_HOST"):
            msg = EmailMessage()
            msg["From"], msg["To"], msg["Subject"] = sender, to, subject
            msg.set_content(body)
            with smtplib.SMTP(os.environ["SMTP_HOST"], int(os.environ.get("SMTP_PORT", 587)), timeout=15) as s:
                s.starttls()
                s.login(os.environ["SMTP_USER"], os.environ["SMTP_PASSWORD"])
                s.send_message(msg)
        else:  # email not configured: print it so you can test locally
            print(f"\n--- EMAIL to {to} ---\n{subject}\n{body}\n")
            return app.debug
        return True
    except Exception:
        app.logger.exception("Could not send email")
        return False


def send_verification(user):
    link = url_for("verify", token=tokens.dumps(user.email), _external=True)
    return send_email(
        user.email, "Confirm your email for School Schedule Tracker",
        f"Hi,\n\nConfirm your email to activate your account:\n{link}\n\n"
        "This link works for 24 hours. If you didn't sign up, you can ignore this email.\n",
    )


# ---------- auth ----------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        pw = request.form["password"]
        if not EMAIL_RE.match(email) or len(email) > 255:
            flash("Enter a valid email address.")
        elif len(pw) < 8:
            flash("Password needs at least 8 characters.")
        else:
            user = User.query.filter_by(email=email).first()
            if user and user.verified:
                flash("That email already has an account. Log in instead.")
            else:
                try:
                    if not user:
                        user = User(email=email)
                        db.session.add(user)
                    user.password_hash = generate_password_hash(pw)
                    db.session.commit()
                except IntegrityError:
                    db.session.rollback()
                    flash("Something went wrong. Try again.")
                    return render_template("auth.html", mode="register")
                if send_verification(user):
                    flash(f"We sent a confirmation link to {email}. Open it to activate your account.")
                else:
                    flash("Account created, but the confirmation email could not be sent. Use Resend below in a few minutes.")
                return redirect(url_for("login"))
    return render_template("auth.html", mode="register")


@app.route("/verify/<token>")
def verify(token):
    try:
        email = tokens.loads(token, max_age=86400)
    except BadSignature:
        flash("That link is invalid or has expired. Enter your email below to get a new one.")
        return redirect(url_for("login"))
    user = User.query.filter_by(email=email).first()
    if user:
        user.verified = True
        db.session.commit()
        flash("Email confirmed. You can log in now.")
    return redirect(url_for("login"))


@app.post("/resend")
def resend():
    user = User.query.filter_by(email=request.form["email"].strip().lower()).first()
    if user and not user.verified:
        send_verification(user)
    flash("If that email has an unconfirmed account, we sent a new link.")
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(email=request.form["email"].strip().lower()).first()
        if not (user and check_password_hash(user.password_hash, request.form["password"])):
            flash("Wrong email or password.")
        elif not user.verified:
            flash("Confirm your email first. Check your inbox for the link, or resend it below.")
        else:
            session.clear()
            session["uid"], session["email"] = user.id, user.email
            return redirect(url_for("index"))
    return render_template("auth.html", mode="login")


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------- schedule ----------
@app.route("/")
@login_required
def index():
    subjects = Subject.query.filter_by(user_id=session["uid"]).order_by(Subject.code).all()
    slots = (Slot.query.join(Subject).filter(Subject.user_id == session["uid"])
             .order_by(Slot.day, Slot.start).all())
    week = {i: [] for i in range(7)}
    mins = {s.id: 0 for s in subjects}
    for sl in slots:
        week[sl.day].append(sl)
        mins[sl.subject_id] += minutes(sl.end) - minutes(sl.start)
    fmt = lambda m: f"{m // 60}h {m % 60:02d}m"
    return render_template(
        "index.html", subjects=subjects, week=week, today=datetime.now().weekday(),
        totals={k: fmt(v) for k, v in mins.items()}, week_total=fmt(sum(mins.values())),
    )


def save_subject(s, form):
    s.code = form["code"].strip().upper()
    s.name = form["name"].strip()
    s.teacher = form.get("teacher", "").strip()
    if not s.code or not s.name:
        return "Enter both a subject code and a subject name."
    try:
        s.user_id = session["uid"]
        db.session.add(s)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return f"You already have a subject with code {s.code}."


@app.post("/subjects")
@login_required
def add_subject():
    err = save_subject(Subject(), request.form)
    flash(err or "Subject added.")
    return redirect(url_for("index"))


@app.route("/subjects/<int:sid>/edit", methods=["GET", "POST"])
@login_required
def edit_subject(sid):
    s = own_subject(sid)
    if request.method == "POST":
        err = save_subject(s, request.form)
        if not err:
            flash("Subject updated.")
            return redirect(url_for("index"))
        flash(err)
        db.session.rollback()
    return render_template("edit_subject.html", s=s)


@app.post("/subjects/<int:sid>/delete")
@login_required
def delete_subject(sid):
    db.session.delete(own_subject(sid))
    db.session.commit()
    flash("Subject and its class times deleted.")
    return redirect(url_for("index"))


def save_slot(slot, form):
    try:
        subject = own_subject(int(form["subject_id"]))
        day, start, end = int(form["day"]), form["start"], form["end"]
        if minutes(end) <= minutes(start):
            return "End time must be after start time."
    except (KeyError, ValueError):
        return "Fill in every field."
    q = Slot.query.join(Subject).filter(
        Subject.user_id == session["uid"], Slot.day == day, Slot.start < end, Slot.end > start)
    if slot.id:
        q = q.filter(Slot.id != slot.id)
    clash = q.first()
    if clash:
        return f"Clashes with {clash.subject.code} on {DAYS[day]} ({time12(clash.start)} to {time12(clash.end)})."
    slot.subject_id, slot.day, slot.start, slot.end = subject.id, day, start, end
    slot.room = form.get("room", "").strip()
    db.session.add(slot)
    db.session.commit()


@app.post("/slots")
@login_required
def add_slot():
    flash(save_slot(Slot(), request.form) or "Class time added.")
    return redirect(url_for("index"))


@app.route("/slots/<int:slot_id>/edit", methods=["GET", "POST"])
@login_required
def edit_slot(slot_id):
    sl = own_slot(slot_id)
    if request.method == "POST":
        err = save_slot(sl, request.form)
        if not err:
            flash("Class time updated.")
            return redirect(url_for("index"))
        flash(err)
    subjects = Subject.query.filter_by(user_id=session["uid"]).order_by(Subject.code).all()
    return render_template("edit_slot.html", slot=sl, subjects=subjects)


@app.post("/slots/<int:slot_id>/delete")
@login_required
def delete_slot(slot_id):
    db.session.delete(own_slot(slot_id))
    db.session.commit()
    return redirect(url_for("index"))


# ---------- templates ----------
BASE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>School Schedule Tracker</title>
<style>
:root{--paper:#f2f5f1;--ink:#1c2f3d;--muted:#5d6f7b;--line:#cfd8d2;--card:#fff;--accent:#2a6f6b;--chalk:#f1c84b;--danger:#a8402f}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);font:16px/1.5 "Segoe UI",system-ui,sans-serif}
main{max-width:1180px;margin:0 auto;padding:24px 20px 60px}
header{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:20px}
h1{font-size:1.8rem;margin:0}h2{font-size:1.15rem;margin:0 0 12px}
.sub{color:var(--muted);margin:0}
.flash{background:var(--chalk);padding:10px 14px;border-radius:6px;margin-bottom:8px}
.forms{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:16px;margin-bottom:28px}
.panel{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:18px;max-width:560px}
.forms .panel{max-width:none}
label{display:block;font-size:.85rem;color:var(--muted);margin-bottom:10px}
input,select{width:100%;padding:8px 10px;margin-top:3px;font:inherit;border:1px solid var(--line);border-radius:6px;background:#fff;color:var(--ink)}
.row{display:grid;grid-template-columns:1fr 1fr;gap:10px}
button,.btn{font:inherit;cursor:pointer;border:0;border-radius:6px;padding:9px 16px;background:var(--accent);color:#fff;text-decoration:none;display:inline-block}
button:hover,.btn:hover{background:#22595a}
.link{background:none;color:var(--accent);padding:2px 6px;font-size:.85rem}
.link:hover{background:none;text-decoration:underline}.danger{color:var(--danger)}
.quiet{background:none;color:var(--ink);border:1px solid var(--line)}.quiet:hover{background:#e6ece8}
:focus-visible{outline:3px solid var(--chalk);outline-offset:2px}
.week{display:grid;grid-template-columns:repeat(7,minmax(150px,1fr));gap:10px;overflow-x:auto;margin-bottom:28px;padding-bottom:6px}
.day{background:var(--card);border:1px solid var(--line);border-radius:8px;min-height:170px}
.day h3{margin:0;padding:10px 12px;font-size:.95rem;border-bottom:1px solid var(--line)}
.day.today h3{background:var(--chalk);border-radius:7px 7px 0 0}
.slot{padding:9px 12px;border-bottom:1px solid var(--line);border-left:4px solid var(--accent)}
.slot:last-child{border-bottom:0}.slot b,.slot small{display:block}.slot small{color:var(--muted)}
.empty{color:var(--muted);padding:12px;font-size:.9rem}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:8px;overflow:hidden}
th,td{text-align:left;padding:10px 14px;border-bottom:1px solid var(--line)}
th{background:#e6ece8;font-size:.9rem}tfoot td{font-weight:600;border-bottom:0}
form.inline{display:inline}
</style></head><body><main>
<header><div><h1>School Schedule Tracker</h1>
{% if username %}<p class="sub">Signed in as {{ username }}</p>{% endif %}</div>
{% if username %}<form method="post" action="{{ url_for('logout') }}"><input type="hidden" name="csrf" value="{{ csrf }}"><button class="quiet">Log out</button></form>{% endif %}
</header>
{% for m in get_flashed_messages() %}<div class="flash" role="status">{{ m }}</div>{% endfor %}
{% block content %}{% endblock %}
</main></body></html>"""

AUTH = """{% extends 'base.html' %}{% block content %}
<form class="panel" method="post">
<input type="hidden" name="csrf" value="{{ csrf }}">
<h2>{{ 'Create your account' if mode == 'register' else 'Log in' }}</h2>
<label>Email<input type="email" name="email" required autocomplete="email"></label>
<label>Password<input type="password" name="password" required {{ 'minlength=8' if mode == 'register' }} autocomplete="{{ 'new-password' if mode == 'register' else 'current-password' }}"></label>
<button>{{ 'Create account' if mode == 'register' else 'Log in' }}</button>
<p class="sub">{% if mode == 'register' %}Already have an account? <a href="{{ url_for('login') }}">Log in</a>
{% else %}New here? <a href="{{ url_for('register') }}">Create an account</a>{% endif %}</p>
</form>
{% if mode == 'login' %}
<form class="panel" method="post" action="{{ url_for('resend') }}" style="margin-top:16px">
<input type="hidden" name="csrf" value="{{ csrf }}">
<h2>Didn't get the confirmation email?</h2>
<label>Email<input type="email" name="email" required autocomplete="email"></label>
<button class="quiet">Resend confirmation</button>
</form>
{% endif %}{% endblock %}"""

SLOT_FORM = """<input type="hidden" name="csrf" value="{{ csrf }}">
<label>Subject<select name="subject_id" required>
{% for s in subjects %}<option value="{{ s.id }}" {{ 'selected' if slot and slot.subject_id == s.id }}>{{ s.code }}: {{ s.name }}</option>{% endfor %}
</select></label>
<div class="row">
<label>Day<select name="day">{% for d in days %}<option value="{{ loop.index0 }}" {{ 'selected' if loop.index0 == (slot.day if slot else today) }}>{{ d }}</option>{% endfor %}</select></label>
<label>Room (optional)<input name="room" value="{{ slot.room if slot else '' }}" placeholder="Room 204"></label>
</div>
<div class="row">
<label>Starts<input type="time" name="start" value="{{ slot.start if slot else '08:00' }}" required></label>
<label>Ends<input type="time" name="end" value="{{ slot.end if slot else '09:00' }}" required></label>
</div>"""

INDEX = """{% extends 'base.html' %}{% block content %}
<section class="forms">
<form class="panel" method="post" action="{{ url_for('add_subject') }}">
<input type="hidden" name="csrf" value="{{ csrf }}"><h2>Add a subject</h2>
<div class="row"><label>Subject code<input name="code" placeholder="MATH101" required></label>
<label>Teacher (optional)<input name="teacher" placeholder="Ms. Reyes"></label></div>
<label>Subject name<input name="name" placeholder="College Algebra" required></label>
<button>Add subject</button></form>
<form class="panel" method="post" action="{{ url_for('add_slot') }}"><h2>Add a class time</h2>
{% if subjects %}{% with slot=None %}{% include 'slot_form.html' %}{% endwith %}<button>Add class time</button>
{% else %}<p class="empty">Add a subject first, then schedule its class times here.</p>{% endif %}</form>
</section>
<h2>This week</h2>
<section class="week">{% for d in days %}{% set di = loop.index0 %}
<div class="day {{ 'today' if di == today }}"><h3>{{ d }}</h3>
{% for s in week[di] %}<div class="slot"><b>{{ s.subject.code }}</b><small>{{ s.subject.name }}</small>
<small>{{ time12(s.start) }} to {{ time12(s.end) }}{% if s.room %} in {{ s.room }}{% endif %}</small>
<a class="link" href="{{ url_for('edit_slot', slot_id=s.id) }}">Edit</a>
<form class="inline" method="post" action="{{ url_for('delete_slot', slot_id=s.id) }}"><input type="hidden" name="csrf" value="{{ csrf }}">
<button class="link danger" aria-label="Remove {{ s.subject.code }} on {{ d }}">Remove</button></form></div>
{% else %}<div class="empty">No classes</div>{% endfor %}</div>{% endfor %}</section>
<h2>Subjects and weekly time</h2>
{% if subjects %}<table><thead><tr><th>Code</th><th>Subject</th><th>Teacher</th><th>Time per week</th><th></th></tr></thead><tbody>
{% for s in subjects %}<tr><td><b>{{ s.code }}</b></td><td>{{ s.name }}</td><td>{{ s.teacher or '-' }}</td><td>{{ totals[s.id] }}</td>
<td><a class="link" href="{{ url_for('edit_subject', sid=s.id) }}">Edit</a>
<form class="inline" method="post" action="{{ url_for('delete_subject', sid=s.id) }}" onsubmit="return confirm('Delete {{ s.code }} and all its class times?')">
<input type="hidden" name="csrf" value="{{ csrf }}"><button class="link danger">Delete</button></form></td></tr>{% endfor %}
</tbody><tfoot><tr><td colspan="3">Total class time</td><td colspan="2">{{ week_total }}</td></tr></tfoot></table>
{% else %}<p class="empty">No subjects yet. Add your first one above.</p>{% endif %}
{% endblock %}"""

EDIT_SUBJECT = """{% extends 'base.html' %}{% block content %}
<form class="panel" method="post"><input type="hidden" name="csrf" value="{{ csrf }}"><h2>Edit subject</h2>
<div class="row"><label>Subject code<input name="code" value="{{ s.code }}" required></label>
<label>Teacher (optional)<input name="teacher" value="{{ s.teacher }}"></label></div>
<label>Subject name<input name="name" value="{{ s.name }}" required></label>
<button>Save changes</button> <a class="btn quiet" href="{{ url_for('index') }}">Cancel</a></form>{% endblock %}"""

EDIT_SLOT = """{% extends 'base.html' %}{% block content %}
<form class="panel" method="post"><h2>Edit class time</h2>{% include 'slot_form.html' %}
<button>Save changes</button> <a class="btn quiet" href="{{ url_for('index') }}">Cancel</a></form>{% endblock %}"""

app.jinja_loader = DictLoader({
    "base.html": BASE, "auth.html": AUTH, "index.html": INDEX, "slot_form.html": SLOT_FORM,
    "edit_subject.html": EDIT_SUBJECT, "edit_slot.html": EDIT_SLOT,
})

if __name__ == "__main__":
    app.run(debug=True)
