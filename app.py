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

AUTH = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ 'Create account' if mode == 'register' else 'Log in' }} · School Schedule Tracker</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,400;12..96,600;12..96,800&display=swap" rel="stylesheet">
<style>
:root{--board:#14313f;--paper:#f6f7f3;--ink:#14313f;--muted:#5f7480;--line:#d9dfd9;--sky:#7cc4f2;--mint:#7fd6b0;--sun:#f4cf5c;--violet:#a99cf5;--pink:#f4a0bf;--coral:#d9573f;--row:46px}
*{box-sizing:border-box}
html,body{height:100%}
body{margin:0;font-family:"Bricolage Grotesque",system-ui,"Segoe UI",sans-serif;color:var(--ink);background:var(--paper)}
.shell{min-height:100%;display:grid;grid-template-columns:minmax(0,1.1fr) minmax(0,.9fr)}

/* left: the timetable that builds itself */
.board{background:var(--board);color:#fff;padding:40px clamp(24px,5vw,64px);display:flex;flex-direction:column;justify-content:space-between;gap:32px;overflow:hidden}
.brand{display:flex;align-items:center;gap:10px;font-weight:600}
.mark{display:grid;grid-template-columns:1fr 1fr;gap:3px;width:22px}
.mark i{display:block;aspect-ratio:1;border-radius:3px}
.mark i:nth-child(1){background:var(--sky)}.mark i:nth-child(2){background:var(--sun)}
.mark i:nth-child(3){background:var(--pink)}.mark i:nth-child(4){background:var(--mint)}
.board h1{font-size:clamp(2.3rem,4.6vw,4.2rem);line-height:.98;letter-spacing:-.035em;font-weight:800;margin:0 0 14px;max-width:10ch}
.board .sub{margin:0;color:#b6c9d3;max-width:34ch}
.tt{max-width:640px;width:100%}
.tt-days{display:grid;grid-template-columns:34px repeat(5,1fr);column-gap:8px;font-size:.78rem;color:#9fb6c2;padding-bottom:8px}
.tt-body{display:grid;grid-template-columns:34px 1fr;column-gap:8px}
.hours{display:grid;grid-template-rows:repeat(5,var(--row));font-size:.72rem;color:#9fb6c2}
.cols{position:relative;display:grid;grid-template-columns:repeat(5,1fr);grid-template-rows:repeat(5,var(--row));column-gap:8px;background:repeating-linear-gradient(to bottom,rgba(255,255,255,.1) 0 1px,transparent 1px var(--row))}
.b{grid-column:var(--c);grid-row:var(--r) / span var(--s);margin:2px 0;padding:5px 8px;border-radius:8px;background:var(--bg);color:var(--board);font-size:.74rem;line-height:1.2;font-weight:600;overflow:hidden;transition:transform .2s,box-shadow .2s;animation:drop .8s cubic-bezier(.2,1.3,.4,1) var(--d) backwards}
.b:hover{transform:translateY(-3px);box-shadow:0 8px 18px rgba(0,0,0,.3)}
.b small{display:block;font-weight:400;opacity:.75}
.sky{--bg:var(--sky)}.mint{--bg:var(--mint)}.sun{--bg:var(--sun)}.violet{--bg:var(--violet)}.pink{--bg:var(--pink)}
.now{position:absolute;left:-6px;right:0;top:0;height:2px;background:var(--sun);box-shadow:0 0 14px rgba(244,207,92,.8);animation:sweep 9s ease-in-out 1.8s infinite alternate backwards;pointer-events:none}
.now::before{content:"";position:absolute;left:0;top:-4px;width:10px;height:10px;border-radius:50%;background:var(--sun)}
@keyframes drop{from{opacity:0;transform:translateY(-40px) scale(.9)}to{opacity:1;transform:none}}
@keyframes sweep{0%{opacity:0;transform:translateY(0)}8%{opacity:1}92%{opacity:1}100%{opacity:0;transform:translateY(calc(var(--row)*5))}}

/* right: the forms */
.side{display:grid;place-items:center;padding:40px 24px}
.auth{width:100%;max-width:400px}
.seg{position:relative;display:grid;grid-template-columns:1fr 1fr;background:#e7ebe5;border-radius:999px;padding:4px;margin-bottom:30px}
.seg::before{content:"";position:absolute;top:4px;bottom:4px;left:4px;width:calc(50% - 4px);background:#fff;border-radius:999px;box-shadow:0 1px 3px rgba(20,49,63,.18);transition:transform .4s cubic-bezier(.3,1.3,.5,1)}
#auth[data-mode=register] .seg::before{transform:translateX(100%)}
.seg a{position:relative;text-align:center;padding:10px 0;border-radius:999px;text-decoration:none;color:var(--muted);font-weight:600;transition:color .2s}
.seg a[aria-current]{color:var(--ink)}
.flash{background:#fff;border:1px solid var(--line);border-left:5px solid var(--sun);border-radius:10px;padding:12px 14px;margin-bottom:20px;font-size:.92rem;animation:slide .5s cubic-bezier(.2,.9,.3,1) backwards}
@keyframes slide{from{opacity:0;transform:translateY(-10px)}}
.forms{display:grid}
.pane{grid-area:1 / 1;opacity:0;visibility:hidden;transform:translateX(26px);transition:opacity .3s,transform .4s cubic-bezier(.2,.9,.3,1),visibility .3s}
#auth[data-mode=login] .pane.login,#auth[data-mode=register] .pane.register{opacity:1;visibility:visible;transform:none}
#auth[data-mode=register] .pane.login{transform:translateX(-26px)}
.pane h2{font-size:1.95rem;letter-spacing:-.025em;font-weight:800;margin:0 0 6px}
.lead{margin:0 0 24px;color:var(--muted)}
.field{position:relative;margin-bottom:14px}
.field input{width:100%;height:56px;padding:22px 14px 6px;border:1.5px solid var(--line);border-radius:12px;background:#fff;font:inherit;color:var(--ink);transition:border-color .2s,box-shadow .2s}
.field input:focus{outline:none;border-color:var(--ink);box-shadow:0 0 0 4px rgba(244,207,92,.5)}
.field label{position:absolute;left:15px;top:17px;color:var(--muted);pointer-events:none;transition:top .18s,font-size .18s}
.field input:focus + label,.field input:not(:placeholder-shown) + label{top:7px;font-size:.72rem}
.eye{position:absolute;right:8px;top:8px;height:40px;padding:0 10px;border:0;border-radius:8px;background:none;color:var(--muted);font:inherit;font-size:.82rem;cursor:pointer}
.eye:hover{color:var(--ink)}
.meter{display:grid;grid-template-columns:repeat(3,1fr);gap:6px;margin:2px 0 8px}
.meter i{height:4px;border-radius:2px;background:var(--line);transition:background .3s}
.meter[data-s="1"] i:nth-child(1){background:var(--coral)}
.meter[data-s="2"] i:nth-child(-n+2){background:var(--sun)}
.meter[data-s="3"] i{background:var(--mint)}
.hint{margin:0 0 18px;font-size:.82rem;color:var(--muted);min-height:1.3em}
.go{position:relative;isolation:isolate;overflow:hidden;width:100%;height:54px;border:0;border-radius:12px;background:var(--ink);color:#fff;font:inherit;font-size:1rem;font-weight:700;cursor:pointer}
.go::before{content:"";position:absolute;inset:0;background:var(--sun);transform:translateX(-101%);transition:transform .45s cubic-bezier(.2,.9,.3,1);z-index:-1}
.go:hover,.go:focus-visible{color:var(--ink)}
.go:hover::before,.go:focus-visible::before{transform:none}
.go:focus-visible{outline:3px solid var(--ink);outline-offset:3px}
.go.busy{pointer-events:none}
.go.busy span{opacity:0}
.go.busy::after{content:"";position:absolute;left:50%;top:50%;width:20px;height:20px;margin:-10px 0 0 -10px;border:3px solid currentColor;border-right-color:transparent;border-radius:50%;animation:spin .7s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.note{margin:16px 0 0;font-size:.85rem;color:var(--muted)}
details{margin-top:22px;font-size:.9rem;color:var(--muted)}
summary{cursor:pointer;width:fit-content}
summary:focus-visible,.seg a:focus-visible,.eye:focus-visible,.ghost:focus-visible{outline:3px solid var(--sun);outline-offset:2px}
details form{margin-top:14px}
.ghost{width:100%;height:46px;border:1.5px solid var(--line);border-radius:12px;background:none;color:var(--ink);font:inherit;font-weight:600;cursor:pointer;transition:background .2s}
.ghost:hover{background:#e7ebe5}

@media (max-width:860px){
  :root{--row:30px}
  .shell{grid-template-columns:1fr}
  .board{padding:22px 20px 26px;gap:18px}
  .board h1{font-size:2rem;max-width:none;margin:0}
  .board .sub,.b small{display:none}
  .b{padding:4px 6px}
  .side{align-items:start;padding:28px 20px 44px}
}
@media (prefers-reduced-motion:reduce){
  *,*::before,*::after{animation:none!important;transition-duration:.01ms!important}
  .now{transform:translateY(calc(var(--row)*2))}
}
</style></head>
<body>
{% set msgs = get_flashed_messages() %}
<div class="shell">
  <aside class="board">
    <div class="brand"><span class="mark" aria-hidden="true"><i></i><i></i><i></i><i></i></span>School Schedule Tracker</div>
    <div>
      <h1>UMTC SCHEDULE TRACKER FOR STUDENTS.</h1>
      <p class="sub">Subjects, codes and class times, all on one timetable.</p>
    </div>
    <div class="tt" aria-hidden="true">
      <div class="tt-days"><span></span><span>Mon</span><span>Tue</span><span>Wed</span><span>Thu</span><span>Fri</span></div>
      <div class="tt-body">
        <div class="hours"><span>8</span><span>9</span><span>10</span><span>11</span><span>12</span></div>
        <div class="cols">
          <div class="b sky" style="--c:1;--r:1;--s:2;--d:.45s">CCE 105<small>PROGRAMMING</small></div>
          <div class="b pink" style="--c:1;--r:4;--s:1;--d:1.15s">IT5<small>PROGRAMMING</small></div>
          <div class="b mint" style="--c:2;--r:2;--s:2;--d:.6s">PHYSICS 1<small>SCIENCE</small></div>
          <div class="b sun" style="--c:3;--r:1;--s:1;--d:.75s">CALCULUS<small>MATH</small></div>
          <div class="b violet" style="--c:3;--r:3;--s:2;--d:.9s">MYSQL<small>Programming</small></div>
          <div class="b sky" style="--c:4;--r:2;--s:1;--d:1.05s">CALCULUS 2<small>MATH</small></div>
          <div class="b mint" style="--c:4;--r:4;--s:2;--d:1.2s">PROGRAMMING 1<small>PROGRAMMING JAVA</small></div>
          <div class="b mint" style="--c:5;--r:1;--s:2;--d:.85s">PROGRAMMING 2<small>PROGRAMMING PYTHON</small></div>
          <div class="b sun" style="--c:5;--r:4;--s:1;--d:1.3s">GITHUB<small>VERSION CONTROL</small></div>
          <div class="now"></div>
        </div>
      </div>
    </div>
  </aside>

  <main class="side">
    <div class="auth" id="auth" data-mode="{{ mode }}" data-login="{{ url_for('login') }}" data-register="{{ url_for('register') }}">
      <nav class="seg" aria-label="Choose log in or create account">
        <a href="{{ url_for('login') }}" data-go="login" {{ 'aria-current=page' if mode == 'login' }}>Log in</a>
        <a href="{{ url_for('register') }}" data-go="register" {{ 'aria-current=page' if mode == 'register' }}>Create account</a>
      </nav>
      {% for m in msgs %}<div class="flash" role="status">{{ m }}</div>{% endfor %}

      <div class="forms">
        <section class="pane login" aria-label="Log in">
          <h2>Welcome back</h2>
          <p class="lead">Log in to see your week.</p>
          <form method="post" action="{{ url_for('login') }}" data-busy>
            <input type="hidden" name="csrf" value="{{ csrf }}">
            <div class="field"><input id="l-email" type="email" name="email" placeholder=" " required autocomplete="email"><label for="l-email">Email address</label></div>
            <div class="field"><input id="l-pw" type="password" name="password" placeholder=" " required autocomplete="current-password"><label for="l-pw">Password</label><button type="button" class="eye">Show</button></div>
            <button class="go"><span>Log in</span></button>
          </form>
          <details>
            <summary>Didn’t get the confirmation email?</summary>
            <form method="post" action="{{ url_for('resend') }}">
              <input type="hidden" name="csrf" value="{{ csrf }}">
              <div class="field"><input id="s-email" type="email" name="email" placeholder=" " required autocomplete="email"><label for="s-email">Email address</label></div>
              <button class="ghost">Resend confirmation</button>
            </form>
          </details>
        </section>

        <section class="pane register" aria-label="Create account">
          <h2>Start your week</h2>
          <p class="lead">Create an account to save your subjects and schedule.</p>
          <form method="post" action="{{ url_for('register') }}" data-busy>
            <input type="hidden" name="csrf" value="{{ csrf }}">
            <div class="field"><input id="r-email" type="email" name="email" placeholder=" " required autocomplete="email"><label for="r-email">Email address</label></div>
            <div class="field"><input id="r-pw" type="password" name="password" placeholder=" " required minlength="8" autocomplete="new-password"><label for="r-pw">Password</label><button type="button" class="eye">Show</button></div>
            <div class="meter" id="meter" data-s="0" aria-hidden="true"><i></i><i></i><i></i></div>
            <p class="hint" id="hint" aria-live="polite">At least 8 characters</p>
            <button class="go"><span>Create account</span></button>
            <p class="note">We’ll email you a link to confirm your address before you can log in.</p>
          </form>
        </section>
      </div>
    </div>
  </main>
</div>
<script>
(function(){
  var root=document.getElementById('auth'),tabs=root.querySelectorAll('[data-go]');
  var urls={login:root.dataset.login,register:root.dataset.register};
  var titles={login:'Log in',register:'Create account'};
  function setMode(m){
    root.dataset.mode=m;
    tabs.forEach(function(t){if(t.dataset.go===m){t.setAttribute('aria-current','page')}else{t.removeAttribute('aria-current')}});
    document.title=titles[m]+' · School Schedule Tracker';
    try{history.replaceState(null,'',urls[m])}catch(e){}
  }
  tabs.forEach(function(t){t.addEventListener('click',function(e){e.preventDefault();setMode(t.dataset.go)})});

  document.querySelectorAll('.eye').forEach(function(b){
    b.addEventListener('click',function(){
      var i=b.parentNode.querySelector('input'),show=i.type==='password';
      i.type=show?'text':'password';b.textContent=show?'Hide':'Show';
    });
  });

  var pw=document.getElementById('r-pw'),meter=document.getElementById('meter'),hint=document.getElementById('hint');
  var msgs=['At least 8 characters','Okay. Add a number or a symbol for more','Good password','Strong password'];
  pw.addEventListener('input',function(){
    var p=pw.value,s=0;
    if(p.length>=8){s=1;if(/[A-Za-z]/.test(p)&&/[0-9]/.test(p)){s=2}if(s===2&&(p.length>=12||/[^A-Za-z0-9]/.test(p))){s=3}}
    meter.dataset.s=s;hint.textContent=msgs[s];
  });

  document.querySelectorAll('form[data-busy]').forEach(function(f){
    f.addEventListener('submit',function(e){
      if(f.dataset.sent){e.preventDefault();return}
      f.dataset.sent='1';f.querySelector('.go').classList.add('busy');
    });
  });
  window.addEventListener('pageshow',function(){
    document.querySelectorAll('form[data-busy]').forEach(function(f){delete f.dataset.sent;f.querySelector('.go').classList.remove('busy')});
  });
})();
</script>
</body></html>"""

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
