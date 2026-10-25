"""TrustVault - Secure Document Management (Flask)."""
import os
import re
import uuid
from datetime import datetime, date, timedelta
from functools import wraps

from flask import (Flask, render_template, request, redirect, url_for, flash,
                   abort, send_from_directory)
from flask_login import (LoginManager, UserMixin, login_user, logout_user,
                         login_required, current_user)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from sqlalchemy import or_, func
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "change-this-in-production"),
    SQLALCHEMY_DATABASE_URI=os.environ.get(
        "DATABASE_URL", "sqlite:///" + os.path.join(BASE_DIR, "trustvault.db")
    ).replace("postgres://", "postgresql://", 1),
    UPLOAD_FOLDER=os.environ.get("UPLOAD_FOLDER", os.path.join(BASE_DIR, "uploads")),
    MAX_CONTENT_LENGTH=10 * 1024 * 1024,  # 10 MB
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
)
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in to continue."

ALLOWED_EXT = {"pdf", "txt", "docx", "xlsx", "csv", "png", "jpg", "jpeg"}

CATEGORIES = [
    ("Finance", "💰", "Invoices, salary slips and financial records."),
    ("HR", "👥", "Resumes, offer letters and employee records."),
    ("Legal", "⚖️", "Contracts, agreements and legal documents."),
    ("IT", "💻", "Technical files and project documentation."),
    ("Education", "🎓", "Certificates, marksheets and study materials."),
    ("Personal", "👤", "Your personal records and important files."),
    ("General", "📁", "Everything else that doesn't fit elsewhere."),
]


# ----------------------------------------------------------------- models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    documents = db.relationship("Document", backref="owner", lazy=True,
                                cascade="all, delete-orphan")


class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, default="")
    category = db.Column(db.String(50), nullable=False, default="General")
    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), nullable=False, unique=True)
    file_size = db.Column(db.Integer, default=0)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)


class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    username = db.Column(db.String(80))
    action = db.Column(db.String(60), nullable=False)
    details = db.Column(db.String(300), default="")
    ip_address = db.Column(db.String(64))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


# ---------------------------------------------------------------- helpers
@login_manager.user_loader
def load_user(uid):
    return db.session.get(User, int(uid))


def log(action, details="", user=None):
    u = user or (current_user if current_user.is_authenticated else None)
    db.session.add(ActivityLog(
        user_id=u.id if u else None,
        username=u.username if u else "anonymous",
        action=action, details=details[:300],
        ip_address=request.headers.get("X-Forwarded-For", request.remote_addr),
    ))
    db.session.commit()


def admin_required(fn):
    @wraps(fn)
    @login_required
    def wrapper(*a, **kw):
        if not current_user.is_admin:
            abort(403)
        return fn(*a, **kw)
    return wrapper


def allowed(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXT


def human_size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def get_owned_doc(doc_id):
    doc = db.session.get(Document, doc_id) or abort(404)
    if doc.user_id != current_user.id and not current_user.is_admin:
        abort(403)
    return doc


app.jinja_env.filters["filesize"] = human_size
app.jinja_env.globals["CATEGORIES"] = CATEGORIES


@app.context_processor
def inject_year():
    return {"now_year": datetime.utcnow().year}


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    return resp


# ------------------------------------------------------------------- auth
@app.route("/")
def index():
    return redirect(url_for("dashboard" if current_user.is_authenticated else "login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    errors, form = {}, {}
    if request.method == "POST":
        form = {k: request.form.get(k, "").strip() for k in ("username", "email")}
        pw, pw2 = request.form.get("password", ""), request.form.get("confirm", "")
        if not 3 <= len(form["username"]) <= 80:
            errors["username"] = "Username must be between 3 and 80 characters."
        elif User.query.filter(func.lower(User.username) == form["username"].lower()).first():
            errors["username"] = "That username is already taken."
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", form["email"]):
            errors["email"] = "Enter a valid email address."
        elif User.query.filter(func.lower(User.email) == form["email"].lower()).first():
            errors["email"] = "An account with this email already exists."
        if len(pw) < 12:
            errors["password"] = "Use at least 12 characters for your password."
        if pw != pw2:
            errors["confirm"] = "Passwords do not match."
        if not errors:
            first = User.query.count() == 0
            user = User(username=form["username"], email=form["email"].lower(),
                        password_hash=generate_password_hash(pw), is_admin=first)
            db.session.add(user)
            db.session.commit()
            log("REGISTER", f"New account: {user.username}", user=user)
            flash("Registration successful. Please log in.", "success")
            return redirect(url_for("login"))
    return render_template("register.html", errors=errors, form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        ident = request.form.get("identifier", "").strip()
        pw = request.form.get("password", "")
        user = User.query.filter(or_(func.lower(User.username) == ident.lower(),
                                     func.lower(User.email) == ident.lower())).first()
        if user and check_password_hash(user.password_hash, pw):
            login_user(user)
            log("LOGIN", "Successful login", user=user)
            nxt = request.args.get("next", "")
            return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//")
                            else url_for("dashboard"))
        log("LOGIN_FAILED", f"Failed login for '{ident[:60]}'")
        flash("Invalid username/email or password.", "error")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    log("LOGOUT")
    logout_user()
    flash("You have been signed out.", "success")
    return redirect(url_for("login"))


# -------------------------------------------------------------- dashboard
@app.route("/dashboard")
@login_required
def dashboard():
    q = Document.query.filter_by(user_id=current_user.id)
    total = q.count()
    size = db.session.query(func.coalesce(func.sum(Document.file_size), 0)) \
        .filter(Document.user_id == current_user.id).scalar()
    recent = q.order_by(Document.uploaded_at.desc()).limit(5).all()
    cats = dict(db.session.query(Document.category, func.count(Document.id))
                .filter_by(user_id=current_user.id).group_by(Document.category).all())
    activity = ActivityLog.query.filter_by(user_id=current_user.id) \
        .order_by(ActivityLog.created_at.desc()).limit(5).all()
    return render_template("dashboard.html", total=total, size=size, recent=recent,
                           cats=cats, activity=activity)


# -------------------------------------------------------------- documents
@app.route("/documents")
@login_required
def documents():
    term = request.args.get("q", "").strip()
    q = Document.query.filter_by(user_id=current_user.id)
    if term:
        q = q.filter(Document.title.ilike(f"%{term}%"))
    docs = q.order_by(Document.uploaded_at.desc()).all()
    return render_template("documents.html", docs=docs, term=term)


@app.route("/documents/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        desc = request.form.get("description", "").strip()
        cat = request.form.get("category", "General")
        f = request.files.get("file")
        valid_cats = [c[0] for c in CATEGORIES]
        if not title:
            flash("Document title is required.", "error")
        elif cat not in valid_cats:
            flash("Choose a valid category.", "error")
        elif not f or not f.filename:
            flash("Please choose a file to upload.", "error")
        elif not allowed(f.filename):
            flash("File type not allowed. Use PDF, TXT, DOCX, XLSX, CSV, PNG, JPG or JPEG.", "error")
        else:
            ext = secure_filename(f.filename).rsplit(".", 1)[-1].lower()
            stored = f"{uuid.uuid4().hex}.{ext}"
            path = os.path.join(app.config["UPLOAD_FOLDER"], stored)
            f.save(path)
            doc = Document(title=title[:200], description=desc, category=cat,
                           original_filename=secure_filename(f.filename),
                           stored_filename=stored, file_size=os.path.getsize(path),
                           user_id=current_user.id)
            db.session.add(doc)
            db.session.commit()
            log("UPLOAD", f"Uploaded '{doc.title}' ({cat})")
            flash("Document uploaded securely.", "success")
            return redirect(url_for("documents"))
    return render_template("upload.html", selected=request.args.get("category", "General"))


@app.route("/documents/<int:doc_id>/download")
@login_required
def download(doc_id):
    doc = get_owned_doc(doc_id)
    log("DOWNLOAD", f"Downloaded '{doc.title}'")
    return send_from_directory(app.config["UPLOAD_FOLDER"], doc.stored_filename,
                               as_attachment=True, download_name=doc.original_filename)


@app.route("/documents/<int:doc_id>/delete", methods=["POST"])
@login_required
def delete(doc_id):
    doc = get_owned_doc(doc_id)
    try:
        os.remove(os.path.join(app.config["UPLOAD_FOLDER"], doc.stored_filename))
    except FileNotFoundError:
        pass
    title = doc.title
    db.session.delete(doc)
    db.session.commit()
    log("DELETE", f"Deleted '{title}'")
    flash("Document deleted.", "success")
    return redirect(request.referrer or url_for("documents"))


@app.route("/documents/search")
@login_required
def search():
    term = request.args.get("q", "").strip()
    cat = request.args.get("category", "")
    owner = request.args.get("user", "").strip()
    day = request.args.get("date", "").strip()
    searched = any([term, cat, owner, day])
    results = []
    if searched:
        q = Document.query.join(User)
        if not current_user.is_admin:
            q = q.filter(Document.user_id == current_user.id)
        if term:
            q = q.filter(or_(Document.title.ilike(f"%{term}%"),
                             Document.original_filename.ilike(f"%{term}%")))
        if cat:
            q = q.filter(Document.category == cat)
        if owner:
            q = q.filter(User.username.ilike(f"%{owner}%"))
        if day:
            try:
                d = datetime.strptime(day, "%Y-%m-%d").date()
                q = q.filter(Document.uploaded_at >= datetime.combine(d, datetime.min.time()),
                             Document.uploaded_at < datetime.combine(d + timedelta(days=1), datetime.min.time()))
            except ValueError:
                flash("Invalid date.", "error")
        results = q.order_by(Document.uploaded_at.desc()).all()
        log("SEARCH", f"q='{term}' cat='{cat}' user='{owner}' date='{day}'")
    return render_template("search.html", results=results, searched=searched,
                           term=term, cat=cat, owner=owner, day=day)


@app.route("/documents/categories")
@login_required
def categories():
    counts = dict(db.session.query(Document.category, func.count(Document.id))
                  .filter_by(user_id=current_user.id).group_by(Document.category).all())
    return render_template("categories.html", counts=counts)


@app.route("/documents/categories/<name>")
@login_required
def category_docs(name):
    meta = next((c for c in CATEGORIES if c[0].lower() == name.lower()), None) or abort(404)
    docs = Document.query.filter_by(user_id=current_user.id, category=meta[0]) \
        .order_by(Document.uploaded_at.desc()).all()
    return render_template("category_docs.html", cat=meta, docs=docs)


@app.route("/logs")
@admin_required
def logs():
    page = request.args.get("page", 1, type=int)
    p = ActivityLog.query.order_by(ActivityLog.created_at.desc()).paginate(page=page, per_page=25)
    return render_template("logs.html", pagination=p)


# ---------------------------------------------------------------- errors
@app.errorhandler(403)
def e403(e):
    if not current_user.is_authenticated:
        return redirect(url_for("login"))
    return render_template("error.html", code=403, title="Access Denied",
                           msg="You don't have permission to access this resource. If you believe "
                               "this is a mistake, contact the document owner or administrator."), 403


@app.errorhandler(404)
def e404(e):
    if not current_user.is_authenticated:
        return redirect(url_for("login"))
    return render_template("error.html", code=404, title="Not Found",
                           msg="The page or document you're looking for doesn't exist."), 404


@app.errorhandler(413)
def e413(e):
    flash("File too large. Maximum size is 10 MB.", "error")
    return redirect(url_for("upload"))


# ------------------------------------------------------------------- CLI
@app.cli.command("make-admin")
def make_admin():
    """Usage: flask make-admin  (prompts for username)"""
    name = input("Username to promote: ").strip()
    u = User.query.filter_by(username=name).first()
    if not u:
        print("User not found.")
        return
    u.is_admin = True
    db.session.commit()
    print(f"{name} is now an admin.")


with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
