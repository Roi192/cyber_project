"""Administrator login and access control for the dashboard (Phase B).

Two separate worlds, on purpose:

  * the DASHBOARD (every page, every read API the pages poll, every administrative action) is for a signed-in administrator only. It uses
    Flask-Login sessions and Flask-WTF CSRF tokens. The default is DENY: a route is open only if it is explicitly marked as a sensor API or
    as public, so a route added later is protected without anyone remembering to protect it.
  * the SENSOR API (browser extensions and Windows agents) keeps its own authentication - the organisation API key and the per-sensor
    secrets - and never looks at a login cookie. Sensor routes are exempt from CSRF because they carry no browser session: a browser can
    be tricked into sending a cookie, never into sending a custom key header.

Passwords are hashed with Werkzeug (PBKDF2-HMAC-SHA256, 600 000 iterations, per-password salt), which exists in every Python build. There
is no default account and no sign-up page: the first administrator is created from a shell on the server with manage_admin.py.
"""
import hashlib
import hmac
import ipaddress
import re
import secrets
import sys
import time
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlsplit

from flask import Blueprint, abort, current_app, has_request_context, jsonify, redirect, render_template, request, session, url_for
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user
from flask_wtf.csrf import CSRFError, CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash

import config
import database

# ---- policy ----------------------------------------------------------------------------------------------------------
PASSWORD_HASH_METHOD = "pbkdf2:sha256:600000"
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128                    # a hard cap so a huge "password" cannot be used to burn CPU
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]{3,40}$")
COMMON_PASSWORDS = frozenset(["password", "password1", "password12", "password123", "passw0rd1234", "123456789012", "qwertyuiop12",
                              "administrator", "changeme1234", "letmein12345", "welcome12345", "iloveyou1234"])

LOGIN_WINDOW_MINUTES = 15
LOGIN_MAX_FAILURES_PER_IP = 5                # failed sign-ins from one address inside the window
LOGIN_MAX_FAILURES_PER_USERNAME = 10         # failed sign-ins for one name from anywhere (higher: it must not be an easy way to lock the owner out)
ATTEMPT_RETENTION_DAYS = 2

KNOWN_WEAK_SECRETS = frozenset(["", "change-me", "changeme", "dev-only-change-me", "secret", "password"])
MIN_SECRET_KEY_LENGTH = 24

csrf = CSRFProtect()
login_manager = LoginManager()
bp = Blueprint("auth", __name__)

_dummy_hash = []


class AuthError(Exception):
    """A refusal that can be shown to the person at the keyboard (weak password, name already used...)."""


# ---- marking routes ----------------------------------------------------------------------------------------------------
def sensor_api(view):
    """The route belongs to the sensor API: it has its own authentication (API key / sensor secret), takes no login cookie and, because a
    sensor sends no browser session, needs no CSRF token. Apply it OUTSIDE the key check: @app.route / @sensor_api / @require_api_key."""
    view.is_sensor_api = True
    csrf.exempt(view)
    return view


def public(view):
    """The route is open to everyone (the sign-in page itself)."""
    view.is_public = True
    return view


# ---- is the dashboard protection active? ------------------------------------------------------------------------------------
def enforced():
    """Always True in production. Only a test run (config.TEST_MODE, which cannot even open the real database) may switch the dashboard
    protection off, and only through the app config flag that the existing test suites set; the tests of this phase turn it on."""
    return not (config.TEST_MODE and current_app.config.get("AUTH_TEST_BYPASS", False))


def is_loopback(address):
    try:
        ip = ipaddress.ip_address((address or "").split("%")[0])
    except ValueError:
        return False
    if getattr(ip, "ipv4_mapped", None) is not None:
        ip = ip.ipv4_mapped
    return ip.is_loopback


def startup_problems(host, api_key, secret_key, test_mode=False):
    """Why this configuration must not be served (empty list = fine). Fail closed: no weak session secret, and no network listener without an
    API key for the sensors."""
    problems = []
    if not test_mode:
        if (secret_key or "") in KNOWN_WEAK_SECRETS or len(secret_key or "") < MIN_SECRET_KEY_LENGTH:
            problems.append("SECRET_KEY is missing, a known placeholder or shorter than %d characters. It signs the administrator sessions. "
                            "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\"" % MIN_SECRET_KEY_LENGTH)
    if host not in ("127.0.0.1", "localhost", "::1") and not (api_key or "").strip():
        problems.append("HOST=%s makes the server reachable from the network but API_KEY is empty, so any computer could submit data. Set "
                        "API_KEY (and the same key in every extension and agent) or use HOST=127.0.0.1." % host)
    return problems


# ---- passwords ---------------------------------------------------------------------------------------------------------
def password_problem(password, username=""):
    """None if acceptable, else the reason in plain words."""
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LENGTH:
        return "The password must have at least %d characters." % MIN_PASSWORD_LENGTH
    if len(password) > MAX_PASSWORD_LENGTH:
        return "The password must have at most %d characters." % MAX_PASSWORD_LENGTH
    lowered = password.lower()
    if lowered in COMMON_PASSWORDS or (username and lowered == username.lower()):
        return "That password is too easy to guess."
    if len(set(password)) < 5:
        return "The password needs more different characters."
    return None


def hash_password(password):
    return generate_password_hash(password, method=PASSWORD_HASH_METHOD)


def _dummy():
    if not _dummy_hash:
        _dummy_hash.append(hash_password("not-a-real-password-" + hashlib.sha256(str(time.time()).encode()).hexdigest()))
    return _dummy_hash[0]


def _fingerprint(password_hash):
    return hashlib.sha256(password_hash.encode("utf-8")).hexdigest()[:16]


# ---- accounts ----------------------------------------------------------------------------------------------------------
class Admin(UserMixin):
    def __init__(self, row):
        self.id = row["id"]
        self.username = row["username"]
        self._hash = row["password_hash"]
        self._active = bool(row["active"])

    @property
    def is_active(self):
        return self._active

    def get_id(self):
        # the id carries a fingerprint of the password hash: changing the password signs every other session out
        return "%d:%s" % (self.id, _fingerprint(self._hash))


def admin_count(conn=None):
    own = conn is None
    conn = conn or database.get_connection()
    try:
        return conn.execute("SELECT COUNT(*) FROM admins WHERE active = 1").fetchone()[0]
    finally:
        if own:
            conn.close()


def create_admin(username, password):
    """Create an administrator; returns its id. Raises AuthError with a readable reason."""
    username = (username or "").strip()
    if not USERNAME_PATTERN.match(username):
        raise AuthError("The user name must be 3 to 40 characters: letters, digits, dot, dash or underscore.")
    problem = password_problem(password, username)
    if problem:
        raise AuthError(problem)
    now = database.now_str()
    conn = database.get_connection()
    try:
        if conn.execute("SELECT 1 FROM admins WHERE username = ?", (username,)).fetchone():
            raise AuthError("An administrator with that name already exists.")
        cur = conn.execute("INSERT INTO admins (username, password_hash, active, created_at, password_changed_at) VALUES (?, ?, 1, ?, ?)",
                           (username, hash_password(password), now, now))
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


# ---- first-run setup (Phase F3.29) -------------------------------------------------------------------------------------------
SETUP_MAX_WRONG_CODES = 10
_setup = {"code": None, "wrong": 0}


def setup_open(conn=None):
    """The one-time setup page exists only while the administrators table is EMPTY (any row, active or not, closes it for good)."""
    own = conn is None
    conn = conn or database.get_connection()
    try:
        return conn.execute("SELECT COUNT(*) FROM admins").fetchone()[0] == 0
    finally:
        if own:
            conn.close()


def setup_code():
    """The code that must be typed on the setup page. It exists only in memory of this running server and is shown only in the terminal that started it,
    so only somebody with access to that terminal can create the first administrator. None once an administrator exists."""
    if not setup_open():
        _setup["code"] = None
        return None
    if _setup["code"] is None:
        _setup["code"] = secrets.token_hex(6).upper()
        _setup["wrong"] = 0
    return _setup["code"]


def create_first_admin(username, password):
    """Create the FIRST administrator, atomically: the table is checked and written inside one write transaction, so two simultaneous requests can never both succeed."""
    username = (username or "").strip()
    if not USERNAME_PATTERN.match(username):
        raise AuthError("The user name must be 3 to 40 characters: letters, digits, dot, dash or underscore.")
    problem = password_problem(password, username)
    if problem:
        raise AuthError(problem)
    now = database.now_str()
    conn = database.get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        if conn.execute("SELECT COUNT(*) FROM admins").fetchone()[0] != 0:
            conn.rollback()
            raise AuthError("An administrator already exists; setup is closed.")
        cur = conn.execute("INSERT INTO admins (username, password_hash, active, created_at, password_changed_at) VALUES (?, ?, 1, ?, ?)",
                           (username, hash_password(password), now, now))
        conn.commit()
        _setup["code"] = None
        return cur.lastrowid
    finally:
        conn.close()


def set_password(username, password):
    problem = password_problem(password, username)
    if problem:
        raise AuthError(problem)
    conn = database.get_connection()
    try:
        changed = conn.execute("UPDATE admins SET password_hash = ?, password_changed_at = ? WHERE username = ?",
                               (hash_password(password), database.now_str(), username)).rowcount
        conn.commit()
        if changed != 1:
            raise AuthError("There is no administrator with that name.")
    finally:
        conn.close()


def set_active(username, active):
    conn = database.get_connection()
    try:
        changed = conn.execute("UPDATE admins SET active = ? WHERE username = ?", (1 if active else 0, username)).rowcount
        conn.commit()
        if changed != 1:
            raise AuthError("There is no administrator with that name.")
    finally:
        conn.close()


def list_admins():
    conn = database.get_connection()
    try:
        return [dict(r) for r in conn.execute("SELECT id, username, active, created_at, last_login_at, password_changed_at FROM admins ORDER BY id")]
    finally:
        conn.close()


@login_manager.user_loader
def load_admin(user_id):
    try:
        number, _, fingerprint = (user_id or "").partition(":")
        number = int(number)
    except ValueError:
        return None
    conn = database.get_connection()
    try:
        row = conn.execute("SELECT * FROM admins WHERE id = ? AND active = 1", (number,)).fetchone()
    finally:
        conn.close()
    if row is None or not hmac.compare_digest(_fingerprint(row["password_hash"]), fingerprint):
        return None
    return Admin(row)


# ---- sign-in attempts and the rate limit -------------------------------------------------------------------------------------
def _stamp(moment):
    return moment.strftime(database.TIME_FORMAT)


def lockout_seconds(conn, ip, username, now):
    """Seconds the caller must wait before another attempt is looked at (0 = go ahead). A failed attempt counts for FIFTEEN minutes; five
    from one address, or ten for one name from anywhere, lock sign-in until enough of them have aged out. Refused attempts are not counted,
    so waiting is never extended by trying."""
    since = _stamp(now - timedelta(minutes=LOGIN_WINDOW_MINUTES))
    waits = [0]
    for column, value, limit in (("ip", ip or "", LOGIN_MAX_FAILURES_PER_IP), ("username", (username or "").lower(), LOGIN_MAX_FAILURES_PER_USERNAME)):
        stamps = [r[0] for r in conn.execute("SELECT attempted_at FROM login_attempts WHERE success = 0 AND " + column + " = ? AND attempted_at >= ? "
                                             "ORDER BY attempted_at", (value, since))]
        if len(stamps) >= limit:
            blocking = datetime.strptime(stamps[len(stamps) - limit], database.TIME_FORMAT)
            waits.append(int((blocking + timedelta(minutes=LOGIN_WINDOW_MINUTES) - now).total_seconds()) + 1)
    return max(waits)


def record_attempt(conn, ip, username, success, now):
    conn.execute("INSERT INTO login_attempts (username, ip, attempted_at, success) VALUES (?, ?, ?, ?)",
                 ((username or "").lower()[:80], (ip or "")[:64], _stamp(now), 1 if success else 0))
    conn.execute("DELETE FROM login_attempts WHERE attempted_at < ?", (_stamp(now - timedelta(days=ATTEMPT_RETENTION_DAYS)),))
    conn.commit()


def check_credentials(username, password):
    """The Admin for a correct name + password, else None. Always spends the same work, so the answer time does not reveal whether the
    name exists."""
    conn = database.get_connection()
    try:
        row = conn.execute("SELECT * FROM admins WHERE username = ? AND active = 1", (username,)).fetchone()
    finally:
        conn.close()
    stored = row["password_hash"] if row is not None else _dummy()
    correct = check_password_hash(stored, password)
    return Admin(row) if (row is not None and correct) else None


# ---- the redirect target after signing in ------------------------------------------------------------------------------------
def safe_next(target):
    """Only a path on this site: never another host, never a scheme, never '//'."""
    if not target or not isinstance(target, str) or len(target) > 300:
        return None
    parts = urlsplit(target)
    if parts.scheme or parts.netloc or not target.startswith("/") or target.startswith("//") or "\\" in target or "\n" in target or "\r" in target:
        return None
    path = parts.path
    root = request.script_root if has_request_context() else ""
    if root and path.startswith(root + "/"):
        path = path[len(root):]                       # under a proxy sub-path the target carries the prefix; the sign-in pages are tested without it
    if path.startswith("/login") or path.startswith("/logout"):
        return None
    return target


# ---- sessions ----------------------------------------------------------------------------------------------------------------
def _session_expired():
    now = time.time()
    started = session.get("login_at")
    last = session.get("last_activity")
    if not isinstance(started, (int, float)) or not isinstance(last, (int, float)):
        return True                                    # a session without our own timestamps is not one we created
    return now - started > config.SESSION_MAX_HOURS * 3600 or now - last > config.SESSION_IDLE_MINUTES * 60


def session_is_valid():
    """True for a signed-in administrator whose session is within its lifetime. An expired one is ended here."""
    if not current_user.is_authenticated:
        return False
    if _session_expired():
        logout_user()
        session.clear()
        return False
    return True


def touch_session():
    # the page refreshes itself every few seconds; only a real request of the person counts as activity
    if not request.headers.get("X-Background-Poll"):
        session["last_activity"] = time.time()


def _wants_json():
    return request.path.startswith("/api/")


def unauthorized():
    if _wants_json():
        response = jsonify({"ok": False, "error": "login required"})
        response.status_code = 401
        return response
    if request.method == "GET":
        target = request.script_root + request.full_path.rstrip("?")        # the path as the browser sees it (with the proxy prefix, if any)
        return redirect(url_for("auth.login", next=safe_next(target)) if safe_next(target) else url_for("auth.login"))
    return redirect(url_for("auth.login"))


login_manager.session_protection = "strong"
login_manager.unauthorized_handler(unauthorized)


# ---- one decision point for every request ------------------------------------------------------------------------------------
def guard():
    """Deny by default. Open: static files, routes marked sensor_api / public, and routes that do their own check (handles_own_auth)."""
    if not enforced():
        return None
    endpoint = request.endpoint
    if endpoint is None or endpoint == "static":
        return None
    view = current_app.view_functions.get(endpoint)
    if getattr(view, "is_sensor_api", False) or getattr(view, "is_public", False) or getattr(view, "handles_own_auth", False):
        return None
    if not session_is_valid():
        return unauthorized()
    touch_session()
    return None


def admin_or_api_key(view):
    """An administrative API action (revoking a sensor): the organisation API key when one is configured (scripts), otherwise a signed-in
    administrator who also sends the CSRF token. Never the 'no key configured' open door."""

    @wraps(view)
    def wrapper(*args, **kwargs):
        supplied = request.headers.get("X-Api-Key", "")
        if config.API_KEY and supplied and hmac.compare_digest(supplied.encode("utf-8"), config.API_KEY.encode("utf-8")):
            return view(*args, **kwargs)
        if enforced():
            if not session_is_valid():
                return unauthorized()
            touch_session()
            csrf.protect()                                   # raises CSRFError for a missing or wrong token
        elif config.API_KEY:
            # tests only (dashboard protection switched off): the organisation key rule of earlier phases still applies
            return jsonify({"ok": False, "error": "invalid or missing API key"}), 401
        return view(*args, **kwargs)

    wrapper.handles_own_auth = True
    csrf.exempt(wrapper)                                    # the check above replaces the global one for this route
    return wrapper


def add_headers(response):
    if request.endpoint != "static":
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    return response


def init_app(app):
    problems = startup_problems(config.HOST, config.API_KEY, config.SECRET_KEY, config.TEST_MODE)
    if problems:
        raise RuntimeError("Refusing to start: " + " | ".join(problems))
    app.config["SECRET_KEY"] = config.SECRET_KEY
    app.config["SESSION_COOKIE_NAME"] = "wm_session"
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = config.SESSION_COOKIE_SECURE
    app.config["REMEMBER_COOKIE_DURATION"] = timedelta(seconds=0)
    app.config["WTF_CSRF_TIME_LIMIT"] = None                 # a token lives as long as the session, not one hour
    app.config["WTF_CSRF_ENABLED"] = not config.TEST_MODE   # the existing test suites post forms without tokens; the tests of this phase enable it
    if config.TEST_MODE:
        app.config.setdefault("AUTH_TEST_BYPASS", True)
    login_manager.init_app(app)
    app.before_request(guard)                               # registered before CSRFProtect's own check: an anonymous request is turned away first
    csrf.init_app(app)
    app.after_request(add_headers)
    app.register_blueprint(bp)

    @app.errorhandler(CSRFError)
    def csrf_failed(error):
        if _wants_json():
            response = jsonify({"ok": False, "error": "security token missing or invalid; reload the page"})
            response.status_code = 400
            return response
        return render_template("auth_error.html", message="The security token of this form is missing or has expired. Reload the page and try again."), 400


# ---- the pages ---------------------------------------------------------------------------------------------------------------
@bp.route("/login", methods=["GET", "POST"])
@public
def login():
    if enforced() and current_user.is_authenticated and session_is_valid():
        return redirect(safe_next(request.args.get("next")) or url_for("dashboard"))
    no_admin = admin_count() == 0
    next_target = safe_next(request.values.get("next"))
    if request.method == "GET":
        return render_template("login.html", no_admin=no_admin, next=next_target, setup_done=request.args.get("setup") == "done")

    username = (request.form.get("username") or "").strip()[:80]
    password = (request.form.get("password") or "")[:MAX_PASSWORD_LENGTH + 1]
    ip = request.remote_addr or ""
    now = datetime.now()
    conn = database.get_connection()
    try:
        wait = lockout_seconds(conn, ip, username, now)
        if wait > 0:
            minutes = max(1, (wait + 59) // 60)
            response = current_app.make_response(render_template(
                "login.html", no_admin=no_admin, next=next_target, username=username,
                error="Too many failed attempts. Try again in %d minute%s." % (minutes, "" if minutes == 1 else "s")))
            response.status_code = 429
            response.headers["Retry-After"] = str(wait)
            return response
        admin = check_credentials(username, password) if len(password) <= MAX_PASSWORD_LENGTH else None
        record_attempt(conn, ip, username, admin is not None, now)
        if admin is None:
            response = current_app.make_response(render_template("login.html", no_admin=no_admin, next=next_target, username=username,
                                                                 error="Invalid user name or password."))
            response.status_code = 401
            return response
        conn.execute("DELETE FROM login_attempts WHERE success = 0 AND ip = ? AND username = ?", (ip[:64], username.lower()[:80]))
        conn.execute("UPDATE admins SET last_login_at = ? WHERE id = ?", (_stamp(now), admin.id))
        conn.commit()
    finally:
        conn.close()
    session.clear()                                         # a new session for a new sign-in: nothing from before is kept (session fixation)
    login_user(admin, remember=False, fresh=True)
    session["login_at"] = time.time()
    session["last_activity"] = time.time()
    return redirect(next_target or url_for("dashboard"))


@bp.route("/setup", methods=["GET", "POST"])
@public
def setup():
    """First-run only: create the first administrator in the browser. 404 as soon as any administrator exists. Needs the setup code printed in the server's terminal
    (so a stranger who reaches the port first cannot take the account), a strong password typed twice, and the normal CSRF token."""
    if not setup_open():
        abort(404)
    expected = setup_code()
    if request.method == "GET":
        return render_template("setup.html")
    form = request.form
    username = (form.get("username") or "").strip()[:80]
    if _setup["wrong"] >= SETUP_MAX_WRONG_CODES:
        response = current_app.make_response(render_template("setup.html", username=username, error="Too many wrong setup codes. Stop the server and start it again to get a new code."))
        response.status_code = 429
        return response
    supplied = (form.get("code") or "").strip().upper()[:64]
    if not hmac.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8")):
        _setup["wrong"] += 1
        response = current_app.make_response(render_template("setup.html", username=username, error="The setup code is wrong. It is printed in the terminal where the server was started."))
        response.status_code = 403
        return response
    password = (form.get("password") or "")[:MAX_PASSWORD_LENGTH + 1]
    if password != (form.get("confirm") or "")[:MAX_PASSWORD_LENGTH + 1]:
        response = current_app.make_response(render_template("setup.html", username=username, error="The two passwords are different."))
        response.status_code = 400
        return response
    try:
        create_first_admin(username, password)
    except AuthError as error:
        response = current_app.make_response(render_template("setup.html", username=username, error=str(error)))
        response.status_code = 400
        return response
    return redirect(url_for("auth.login", setup="done"))


@bp.route("/logout", methods=["POST"])
def logout():
    logout_user()
    session.clear()
    return redirect(url_for("auth.login"))
