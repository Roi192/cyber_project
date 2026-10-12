"""First-run preparation for `python app.py` (Phases F3.29 / F3.30). Imported by app.py BEFORE the configuration, and only when app.py is run as a program.

What it does, and only this:
  * checks the Python version and that the required packages are installed, and says how to fix it in plain words;
  * if there is no `.env`, it creates one from `.env.example` with a freshly generated SECRET_KEY and API_KEY (random, never printed);
  * if `.env` exists but SECRET_KEY is empty or a known placeholder, it fills in a generated one; if HOST listens beyond this computer while API_KEY is empty (the application would
    refuse to start), it generates the API_KEY; nothing else in the file is touched (comments, order, line endings, your keys);
  * on Linux/macOS it tightens a `.env` that other users could read to mode 600;
  * checks that the database folder can be written, and says what to do if not.
It never overwrites an existing value, never reads or prints a provider key, never touches the database, and does nothing at all in a test run.
Standard library only; Python 3.8 compatible (the version check itself must run on older interpreters too, so this file uses no newer syntax).
"""
import importlib.util
import os
import re
import secrets
import stat
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
IS_POSIX = os.name != "nt"
WEAK_SECRETS = ("", "change-me", "changeme", "dev-only-change-me", "secret", "password")
LOOPBACK = ("127.0.0.1", "localhost", "::1")
MINIMAL = ("HOST=127.0.0.1\nPORT=5002\nSECRET_KEY=\nAPI_KEY=\nSEVERITY_POLICY=legacy\nDATABASE_PATH=data/monitoring.db\n")
REQUIRED_MODULES = (("flask", "Flask"), ("flask_login", "Flask-Login"), ("flask_wtf", "Flask-WTF"), ("werkzeug", "Werkzeug"), ("jinja2", "Jinja2"), ("wtforms", "WTForms"),
                    ("requests", "requests"), ("dotenv", "python-dotenv"))


def _value(text, name):
    match = re.search(r"(?m)^[ \t]*%s[ \t]*=[ \t]*(.*?)[ \t]*\r?$" % re.escape(name), text)
    return match.group(1).strip().strip("'\"") if match else None


def _set(text, name, value):
    """NAME=value: replaces an existing (empty) line in place, otherwise appends. Line endings are kept."""
    newline = "\r\n" if "\r\n" in text else "\n"
    pattern = re.compile(r"(?m)^[ \t]*%s[ \t]*=.*?(\r?)$" % re.escape(name))
    if pattern.search(text):
        return pattern.sub(lambda m: "%s=%s%s" % (name, value, m.group(1)), text, count=1)
    return text + ("" if text.endswith("\n") or not text else newline) + "%s=%s%s" % (name, value, newline)


def python_problem(version=None):
    version = version or sys.version_info
    if tuple(version[:2]) < (3, 8):
        return ("This program needs Python 3.8 or newer; this is Python %d.%d. Use the right interpreter to create the environment: python3.8 -m venv venv, then "
                "source venv/bin/activate and pip install -r requirements.txt." % (version[0], version[1]))
    return None


def missing_packages(finder=None):
    """[pip names] of required packages that cannot be imported in this interpreter."""
    finder = finder or importlib.util.find_spec
    missing = []
    for module, package in REQUIRED_MODULES:
        try:
            found = finder(module)
        except (ImportError, ValueError):
            found = None
        if found is None:
            missing.append(package)
    return missing


def database_problem(root=None, environ=None):
    """None if the database folder exists or can be created and written; otherwise a plain sentence with the way out. Looks at DATABASE_PATH (environment first, then .env)."""
    root = root or ROOT
    environ = os.environ if environ is None else environ
    path = (environ.get("DATABASE_PATH") or "").strip()
    env_file = os.path.join(root, ".env")
    if not path and os.path.isfile(env_file):
        with open(env_file, "r", encoding="utf-8", newline="") as handle:
            path = _value(handle.read(), "DATABASE_PATH") or ""
    path = path or os.path.join("data", "monitoring.db")
    if not os.path.isabs(path):
        path = os.path.join(root, path)
    folder = os.path.dirname(path)
    try:
        os.makedirs(folder, exist_ok=True)
        probe = os.path.join(folder, ".write_test_%d" % os.getpid())
        with open(probe, "w") as handle:
            handle.write("ok")
        os.remove(probe)
    except OSError as error:
        return ("The database folder %s cannot be written by this user (%s). Fix its ownership or permissions (chmod u+rwx), or set DATABASE_PATH in .env to a folder you own."
                % (folder, error.strerror or type(error).__name__))
    if os.path.exists(path) and not os.access(path, os.W_OK):
        return "The database file %s exists but is read-only for this user. Fix its permissions (chmod u+rw), or set DATABASE_PATH in .env to another file." % path
    return None


def ensure_environment(root=None, out=print):
    """Prepare `.env`. Returns a list of plain sentences describing what was done (empty = nothing needed)."""
    root = root or ROOT
    if os.environ.get("WEBSITE_MONITOR_TEST_MODE") == "1":
        return []
    path = os.path.join(root, ".env")
    done = []
    if not os.path.isfile(path):
        example = os.path.join(root, ".env.example")
        if os.path.isfile(example):
            with open(example, "r", encoding="utf-8", newline="") as handle:
                text = handle.read()
        else:
            text = MINIMAL
        text = _set(text, "SECRET_KEY", secrets.token_hex(32))
        text = _set(text, "API_KEY", secrets.token_hex(24))
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
        done.append("No .env was found: created one with a new random SECRET_KEY and API_KEY (provider keys are empty; add them to .env or copy your private .env here and restart).")
    else:
        with open(path, "r", encoding="utf-8", newline="") as handle:
            text = handle.read()
        changed = False
        if (_value(text, "SECRET_KEY") or "").lower() in WEAK_SECRETS:
            text = _set(text, "SECRET_KEY", secrets.token_hex(32))
            changed = True
            done.append("SECRET_KEY in .env was empty or a placeholder: generated a new random one (nothing else changed).")
        host = (os.environ.get("HOST") or _value(text, "HOST") or "127.0.0.1").strip()
        if host not in LOOPBACK and not (_value(text, "API_KEY") or "").strip() and not os.environ.get("API_KEY"):
            text = _set(text, "API_KEY", secrets.token_hex(24))
            changed = True
            done.append("HOST=%s listens beyond this computer but API_KEY was empty (the server would refuse to start): generated a random API_KEY. Put the same key in every sensor." % host)
        if changed:
            with open(path, "w", encoding="utf-8", newline="") as handle:
                handle.write(text)
    if IS_POSIX:
        try:
            mode = stat.S_IMODE(os.stat(path).st_mode)
            if mode & 0o077:
                os.chmod(path, 0o600)
                done.append(".env was readable by other users: its permissions are now 600.")
        except OSError:
            pass
    for sentence in done:
        out("[setup] " + sentence)
    return done


def preflight(root=None, out=None):
    """Everything `python app.py` checks before it starts. Returns 0 when it may continue, otherwise 1 after printing what is wrong and how to fix it."""
    out = out or (lambda text: sys.stderr.write(text + "\n"))
    if os.environ.get("WEBSITE_MONITOR_TEST_MODE") == "1":
        return 0
    problem = python_problem()
    if problem:
        out("[cannot start] " + problem)
        return 1
    missing = missing_packages()
    if missing:
        out("[cannot start] Required package(s) not installed in this Python: %s. Activate the virtual environment (source venv/bin/activate) and run: pip install -r requirements.txt. "
            "If pip cannot reach PyPI or reports a certificate error, see 'No internet, or PyPI blocked?' in README.md (never turn certificate checks off)." % ", ".join(missing))
        return 1
    ensure_environment(root, out=lambda text: sys.stdout.write(text + "\n"))
    problem = database_problem(root)
    if problem:
        out("[cannot start] " + problem)
        return 1
    return 0
