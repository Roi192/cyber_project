"""Pre-flight check for a deployment directory. Prints OK / WARN / FAIL lines.

It NEVER prints secret values: API_KEY and VT_API_KEY are only reported as
"set" / "not set" and a length. Run it from the project directory:

    python deploy/check_env.py            # checks the .env in the project directory
    python deploy/check_env.py --port 5002

Exit code 0 when nothing FAILED (warnings are allowed), 1 otherwise.
Standard library only, Python 3.8 compatible. It does not import the Flask app, so it
never creates or touches the database.
"""
import argparse
import importlib
import os
import socket
import stat
import sys
import tempfile
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MIN_API_KEY_LENGTH = 16
REQUIRED_MODULES = ("flask", "werkzeug", "jinja2", "requests", "dotenv", "gunicorn")

results = []


def report(level, message):
    results.append(level)
    print("%-4s  %s" % (level, message))


def check_python():
    version = sys.version_info
    text = "Python %d.%d.%d" % version[:3]
    if version < (3, 8):
        report("FAIL", text + " - Python 3.8 or newer is required")
    elif version[:2] == (3, 8):
        report("OK", text + " (the target version)")
    else:
        report("OK", text)


DISTRIBUTIONS = {"flask": "Flask", "werkzeug": "Werkzeug", "jinja2": "Jinja2", "requests": "requests",
                 "dotenv": "python-dotenv", "gunicorn": "gunicorn"}


def installed_version(module_name):
    """Version from the package metadata (module.__version__ is deprecated in Flask/Werkzeug)."""
    try:
        from importlib import metadata          # standard library since Python 3.8
        return metadata.version(DISTRIBUTIONS[module_name])
    except Exception:
        return "(version unknown)"


def check_packages():
    for name in REQUIRED_MODULES:
        try:
            importlib.import_module(name)
            report("OK", "package %s %s" % (name, installed_version(name)))
        except ImportError as error:
            # gunicorn only imports on Linux/macOS; elsewhere it is only a deployment-time need
            level = "WARN" if name == "gunicorn" and os.name == "nt" else "FAIL"
            report(level, "package %s is not importable (%s). Run: python -m pip install -r requirements.txt" % (name, error))


def check_env_file():
    path = os.path.join(ROOT, ".env")
    if not os.path.isfile(path):
        report("FAIL", ".env not found in %s - copy .env.example to .env and edit it" % ROOT)
        return
    report("OK", ".env exists")
    if os.name != "nt":
        mode = stat.S_IMODE(os.stat(path).st_mode)
        if mode & 0o077:
            report("WARN", ".env is readable by other users (mode %o); run: chmod 600 .env" % mode)
        else:
            report("OK", ".env permissions %o" % mode)


def check_config():
    sys.path.insert(0, ROOT)
    try:
        import config
    except Exception as error:  # a broken .env must be reported, not crash the checker
        report("FAIL", "config could not be loaded: %s" % type(error).__name__)
        return
    key = config.API_KEY
    if not key:
        report("FAIL", "API_KEY is empty - the server would run in DEV MODE; set a long random value in .env")
    elif len(key) < MIN_API_KEY_LENGTH:
        report("FAIL", "API_KEY is only %d characters; use at least %d (python -c \"import secrets; print(secrets.token_hex(24))\")"
               % (len(key), MIN_API_KEY_LENGTH))
    else:
        report("OK", "API_KEY is set (%d characters, value not shown)" % len(key))
    if config.VT_API_KEY:
        report("OK", "VT_API_KEY is set (%d characters, value not shown) - reputation checks can run" % len(config.VT_API_KEY))
    else:
        report("WARN", "VT_API_KEY is not set - every website will be shown as Not checked (visits are still stored)")
    if config.SECRET_KEY == "dev-only-change-me":
        report("WARN", "SECRET_KEY is the development default (currently unused: the app has no sessions)")
    report("OK", "RETENTION_DAYS=%s REPUTATION_CACHE_HOURS=%s" % (config.RETENTION_DAYS, config.REPUTATION_CACHE_HOURS))
    check_database_location(config.DATABASE_PATH)


def check_database_location(db_path):
    directory = os.path.dirname(db_path)
    report("OK", "database file will be %s" % db_path)
    if os.path.exists(db_path):
        report("WARN", "a database already exists there; a fresh deployment should start with a new one")
    probe_dir = directory
    while probe_dir and not os.path.isdir(probe_dir):          # the app creates missing directories itself
        probe_dir = os.path.dirname(probe_dir)
    try:
        handle, probe = tempfile.mkstemp(prefix=".write-test-", dir=probe_dir)
        os.close(handle)
        os.remove(probe)
        report("OK", "directory %s is writable by %s" % (probe_dir, os.environ.get("USER") or os.environ.get("USERNAME") or "this user"))
    except OSError as error:
        report("FAIL", "cannot write to %s (%s)" % (probe_dir, type(error).__name__))
    if os.name != "nt":
        try:
            import subprocess
            fs = subprocess.check_output(["df", "-T", probe_dir], universal_newlines=True).splitlines()[-1].split()[1]
            if fs.lower().startswith("nfs") or fs.lower() in ("cifs", "smb", "smbfs", "fuse.sshfs"):
                report("WARN", "database directory is on a network filesystem (%s); SQLite locking is unreliable there - "
                               "set DATABASE_PATH to a local disk path" % fs)
            else:
                report("OK", "database directory filesystem: %s" % fs)
        except Exception:
            report("WARN", "could not determine the filesystem type of %s" % probe_dir)


def check_port(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("0.0.0.0", port))
        report("OK", "TCP port %d is free on this machine" % port)
    except OSError:
        report("WARN", "TCP port %d is already in use - pick another port (and use it in the extension address)" % port)
    finally:
        sock.close()


def check_clock():
    now = datetime.now()
    offset = now.astimezone().strftime("%z")                    # ASCII, for example +0300
    report("OK", "server local time %s, UTC offset %s (compare with the Windows clock; "
                 "set TZ before starting gunicorn if they differ)" % (now.strftime("%Y-%m-%d %H:%M:%S"), offset))


def main():
    parser = argparse.ArgumentParser(description="Website Monitor deployment pre-flight check")
    parser.add_argument("--port", type=int, default=5002)
    args = parser.parse_args()
    print("Website Monitor pre-flight check in %s\n" % ROOT)
    check_python()
    check_packages()
    check_env_file()
    check_config()
    check_port(args.port)
    check_clock()
    failed = results.count("FAIL")
    print("\n%d OK, %d WARN, %d FAIL" % (results.count("OK"), results.count("WARN"), failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
