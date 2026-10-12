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
MIN_SECRET_KEY_LENGTH = 24
REQUIRED_MODULES = ("flask", "werkzeug", "jinja2", "requests", "dotenv", "gunicorn", "flask_login", "flask_wtf", "wtforms")

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


MIN_SQLITE = (3, 24, 0)          # upserts (ON CONFLICT ... DO UPDATE); Ubuntu 20.04 ships 3.31
MIN_OPENSSL = (1, 1, 1)          # urllib3 2.x (pinned in requirements.txt) refuses an older OpenSSL; Ubuntu 20.04 ships 1.1.1


def check_runtime():
    import sqlite3
    import ssl
    version = tuple(int(x) for x in sqlite3.sqlite_version.split(".")[:3])
    if version < MIN_SQLITE:
        report("FAIL", "SQLite %s is older than %s: the database layer needs upserts" % (sqlite3.sqlite_version, ".".join(map(str, MIN_SQLITE))))
    else:
        report("OK", "SQLite %s" % sqlite3.sqlite_version)
    if ssl.OPENSSL_VERSION_INFO[:3] < MIN_OPENSSL:
        report("FAIL", "%s is too old for urllib3 2.x: change urllib3==2.2.3 to urllib3==1.26.20 in requirements.txt (requests 2.31 supports both) and reinstall"
               % ssl.OPENSSL_VERSION)
    else:
        report("OK", ssl.OPENSSL_VERSION)


DISTRIBUTIONS = {"flask": "Flask", "werkzeug": "Werkzeug", "jinja2": "Jinja2", "requests": "requests",
                 "dotenv": "python-dotenv", "gunicorn": "gunicorn", "flask_login": "Flask-Login", "flask_wtf": "Flask-WTF",
                 "wtforms": "WTForms"}


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
    check_providers(config)
    secret = config.SECRET_KEY or ""
    if secret in ("", "change-me", "changeme", "dev-only-change-me", "secret", "password") or len(secret) < MIN_SECRET_KEY_LENGTH:
        report("FAIL", "SECRET_KEY is missing, a placeholder or shorter than %d characters - the application refuses to start (it signs the administrator "
                       "sessions). Use: python -c \"import secrets; print(secrets.token_hex(32))\"" % MIN_SECRET_KEY_LENGTH)
    else:
        report("OK", "SECRET_KEY is set (%d characters, value not shown)" % len(secret))
    if config.HOST not in ("127.0.0.1", "localhost", "::1") and not key:
        report("FAIL", "HOST=%s listens on the network but API_KEY is empty - the application refuses to start" % config.HOST)
    hops = getattr(config, "TRUSTED_PROXY_HOPS", 0)
    if hops:
        report("OK", "TRUSTED_PROXY_HOPS=%d: the client address, scheme and /prefix come from Apache's X-Forwarded-* headers. Gunicorn must then be reachable ONLY "
                     "from Apache (bind 127.0.0.1): anybody who can reach it directly could forge those headers" % hops)
        if not key:
            report("WARN", "TRUSTED_PROXY_HOPS is set but API_KEY is empty - set API_KEY so a sensor needs the key even when it arrives through the proxy")
    else:
        report("OK", "TRUSTED_PROXY_HOPS=0 (no reverse proxy assumed; set it to 1 only when Apache forwards to Gunicorn)")
    report("OK", "RETENTION_DAYS=%s REPUTATION_CACHE_HOURS=%s" % (config.RETENTION_DAYS, config.REPUTATION_CACHE_HOURS))
    check_database_location(config.DATABASE_PATH)
    check_administrator(config.DATABASE_PATH)


def check_providers(config):
    """The seven threat-intelligence sources, as the application will use them after a restart. Names only: no value is ever printed. The classic mistakes are reported: a key
    without its switch (the source stays OFF), a switch without its key (it can do nothing)."""
    rows = (("VirusTotal", "VT_API_KEY", None, True), ("Google Safe Browsing", "GSB_API_KEY", "GSB_ENABLED", True),
            ("AlienVault OTX", "OTX_API_KEY", "OTX_ENABLED", True), ("urlscan.io", "URLSCAN_API_KEY", "URLSCAN_ENABLED", False),
            ("APIVoid (observation only)", "APIVOID_API_KEY", "APIVOID_ENABLED", True), ("MetaDefender Cloud (observation only)", "METADEFENDER_API_KEY", "METADEFENDER_ENABLED", True),
            ("AbuseIPDB (IP reputation, observation only)", "ABUSEIPDB_API_KEY", "ABUSEIPDB_ENABLED", True))
    for name, key_var, flag_var, required in rows:
        has_key = bool(getattr(config, key_var, ""))
        on = True if flag_var is None else bool(getattr(config, flag_var, False))
        if required and not has_key and on and flag_var:
            report("WARN", "%s: %s=true but %s is empty - it will be NOT CONFIGURED and ignored" % (name, flag_var, key_var))
        elif required and not has_key:
            report("OK", "%s: not configured (%s is empty) - it will not be used" % (name, key_var))
        elif has_key and not on:
            report("WARN", "%s: the key is set but %s is not true - the source stays OFF; set %s=true to use it" % (name, flag_var, flag_var))
        elif on:
            report("OK", "%s: will be used for every new website (%s%s)" % (name, "key set, value not shown" if has_key else "no key needed", "" if flag_var is None else ", " + flag_var + "=true"))
        else:
            report("OK", "%s: switched off" % name)


def check_administrator(db_path):
    """The dashboard is closed until an administrator exists. Reads the file read-only; never prints a name or a hash."""
    import sqlite3
    count = 0
    if os.path.isfile(db_path):
        try:
            conn = sqlite3.connect("file:%s?mode=ro" % db_path.replace("\\", "/"), uri=True)
            try:
                count = conn.execute("SELECT COUNT(*) FROM admins WHERE active = 1").fetchone()[0]
            finally:
                conn.close()
        except sqlite3.Error:
            count = 0
    if count:
        report("OK", "%d dashboard administrator(s) exist" % count)
    else:
        report("WARN", "no dashboard administrator exists yet - the dashboard stays closed. Run: python manage_admin.py create")


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
    # On Windows a bind to 0.0.0.0 SUCCEEDS even while a server holds 127.0.0.1:port, so "can I bind?" alone says "free" for a port that is in use. Ask by connecting first.
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.settimeout(1)
    try:
        listening = probe.connect_ex(("127.0.0.1", port)) == 0
    finally:
        probe.close()
    if listening:
        report("WARN", "TCP port %d is already in use on this machine: a server is listening there (fine if it is the running Website Monitor; otherwise pick another port)" % port)
        return
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
    check_runtime()
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
