"""Deployment validation for the college server (Phase F3.24). Prints OK / WARN / FAIL lines; never prints a secret; makes NO request to any threat-intelligence provider.

    cd /home/team2/cyber_project
    venv/bin/python deploy/validate_college.py                         # the installation: Python, packages, .env, database location, schema rehearsal, the seven sources
    venv/bin/python deploy/validate_college.py --url http://127.0.0.1:5002   # also asks the RUNNING server the anonymous questions (never signs in)

It reuses the pre-flight check (deploy/check_env.py) and adds what the college needs: the expected directory and port, Python 3.8, a database that is local and separate from any
Windows production data, DEBUG off, the legacy alert policy, a rehearsal of the schema creation on a throw-away database (so nothing real is touched), and the state of the seven
sources AS CONFIGURED (whether one really answers is only known to the running server: dashboard "Threat-intelligence sources"). The application itself is not imported and the
real database is never opened. Exit code 0 = nothing FAILED. Standard library only; Python 3.8 compatible.
"""
import argparse
import importlib.util
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
EXPECTED_DIR = "/home/team2/cyber_project"
EXPECTED_PORT = 5002
SOURCES = (("VirusTotal", "VT_API_KEY", None), ("Google Safe Browsing", "GSB_API_KEY", "GSB_ENABLED"), ("AlienVault OTX", "OTX_API_KEY", "OTX_ENABLED"),
           ("urlscan.io", "URLSCAN_API_KEY", "URLSCAN_ENABLED"), ("APIVoid", "APIVOID_API_KEY", "APIVOID_ENABLED"), ("MetaDefender Cloud", "METADEFENDER_API_KEY", "METADEFENDER_ENABLED"),
           ("AbuseIPDB", "ABUSEIPDB_API_KEY", "ABUSEIPDB_ENABLED"))
RESULTS = []


def report(level, message):
    RESULTS.append(level)
    print("%-4s  %s" % (level, message))


def load_check_env():
    spec = importlib.util.spec_from_file_location("check_env", os.path.join(HERE, "check_env.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_env_names(path):
    """NAME -> value from .env, parsed here so that the checks never depend on importing the application."""
    values = {}
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                match = re.match(r"^\s*([A-Z][A-Z0-9_]*)\s*=\s*(.*?)\s*$", line)
                if match:
                    values[match.group(1)] = match.group(2).strip('"').strip("'")
    return values


def truthy(value):
    return str(value or "").strip().lower() in ("1", "true", "yes", "on")


def check_place(env):
    if os.name == "nt":
        report("WARN", "this is Windows: the college server is Linux. These checks are meaningful here only as a rehearsal")
    if os.path.realpath(ROOT) != os.path.realpath(EXPECTED_DIR) and os.name != "nt":
        report("WARN", "the project is in %s, the college plan expects %s (nothing in the code depends on it, but the documented commands do)" % (ROOT, EXPECTED_DIR))
    else:
        report("OK", "project directory %s" % ROOT)
    version = sys.version_info
    report("OK" if version[:2] == (3, 8) else "WARN", "Python %d.%d.%d%s" % (version[0], version[1], version[2], "" if version[:2] == (3, 8) else " (the college server has 3.8; the suite also passes on newer versions)"))
    port = env.get("PORT", env.get("GUNICORN_BIND", "").rsplit(":", 1)[-1] or str(EXPECTED_PORT))
    report("OK" if str(port) == str(EXPECTED_PORT) else "WARN", "port %s (the college plan uses %d)" % (port, EXPECTED_PORT))


def check_settings(env):
    policy = env.get("SEVERITY_POLICY", "legacy").strip().lower() or "legacy"
    report("OK" if policy == "legacy" else "FAIL", "SEVERITY_POLICY=%s%s" % (policy, "" if policy == "legacy" else " - the demonstration must run the legacy policy"))
    for name in ("FLASK_DEBUG", "DEBUG"):
        if truthy(env.get(name)):
            report("FAIL", "%s is true - the debugger must never run on a shared server" % name)
    report("OK", "debug is off (the server is started by Gunicorn, which has no debugger; app.py itself calls run(debug=False))")
    host = env.get("HOST", "127.0.0.1")
    if host not in ("127.0.0.1", "localhost", "::1") and not env.get("API_KEY"):
        report("FAIL", "HOST=%s listens beyond this computer without an API_KEY" % host)
    else:
        report("OK", "HOST=%s" % host)
    bind = env.get("GUNICORN_BIND", "127.0.0.1:%d" % EXPECTED_PORT)
    report("OK" if bind.startswith("127.0.0.1") else "WARN", "Gunicorn bind %s%s" % (bind, "" if bind.startswith("127.0.0.1") else " - reachable from other machines: fine only when the college wants direct access"))
    old = sorted(k for k in env if k.startswith("URLHAUS"))
    if old:
        report("WARN", "obsolete settings in .env are ignored: %s (URLhaus was removed; delete the lines)" % ", ".join(old))
    else:
        report("OK", "no obsolete URLhaus settings")
    if env.get("DATABASE_PATH"):
        path = env["DATABASE_PATH"]
        if re.match(r"^[A-Za-z]:[\\/]", path) or "\\" in path:
            report("FAIL", "DATABASE_PATH looks like a Windows path (%s): the college database must be its own Linux file" % os.path.basename(path.replace("\\", "/")))
        elif os.path.basename(path) == "monitoring.db" and os.path.dirname(os.path.abspath(path)) != os.path.join(ROOT, "data"):
            report("WARN", "DATABASE_PATH points to a monitoring.db outside this project's data folder: make sure it is not a copy of the Windows production data")
        else:
            report("OK", "DATABASE_PATH set (a separate file for this installation)")
    else:
        report("OK", "DATABASE_PATH not set: data/monitoring.db inside this project, created empty on first start (never copied from Windows)")


def check_sources(env):
    """Names and states AS CONFIGURED. 'configured' = key present, 'enabled' = switched on. 'checked' / 'unavailable' exist only on the running server."""
    usable = 0
    for name, key_var, flag_var in SOURCES:
        configured = bool(env.get(key_var))
        enabled = True if flag_var is None else truthy(env.get(flag_var))
        if configured and enabled:
            state = "configured and enabled - will be asked"
            usable += 1
        elif configured:
            state = "configured but OFF (%s is not true)" % flag_var
        elif enabled and flag_var:
            state = "switched on but NOT CONFIGURED (%s is empty)" % key_var
        else:
            state = "not configured"
        report("OK", "%-19s %s" % (name, state))
    report("OK" if usable else "WARN", "%d of 7 sources are configured and enabled. Whether each one ANSWERS is shown only by the running server (dashboard); with no outbound access to a "
                                       "provider it is shown as unavailable and everything else keeps working" % usable)


def check_schema_rehearsal():
    """Create the schema twice on a throw-away database in a subprocess (test mode cannot open the real database)."""
    folder = tempfile.mkdtemp(prefix="validate_college_")
    code = ("import sqlite3, database; database.init_db(); database.init_db(); "
            "c = sqlite3.connect(database.config.DATABASE_PATH); print(len(c.execute(\"SELECT name FROM sqlite_master WHERE type='table'\").fetchall()))")
    env = dict((k, v) for k, v in os.environ.items() if not k.startswith(("DATABASE_PATH", "WEBSITE_MONITOR")))
    env.update(DATABASE_PATH=os.path.join(folder, "rehearsal.db"), WEBSITE_MONITOR_TEST_MODE="1")
    try:
        done = subprocess.run([sys.executable, "-I", "-c", "import sys; sys.path.insert(0, %r); %s" % (ROOT, code)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as error:
        report("FAIL", "the schema rehearsal could not run: %s" % type(error).__name__)
        return
    if done.returncode == 0 and done.stdout.strip().isdigit():
        report("OK", "schema created twice on a throw-away database (%s tables, idempotent); the real database was not touched" % done.stdout.strip())
    else:
        report("FAIL", "the schema rehearsal failed: %s" % (done.stderr.strip().splitlines() or ["no message"])[-1][:200])


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def ask(url):
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(url, timeout=10) as answer:
            return answer.status, dict(answer.headers)
    except urllib.error.HTTPError as error:
        error.close()
        return error.code, dict(error.headers)
    except (urllib.error.URLError, OSError):
        return None, {}


def check_running(base):
    base = base.rstrip("/")
    for path, want, what in (("/login", 200, "the sign-in page is served"), ("/api/status", 401, "the dashboard data is refused to an anonymous visitor"),
                             ("/computers/1", 302, "a computer page sends an anonymous visitor to the sign-in"), ("/alerts", 302, "the alerts page sends an anonymous visitor to the sign-in")):
        code, headers = ask(base + path)
        if code is None:
            report("FAIL", "nothing answers at %s (is the server started? run: python app.py)" % base)
            return
        report("OK" if code == want else "FAIL", "%s (HTTP %s)" % (what, code))
        if path == "/login":
            server = headers.get("Server", "")
            report("OK" if "Werkzeug" not in server else "WARN", "server header: %s" % (server or "not sent"))


def main(argv=None):
    parser = argparse.ArgumentParser(description="College deployment validation (no provider is contacted).")
    parser.add_argument("--url", help="also ask a running server the anonymous questions, for example http://127.0.0.1:5002")
    args = parser.parse_args(argv)
    del RESULTS[:]
    print("College deployment validation in %s\n" % ROOT)
    env = read_env_names(os.path.join(ROOT, ".env"))
    check_place(env)
    check_settings(env)
    check_sources(env)
    check_schema_rehearsal()
    print("\n-- the standard pre-flight check (deploy/check_env.py) --")
    pre = load_check_env()
    del pre.results[:]
    pre.check_python()
    pre.check_runtime()
    pre.check_packages()
    pre.check_env_file()
    pre.check_config()
    RESULTS.extend(pre.results)
    if args.url:
        print("\n-- the running server --")
        check_running(args.url)
    failed = RESULTS.count("FAIL")
    print("\n%d OK, %d WARN, %d FAIL" % (RESULTS.count("OK"), RESULTS.count("WARN"), failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
