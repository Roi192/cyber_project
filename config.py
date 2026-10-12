"""Configuration - every value comes from environment variables (.env).

TEST MODE (fail-closed). Automated tests delete rows, so they must never be able to reach the real database, whatever order their modules are imported in.
Test mode is switched on by WEBSITE_MONITOR_TEST_MODE=1, or automatically when the process was started by a test runner (python -m unittest, pytest, or a script
inside this project's tests folder). In test mode:
  * the .env file is NOT read (so a test can never pick up the real database path, API key or VirusTotal key from it);
  * DATABASE_PATH must be set in the real environment, be an absolute path, lie inside the system temporary folder and never inside the project's data folder;
    otherwise importing this module raises RuntimeError - there is no fallback to the production path;
  * database.get_connection() re-checks every path it opens (assert_database_allowed), so a path changed later is refused too.
Production (python app.py, gunicorn, deploy scripts) is not a test run and behaves exactly as before; assert_database_allowed() does nothing there.
"""
import os
import sys
import tempfile

from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PRODUCTION_DATA_DIR = os.path.join(BASE_DIR, "data")


RUNNER_NAMES = ("unittest", "pytest", "py.test")


def _started_by_a_test_runner():
    """True for `python -m unittest ...` / `python -m pytest ...` (also inside `-m coverage run -m unittest`), a pytest executable, or a script that lives in
    this project's tests folder. Python 3.10+ records the real command line in sys.orig_argv; older versions put the runner's file path in sys.argv[0]."""
    orig = getattr(sys, "orig_argv", None) or []
    for flag, module in zip(orig, orig[1:]):
        if flag == "-m" and module.split(".")[0] in RUNNER_NAMES:
            return True
    if not sys.argv or not sys.argv[0]:
        return False
    zero = sys.argv[0]
    first = os.path.normcase(os.path.abspath(zero)).replace("\\", "/")
    parts = first.split("/")
    name = parts[-1]
    tests_folder = os.path.normcase(os.path.join(BASE_DIR, "tests")).replace("\\", "/") + "/"
    if first.startswith(tests_folder):
        return True
    if len(parts) >= 2 and parts[-2] in ("unittest", "pytest", "_pytest") and name.startswith("__main__"):
        return True
    if name.startswith(("pytest", "py.test")):
        return True
    return any(token in RUNNER_NAMES for token in zero.replace("/", " ").replace("\\", " ").split())      # 'python.exe -m unittest' (Python 3.14 style argv[0])


TEST_MODE = os.environ.get("WEBSITE_MONITOR_TEST_MODE") == "1" or _started_by_a_test_runner()


def _inside(path, folder):
    try:
        return os.path.commonpath([path, folder]) == folder
    except ValueError:                 # another drive
        return False


def assert_database_allowed(path):
    """Production: does nothing. Test mode: only a database file inside the system temporary folder, never the project's data folder."""
    if not TEST_MODE:
        return path
    resolved = os.path.normcase(os.path.realpath(os.path.abspath(path)))
    production = os.path.normcase(os.path.realpath(PRODUCTION_DATA_DIR))
    temporary = os.path.normcase(os.path.realpath(tempfile.gettempdir()))
    if resolved == production or _inside(resolved, production):
        raise RuntimeError("TEST MODE: refusing the production database folder (%s)" % path)
    if not _inside(resolved, temporary):
        raise RuntimeError("TEST MODE: a test database must be inside the system temporary folder (%s)" % path)
    return path


# Always the .env next to this file. A bare load_dotenv() searches from the current
# directory when Python was started interactively (python -c, a REPL), so the result
# would depend on how and from where the process is launched. Real environment
# variables still win over the file (load_dotenv does not override them).
# In test mode the file is never read.
if not TEST_MODE:
    load_dotenv(os.path.join(BASE_DIR, ".env"))


def _int(name, default):
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


# The default is this computer only. Listening on the network needs HOST=0.0.0.0 AND an API_KEY (the application refuses to start
# otherwise, see auth.startup_problems).
HOST = os.getenv("HOST", "127.0.0.1")
PORT = _int("PORT", 5002)
SECRET_KEY = os.getenv("SECRET_KEY", "dev-only-change-me")
API_KEY = os.getenv("API_KEY", "").strip()

# Behind a reverse proxy (Apache ProxyPass) every request reaches Gunicorn from the proxy's own address (127.0.0.1) and, if the site is published under a sub-path,
# without that prefix. TRUSTED_PROXY_HOPS is the number of proxies in front of Gunicorn (0 = none, the default and the only safe value when clients can reach
# Gunicorn directly: the forwarded headers can be forged then). With 1, Werkzeug's ProxyFix takes the client address, the scheme and the path prefix from the
# X-Forwarded-For / -Proto / -Prefix headers that Apache adds, so the sensor address check, the sign-in rate limit and every generated link see the real values.
TRUSTED_PROXY_HOPS = max(0, min(_int("TRUSTED_PROXY_HOPS", 0), 3))

# Administrator sessions (Phase B). The cookie is a browser-session cookie; the server also ends a session after SESSION_MAX_HOURS since
# login and after SESSION_IDLE_MINUTES without a click (background refreshes of an open page do not count as activity).
SESSION_IDLE_MINUTES = max(1, min(_int("SESSION_IDLE_MINUTES", 30), 24 * 60))
SESSION_MAX_HOURS = max(1, min(_int("SESSION_MAX_HOURS", 8), 24 * 14))
# Set to true when the dashboard is served over HTTPS (the cookie is then never sent over plain HTTP).
SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "").strip().lower() in ("1", "true", "yes", "on")

if TEST_MODE:
    _requested = os.environ.get("DATABASE_PATH", "").strip()
    if not _requested:
        raise RuntimeError("TEST MODE: DATABASE_PATH is not set. A test must point it at a temporary database BEFORE importing config, database or app "
                           "(there is deliberately no fallback to the production database).")
    if not os.path.isabs(_requested):
        raise RuntimeError("TEST MODE: DATABASE_PATH must be an absolute path (%s)" % _requested)
    DATABASE_PATH = assert_database_allowed(os.path.abspath(_requested))
else:
    DATABASE_PATH = os.path.join(BASE_DIR, os.getenv("DATABASE_PATH", "data/monitoring.db"))
RETENTION_DAYS = _int("RETENTION_DAYS", 30)
REPUTATION_CACHE_HOURS = _int("REPUTATION_CACHE_HOURS", 24)
VT_API_KEY = os.getenv("VT_API_KEY", "").strip()
# Which policy decides the alert level of a VirusTotal answer: "legacy" (the default; one malicious engine is already SUSPICIOUS and raises a MEDIUM alert) or
# "evidence" (services/evidence.py: weak single-engine findings are kept for investigation without an alert). Anything else means "legacy".
# VirusTotal request budget, shared by every source (browser extension, agent history, agent lookups). The free key allows 4 requests a minute and 500 a day; the defaults leave
# headroom. A request over the budget is answered "not checked yet" (never cached) instead of being sent.
VT_MAX_PER_MINUTE = max(1, min(_int("VT_MAX_PER_MINUTE", 3), 1000))
VT_MAX_PER_DAY = max(1, min(_int("VT_MAX_PER_DAY", 450), 100000))
# Extra reputation sources (Phase F3.1). Both are OFF unless their flag is true AND their credential is set; a flag without a credential is reported as "not configured", never as
# "safe". Google Safe Browsing (v5 hashes.search, needs a Google Cloud API key; non-commercial use only).
GSB_ENABLED = os.getenv("GSB_ENABLED", "").strip().lower() in ("1", "true", "yes", "on")
GSB_API_KEY = os.getenv("GSB_API_KEY", "").strip()
GSB_MAX_PER_MINUTE = max(1, min(_int("GSB_MAX_PER_MINUTE", 10), 1000))
GSB_MAX_PER_DAY = max(1, min(_int("GSB_MAX_PER_DAY", 1000), 100000))
# Phase F3.12: the fourth and fifth sources. Both OFF unless their flag is true AND (OTX) the key is set; a flag without what it needs is reported as "not configured", never as
# "safe". AlienVault OTX needs a free key from otx.alienvault.com (sent as the X-OTX-API-KEY header). urlscan.io searches work without a key (small quotas); a free key
# (the `api-key` header) raises the quotas, so it is optional. Only the website NAME is ever sent to either of them; nothing is ever submitted for a new public scan.
OTX_ENABLED = os.getenv("OTX_ENABLED", "").strip().lower() in ("1", "true", "yes", "on")
OTX_API_KEY = os.getenv("OTX_API_KEY", "").strip()
OTX_MAX_PER_MINUTE = max(1, min(_int("OTX_MAX_PER_MINUTE", 10), 1000))
OTX_MAX_PER_DAY = max(1, min(_int("OTX_MAX_PER_DAY", 1000), 100000))
URLSCAN_ENABLED = os.getenv("URLSCAN_ENABLED", "").strip().lower() in ("1", "true", "yes", "on")
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY", "").strip()
URLSCAN_MAX_PER_MINUTE = max(1, min(_int("URLSCAN_MAX_PER_MINUTE", 5), 1000))
URLSCAN_MAX_PER_DAY = max(1, min(_int("URLSCAN_MAX_PER_DAY", 300), 100000))
# Phase F3.22: three further sources, each OFF unless its flag is true AND its key is set (a flag without a key is "not configured", never "safe"). They are OBSERVATION-ONLY at first:
# their answers are stored and shown, but they never change a verdict, a risk score or an alert (see docs/PROVIDERS.md for the proposed mapping). The limits below are deliberately
# conservative; set them to your plan's real quota. APIVoid (the API behind URLVoid): domain reputation; MetaDefender Cloud (OPSWAT): domain reputation; AbuseIPDB: reputation of the
# public IP address the website resolves to (an IP is never the same thing as a website).
APIVOID_ENABLED = os.getenv("APIVOID_ENABLED", "").strip().lower() in ("1", "true", "yes", "on")
APIVOID_API_KEY = os.getenv("APIVOID_API_KEY", "").strip()
APIVOID_MAX_PER_MINUTE = max(1, min(_int("APIVOID_MAX_PER_MINUTE", 2), 1000))
APIVOID_MAX_PER_DAY = max(1, min(_int("APIVOID_MAX_PER_DAY", 30), 100000))
METADEFENDER_ENABLED = os.getenv("METADEFENDER_ENABLED", "").strip().lower() in ("1", "true", "yes", "on")
METADEFENDER_API_KEY = os.getenv("METADEFENDER_API_KEY", "").strip()
METADEFENDER_MAX_PER_MINUTE = max(1, min(_int("METADEFENDER_MAX_PER_MINUTE", 2), 1000))
METADEFENDER_MAX_PER_DAY = max(1, min(_int("METADEFENDER_MAX_PER_DAY", 100), 100000))
ABUSEIPDB_ENABLED = os.getenv("ABUSEIPDB_ENABLED", "").strip().lower() in ("1", "true", "yes", "on")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()
ABUSEIPDB_MAX_PER_MINUTE = max(1, min(_int("ABUSEIPDB_MAX_PER_MINUTE", 5), 1000))
ABUSEIPDB_MAX_PER_DAY = max(1, min(_int("ABUSEIPDB_MAX_PER_DAY", 300), 100000))
SEVERITY_POLICY = "evidence" if os.getenv("SEVERITY_POLICY", "legacy").strip().lower() == "evidence" else "legacy"
