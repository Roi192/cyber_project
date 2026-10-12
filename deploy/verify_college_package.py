"""Independent end-to-end check of the staged COLLEGE package (Phase F3.29). It runs the package as the college will: `python app.py`, in a fresh copy, with no .env.

    venv\\Scripts\\python.exe deploy\\verify_college_package.py C:\\Users\\Moshe\\cyber_project_college\\cyber_project [--python PATH]

The package is copied to a temporary folder (the staging folder and the real project are never touched), and its own interpreter-level dependencies come from the Python you run
this with (--python selects another, for example a clean virtual environment). It checks, in order: the package contents; a clean import of every module; the first start
(.env created, mode, database created, start-up report, setup code); the first-run administrator setup over HTTP (CSRF, wrong code, weak password, success, closed afterwards);
sign-in, every page, the static files and the seven-source report; a second copy refused while the first runs; graceful shutdown; a restart that keeps the database, the
administrator and the .env; a private .env being honoured (fake keys: no network call at start, nothing leaked); the secret-leak scan of every file and of the server's output.
No provider is contacted (no key is real, nothing is asked at start-up). Port: --port (default 5392; never 5002). Exit code 0 = every check passed.
"""
import argparse
import http.cookiejar
import os
import re
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULES = ["config", "database", "auth", "validation", "overview", "analytics", "devices", "bootstrap", "app"]
PAGES = ["/", "/alerts", "/browsing", "/endpoints", "/shadow"]
SOURCES = ("VirusTotal", "Google Safe Browsing", "AlienVault OTX", "urlscan.io", "APIVoid", "MetaDefender Cloud", "AbuseIPDB")
PASSWORD = "Verify-Only-Pass-2026"          # for the throw-away copy only
results = []


def check(ok, text):
    results.append(ok)
    print("%-4s  %s" % ("OK" if ok else "FAIL", text))
    return ok


class Server(object):
    def __init__(self, python, folder, port, extra_env=None):
        env = dict((k, v) for k, v in os.environ.items() if not k.startswith(("WEBSITE_MONITOR", "DATABASE_PATH", "SECRET_KEY", "API_KEY", "VT_API_KEY", "HOST", "REQUESTS_CA", "SSL_CERT")))
        env.update({"PORT": str(port), "PYTHONUNBUFFERED": "1", "PYTHONDONTWRITEBYTECODE": "1"})
        env.update(extra_env or {})
        flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        self.log = tempfile.NamedTemporaryFile(prefix="college_server_", suffix=".log", delete=False)
        self.proc = subprocess.Popen([python, "app.py"], cwd=folder, env=env, stdout=self.log, stderr=subprocess.STDOUT, creationflags=flags)
        self.port = port

    def output(self):
        self.log.flush()
        with open(self.log.name, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()

    def wait_ready(self, seconds=40):
        end = time.time() + seconds
        while time.time() < end:
            if self.proc.poll() is not None:
                return False
            try:
                with urllib.request.urlopen("http://127.0.0.1:%d/login" % self.port, timeout=2) as answer:
                    if answer.status == 200:
                        return True
            except (urllib.error.URLError, OSError):
                time.sleep(0.4)
        return False

    def stop(self):
        """Ask politely (Ctrl+Break on Windows, SIGTERM elsewhere); returns the exit code, or None if it had to be killed."""
        if self.proc.poll() is None:
            try:
                self.proc.send_signal(signal.CTRL_BREAK_EVENT if os.name == "nt" else signal.SIGTERM)
            except (OSError, ValueError):
                pass
            try:
                self.proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
                return None
        return self.proc.returncode


class Browser(object):
    def __init__(self, port):
        self.base = "http://127.0.0.1:%d" % port
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar), NoRedirect())

    def get(self, path):
        try:
            with self.opener.open(self.base + path, timeout=20) as answer:
                return answer.status, answer.read().decode("utf-8", "replace"), dict(answer.headers)
        except urllib.error.HTTPError as error:
            body = error.read().decode("utf-8", "replace")
            headers = dict(error.headers)
            error.close()
            return error.code, body, headers

    def post(self, path, data):
        body = urllib.parse.urlencode(data).encode("utf-8")
        try:
            with self.opener.open(urllib.request.Request(self.base + path, data=body), timeout=30) as answer:
                return answer.status, answer.read().decode("utf-8", "replace"), dict(answer.headers)
        except urllib.error.HTTPError as error:
            text = error.read().decode("utf-8", "replace")
            headers = dict(error.headers)
            error.close()
            return error.code, text, headers

    def token(self, path):
        status, page, _ = self.get(path)
        match = re.search(r'name="csrf_token" value="([^"]+)"', page)
        return match.group(1) if match else ""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def free_port(preferred):
    for port in range(preferred, preferred + 30):
        probe = socket.socket()
        try:
            probe.bind(("127.0.0.1", port))
            return port
        except OSError:
            continue
        finally:
            probe.close()
    raise SystemExit("no free port near %d" % preferred)


def env_values(path):
    values = {}
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            match = re.match(r"^([A-Z][A-Z0-9_]*)=(.*)$", line.rstrip("\r\n"))
            if match:
                values[match.group(1)] = match.group(2)
    return values


def main(argv=None):
    parser = argparse.ArgumentParser(description="End-to-end check of the college package.")
    parser.add_argument("package")
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--port", type=int, default=5392)
    args = parser.parse_args(argv)
    package = os.path.abspath(args.package)
    if args.port == 5002:
        raise SystemExit("port 5002 is the real monitor; this check never uses it")
    work = tempfile.mkdtemp(prefix="college_verify_")
    folder = os.path.join(work, "cyber_project")
    shutil.copytree(package, folder)
    port = free_port(args.port)
    print("Verifying %s in %s (port %d, Python %s)\n" % (package, folder, port, subprocess.check_output([args.python, "-c", "import platform;print(platform.python_version())"], universal_newlines=True).strip()))

    # 1. contents ---------------------------------------------------------------------------------------------------------------
    names = set()
    for base, dirs, files in os.walk(folder):
        names.update(dirs)
        names.update(files)
    for forbidden in (".env", "venv", "data", "tests", "agent", "browser_extension", "requirements-lock.txt", "gunicorn.conf.py", "__pycache__"):
        check(forbidden not in names, "the package contains no '%s'" % forbidden)
    check(not [n for n in names if n.endswith((".db", ".pem", ".crx", ".log", ".pyc"))], "no database, key, log or cache file in the package")
    requirements = [l for l in open(os.path.join(folder, "requirements.txt"), encoding="utf-8").read().splitlines() if l.strip() and not l.startswith("#")]
    check(os.path.isfile(os.path.join(folder, "requirements.txt")) and len([n for n in os.listdir(folder) if n.startswith("requirements")]) == 1, "exactly one requirements file (%d pinned lines)" % len(requirements))
    check(all("==" in l for l in requirements) and not any(re.match(r"(?i)^(gunicorn|colorama|pywin32|psutil|reportlab)\b", l) for l in requirements), "every requirement is pinned; no Gunicorn or Windows-only package")
    for rel in ("app.py", "config.py", "templates/base.html", "static/css/style.css", "services/reputation.py"):
        check(os.path.isfile(os.path.join(folder, rel)), "required file present: " + rel)

    # 2. clean import ------------------------------------------------------------------------------------------------------------
    scratch = tempfile.mkdtemp(prefix="college_import_")
    env = dict((k, v) for k, v in os.environ.items() if k not in ("HOST", "PORT", "API_KEY", "SECRET_KEY"))          # the surrounding environment (a container sets HOST) must not leak in
    env.update(WEBSITE_MONITOR_TEST_MODE="1", DATABASE_PATH=os.path.join(scratch, "import.db"), PYTHONDONTWRITEBYTECODE="1")
    done = subprocess.run([args.python, "-I", "-c", "import sys; sys.path.insert(0, %r); [__import__(m) for m in %r]; print('imported')" % (folder, MODULES)], cwd=scratch, env=env,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    check(done.returncode == 0 and "imported" in done.stdout, "every module imports cleanly in an isolated interpreter%s" % ("" if done.returncode == 0 else ": " + done.stderr.strip().splitlines()[-1][:160]))

    # 3. first start -------------------------------------------------------------------------------------------------------------
    server = Server(args.python, folder, port)
    ready = server.wait_ready()
    out = server.output()
    check(ready, "python app.py starts and answers on the port with no .env, no database and no extra command")
    if not ready:
        print(out[-1500:])
        return 1
    env_path = os.path.join(folder, ".env")
    values = env_values(env_path) if os.path.isfile(env_path) else {}
    check(os.path.isfile(env_path) and len(values.get("SECRET_KEY", "")) == 64 and len(values.get("API_KEY", "")) == 48, ".env was created with new random SECRET_KEY and API_KEY")
    check(all(not values.get(k) for k in ("VT_API_KEY", "GSB_API_KEY", "OTX_API_KEY", "APIVOID_API_KEY", "METADEFENDER_API_KEY", "ABUSEIPDB_API_KEY")), "the generated .env has no provider key")
    if os.name != "nt":
        check((os.stat(env_path).st_mode & 0o077) == 0, ".env is mode 600 (team2 only)")
    db_path = os.path.join(folder, "data", "monitoring.db")
    check(os.path.isfile(db_path), "the SQLite database was created in data/")
    check("NEW, created now" in out and "Alert policy  : legacy" in out and "Python " in out, "the start-up report names the database (new) and the legacy alert policy")
    check(all(name in out for name in SOURCES) and "URLhaus" not in out, "the start-up report lists the seven sources and no URLhaus")
    match = re.search(r"setup code: ([0-9A-F]{12})", out)
    check(bool(match), "a one-time setup code is printed in the terminal")
    code = match.group(1) if match else ""
    check(values.get("SECRET_KEY", "x") not in out and values.get("API_KEY", "x") not in out, "no secret is printed in the start-up output")

    # 4. first-run administrator -------------------------------------------------------------------------------------------------
    browser = Browser(port)
    status, page, _ = browser.get("/")
    check(status == 302, "the dashboard redirects an anonymous visitor to sign-in")
    status, page, _ = browser.get("/login")
    check(status == 200 and "/setup" in page, "the login page points to the first-time setup while no administrator exists")
    status, page, _ = browser.get("/api/status")
    check(status == 401, "the dashboard API is closed to an anonymous visitor")
    status, page, _ = browser.post("/setup", {"code": code, "username": "owner", "password": PASSWORD, "confirm": PASSWORD})
    check(status == 400, "a setup form without the security token is refused")
    token = browser.token("/setup")
    status, page, _ = browser.post("/setup", {"csrf_token": token, "code": "000000000000", "username": "owner", "password": PASSWORD, "confirm": PASSWORD})
    check(status == 403, "a wrong setup code is refused")
    status, page, _ = browser.post("/setup", {"csrf_token": browser.token("/setup"), "code": code, "username": "owner", "password": "short", "confirm": "short"})
    check(status == 400 and "at least 12" in page, "a weak password is refused with the reason")
    status, page, headers = browser.post("/setup", {"csrf_token": browser.token("/setup"), "code": code, "username": "owner", "password": PASSWORD, "confirm": PASSWORD})
    check(status == 302 and "setup=done" in headers.get("Location", ""), "the right code and a strong password create the administrator")
    check(browser.get("/setup")[0] == 404, "the setup page is gone once the administrator exists")
    status, page, headers = browser.post("/login", {"csrf_token": browser.token("/login"), "username": "owner", "password": PASSWORD})
    check(status == 302, "the administrator can sign in")
    connection = sqlite3.connect("file:%s?mode=ro" % db_path.replace("\\", "/"), uri=True)
    admins = connection.execute("SELECT COUNT(*) FROM admins").fetchone()[0]
    tables = connection.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'").fetchone()[0]
    connection.close()
    check(admins == 1 and tables >= 15, "exactly one administrator and the full schema (%d tables) exist" % tables)

    # 5. every page ---------------------------------------------------------------------------------------------------------------
    for path in PAGES:
        status, page, _ = browser.get(path)
        check(status == 200 and "<html" in page.lower(), "page %s renders (HTTP %s)" % (path, status))
    status, dashboard, _ = browser.get("/")
    check(all(name in dashboard for name in SOURCES) and "URLhaus" not in dashboard, "the dashboard shows the seven sources and no URLhaus")
    check("0 of 7 sources are operational" in re.sub(r"<[^>]+>", "", dashboard), "with no key configured the dashboard honestly reports 0 of 7 operational")
    css = browser.get("/static/css/style.css")
    js = browser.get("/static/js/app.js")
    check(css[0] == 200 and js[0] == 200, "static files are served (CSS and JavaScript)")
    check(browser.get("/api/status")[0] == 200, "the dashboard API answers for the signed-in administrator")

    # 5b. a SIMULATED browsing event through the real sensor API (isolated database; this proves the pipeline, not real endpoint telemetry) ---------------------------------
    simulated = "simulated-visit.example.test"
    request = urllib.request.Request("http://127.0.0.1:%d/api/web-events" % port, method="POST", headers={"Content-Type": "application/json", "X-Api-Key": values.get("API_KEY", "")},
                                     data=('{"endpoint_uid": "verify-pc-0001", "computer_name": "VERIFY-PC (SIMULATED)", "browser": "Chrome", "domain": "%s", "url": "https://%s/start?token=hidden", '
                                           '"timestamp": "%s"}' % (simulated, simulated, time.strftime("%Y-%m-%dT%H:%M:%S"))).encode())
    try:
        with urllib.request.urlopen(request, timeout=30) as answer:
            posted = answer.status
            visit_id = re.search(r'"visit_id":\s*(\d+)', answer.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as error:
        posted, visit_id = error.code, None
        error.close()
    check(posted == 201 and bool(visit_id), "a simulated browsing event is accepted by the sensor API with the generated API key (HTTP %s)" % posted)
    status, page, _ = browser.get("/browsing")
    check(status == 200 and simulated in page, "the simulated event appears in Web Monitoring (/browsing)")
    status, page, _ = browser.get("/endpoints")
    check(status == 200 and "VERIFY-PC" in page, "the reporting computer appears on the Computers page")
    if visit_id:
        status, page, _ = browser.get("/visits/%s" % visit_id.group(1))
        text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", page))
        check(status == 200 and all(name in text for name in SOURCES), "the visit analysis page shows all seven sources")
        check(text.count("is not set up, so it was not asked") >= 4 and "Not configured" in text, "with no key configured the analysis says so honestly (not checked, never 'safe')")
    anonymous_post = urllib.request.Request("http://127.0.0.1:%d/api/web-events" % port, method="POST", headers={"Content-Type": "application/json"}, data=b"{}")
    try:
        urllib.request.urlopen(anonymous_post, timeout=15)
        refused = None
    except urllib.error.HTTPError as error:
        refused = error.code
        error.close()
    check(refused == 401, "the sensor API refuses a request without the API key (HTTP %s)" % refused)

    # 6. duplicate start, graceful stop -------------------------------------------------------------------------------------------
    second = Server(args.python, folder, port)
    try:
        code2 = second.proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        second.proc.kill()
        code2 = None
    check(code2 == 1 and "already in use" in second.output(), "a second copy is refused with a clear message while the first runs")
    check(Browser(port).get("/login")[0] == 200, "the first copy is unaffected by the refused second start")
    exit_code = server.stop()
    final = server.output()
    check(exit_code == 0 and "stopped cleanly" in final, "the server stops cleanly on a polite signal (exit code %s)" % exit_code)

    # 7. restart keeps everything --------------------------------------------------------------------------------------------------
    before = open(env_path, "rb").read()
    size_before = os.path.getsize(db_path)
    server2 = Server(args.python, folder, port)
    check(server2.wait_ready(), "a restart works")
    out2 = server2.output()
    check("existing, kept as it is" in out2 and "FIRST-TIME SETUP" not in out2 and "Sign in at" in out2, "the restart keeps the database, prints no setup code and asks for sign-in")
    check(open(env_path, "rb").read() == before, ".env is unchanged by the restart")
    check(Browser(port).get("/setup")[0] == 404, "the setup page stays closed after the restart")
    check(os.path.getsize(db_path) >= size_before, "the database was not recreated")
    server2.stop()

    # 8. a private .env is honoured, with fake keys ----------------------------------------------------------------------------------
    private = (open(env_path, encoding="utf-8").read() + "\nVT_API_KEY=fake-vt-key-NOT-REAL-0123456789\nGSB_ENABLED=true\nGSB_API_KEY=fake-gsb-key-NOT-REAL-0123456789\nAPIVOID_ENABLED=true\n"
               "APIVOID_API_KEY=fake-apivoid-key-NOT-REAL-0123456789\nMETADEFENDER_ENABLED=true\nMETADEFENDER_API_KEY=fake-md-key-NOT-REAL-0123456789\nABUSEIPDB_ENABLED=true\n"
               "ABUSEIPDB_API_KEY=fake-abuse-key-NOT-REAL-0123456789\nOTX_ENABLED=true\nOTX_API_KEY=fake-otx-key-NOT-REAL-0123456789\n")
    with open(env_path, "w", encoding="utf-8", newline="") as handle:
        handle.write(private)
    server3 = Server(args.python, folder, port)
    check(server3.wait_ready(), "a copied-in private .env starts normally")
    out3 = server3.output()
    check(all(("source %s: ready" % name) in out3 for name in ("VirusTotal", "Google Safe Browsing", "AlienVault OTX", "APIVoid", "MetaDefender Cloud", "AbuseIPDB")),
          "the providers configured in .env are loaded (report: ready)")
    check("fake-" not in out3, "no key value appears in the start-up output")
    server3.stop()
    # 8b. the offline demonstration, started exactly as documented (python demo.py) -----------------------------------------------------------------------------------
    demo_port = free_port(port + 1)
    demo_env = dict((k, v) for k, v in os.environ.items() if not k.startswith(("WEBSITE_MONITOR", "DATABASE_PATH", "SECRET_KEY", "API_KEY", "HOST", "PORT", "REQUESTS_CA", "SSL_CERT")))
    demo_env.update({"WM_DEMO_PASSWORD": PASSWORD, "PYTHONUNBUFFERED": "1", "PYTHONDONTWRITEBYTECODE": "1"})
    demo_log = tempfile.NamedTemporaryFile(prefix="college_demo_", suffix=".log", delete=False)
    demo = subprocess.Popen([args.python, "demo.py", "--port", str(demo_port)], cwd=folder, env=demo_env, stdout=demo_log, stderr=subprocess.STDOUT)
    demo_text = ""
    try:
        end = time.time() + 60
        ready = False
        while time.time() < end and demo.poll() is None and not ready:
            try:
                with urllib.request.urlopen("http://127.0.0.1:%d/login" % demo_port, timeout=2) as answer:
                    ready = answer.status == 200
            except (urllib.error.URLError, OSError):
                time.sleep(0.5)
        check(ready, "python demo.py starts the offline demonstration (simulated providers, no key, no network)")
        if ready:
            guest = Browser(demo_port)
            status, page, headers = guest.post("/login", {"csrf_token": guest.token("/login"), "username": "demo", "password": PASSWORD})
            check(status == 302, "the demo administrator can sign in")
            _, home, _ = guest.get("/")
            plain = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", home))
            check("SIMULATED DEMONSTRATION" in plain and "6 of 7 sources are operational" in plain and "URLhaus" not in plain, "the demo dashboard is labelled SIMULATED, shows 6 of 7 sources operational and no URLhaus")
            _, alerts, _ = guest.get("/alerts")
            check("malware-demo.example.test" in alerts, "the simulated malicious site produced an alert")
            _, browsing, _ = guest.get("/browsing")
            visit = re.search(r'href="[^"]*?/visits/(\d+)"', browsing)
            statuses = []
            if visit:
                for vid in re.findall(r'/visits/(\d+)"', browsing):
                    _, vpage, _ = guest.get("/visits/%s" % vid)
                    statuses.append(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", vpage)))
            check(any("Risk 9" in t or "Risk 100" in t for t in statuses) and any("observation only" in t for t in statuses), "the simulated malicious visit shows a critical risk and the observation-only sources")
            _, shadow, _ = guest.get("/shadow")
            check("Alert policy shadow comparison" in shadow, "Shadow Mode renders in the demo")
    finally:
        if demo.poll() is None:
            demo.terminate()
            try:
                demo.wait(timeout=15)
            except subprocess.TimeoutExpired:
                demo.kill()
        demo_log.flush()
        with open(demo_log.name, "r", encoding="utf-8", errors="replace") as handle:
            demo_text = handle.read()
    final_all = server.output() + out2 + server3.output() + demo_text
    check("Traceback" not in final_all and "Exception" not in final_all.replace("KeyboardInterrupt", ""), "no exception or traceback in any server output")

    # 9. leak scan -----------------------------------------------------------------------------------------------------------------
    secrets = [values.get("SECRET_KEY", ""), values.get("API_KEY", ""), PASSWORD] + re.findall(r"fake-[a-z]+-key-NOT-REAL-0123456789", private)
    leaked = []
    for base, dirs, files in os.walk(folder):
        for name in files:
            path = os.path.join(base, name)
            if name == ".env" or name.endswith(".db"):
                continue
            with open(path, "rb") as handle:
                data = handle.read()
            if any(s.encode("utf-8") in data for s in secrets if s):
                leaked.append(os.path.relpath(path, folder))
    check(not leaked and not any(s in final_all for s in secrets if s), "no secret or password appears in any package file or in the server output%s" % (": " + ", ".join(leaked) if leaked else ""))
    shutil.rmtree(work, ignore_errors=True)
    failed = results.count(False)
    print("\n%d checks, %d failed" % (len(results), failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
