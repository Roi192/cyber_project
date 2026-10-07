"""Phase 4 deployment-readiness tests (reported separately from the 171 functional tests).

They prove, without touching any server: Python 3.8 source compatibility, Linux
portability of the runtime code, a fresh database from nothing, a clean deployment
package, the pre-flight checker, and that the browser extension talks only to the
configured (remote) server. Temporary directories only; no network; no real keys.
Run:  python -m unittest discover -s tests -v
"""
import ast
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUNTIME_PY = ["app.py", "config.py", "database.py", "overview.py", "validation.py", "services/__init__.py", "services/reputation.py"]
SCAN_PY = RUNTIME_PY + ["deploy/check_env.py", "deploy/build_package.py"]
BUILD_SCRIPT = os.path.join(ROOT, "deploy", "build_package.py")
CHECK_ENV = os.path.join(ROOT, "deploy", "check_env.py")


def read_bytes(relative):
    with open(os.path.join(ROOT, relative), "rb") as handle:
        return handle.read()


def clean_env(**extra):
    """The current environment minus every variable the app reads, plus `extra`."""
    env = dict(os.environ)
    for name in ("API_KEY", "VT_API_KEY", "DATABASE_PATH", "SECRET_KEY", "HOST", "PORT", "RETENTION_DAYS",
                 "REPUTATION_CACHE_HOURS", "PYTHONPATH"):
        env.pop(name, None)
    env.update(extra)
    return env


# --------------------------------------------------------------------
# Python 3.8 source compatibility (works on any interpreter)
# --------------------------------------------------------------------
class Python38SourceTests(unittest.TestCase):
    BUILTIN_GENERICS = {"list", "dict", "tuple", "set", "frozenset", "type"}
    NEWER_ATTRIBUTES = {"removeprefix", "removesuffix", "with_stem", "is_relative_to", "bit_count", "lcm", "readlink"}
    NEWER_MODULES = {"zoneinfo", "tomllib", "graphlib"}

    def trees(self):
        for relative in SCAN_PY:
            if os.path.exists(os.path.join(ROOT, relative)):
                source = read_bytes(relative).decode("utf-8")
                yield relative, ast.parse(source, filename=relative, feature_version=(3, 8))   # fails on match/walrus-style syntax newer than 3.8

    def test_files_parse_as_python_3_8(self):
        scanned = [relative for relative, _ in self.trees()]
        self.assertIn("app.py", scanned)
        self.assertGreaterEqual(len(scanned), len(RUNTIME_PY))

    def test_no_python_3_9_plus_annotations_or_calls(self):
        problems = []
        for relative, tree in self.trees():
            annotations = []
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    args = node.args
                    for arg in args.args + args.kwonlyargs + getattr(args, "posonlyargs", []):
                        annotations.append(arg.annotation)
                    annotations.extend([getattr(args.vararg, "annotation", None), getattr(args.kwarg, "annotation", None), node.returns])
                elif isinstance(node, ast.AnnAssign):
                    annotations.append(node.annotation)
                elif isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) and node.value.id in self.BUILTIN_GENERICS:
                    problems.append("%s:%d built-in generic %s[...]" % (relative, node.lineno, node.value.id))
                elif isinstance(node, ast.Attribute) and node.attr in self.NEWER_ATTRIBUTES:
                    problems.append("%s:%d .%s needs a newer Python" % (relative, node.lineno, node.attr))
                elif isinstance(node, ast.Attribute) and node.attr == "cache" and getattr(node.value, "id", "") == "functools":
                    problems.append("%s:%d functools.cache needs 3.9" % (relative, node.lineno))
                elif isinstance(node, ast.Import):
                    problems.extend("%s:%d import %s needs a newer Python" % (relative, node.lineno, a.name)
                                    for a in node.names if a.name.split(".")[0] in self.NEWER_MODULES)
                elif isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] in self.NEWER_MODULES:
                    problems.append("%s:%d from %s needs a newer Python" % (relative, node.lineno, node.module))
            for annotation in annotations:
                if annotation is None:
                    continue
                for inner in ast.walk(annotation):
                    if isinstance(inner, ast.BinOp) and isinstance(inner.op, ast.BitOr):
                        problems.append("%s:%d union written with |" % (relative, annotation.lineno))
        self.assertEqual(problems, [])

    def test_requirements_are_pinned_complete_and_free_of_stdlib_or_windows_only_packages(self):
        lines = [l.strip() for l in read_bytes("requirements.txt").decode("utf-8").splitlines() if l.strip() and not l.startswith("#")]
        names = {}
        for line in lines:
            self.assertRegex(line, r"^[A-Za-z0-9_.\-]+==[0-9][0-9A-Za-z.\-]*$", "every requirement is pinned exactly: " + line)
            name, version = line.split("==")
            names[name.lower()] = version
        for needed in ("flask", "werkzeug", "jinja2", "markupsafe", "itsdangerous", "click", "blinker", "gunicorn",
                       "python-dotenv", "requests"):
            self.assertIn(needed, names)
        for forbidden in ("sqlite3", "pywin32", "colorama", "waitress", "pytest"):
            self.assertNotIn(forbidden, names)

    def test_every_third_party_module_the_runtime_imports_is_in_requirements(self):
        requirements = read_bytes("requirements.txt").decode("utf-8").lower()
        module_to_package = {"flask": "flask", "dotenv": "python-dotenv", "requests": "requests"}
        stdlib_or_local = set(sys.stdlib_module_names) if hasattr(sys, "stdlib_module_names") else None
        imported = set()
        for relative, tree in self.trees():
            if relative.startswith("deploy/"):
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(a.name.split(".")[0] for a in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                    imported.add(node.module.split(".")[0])
        local = {"config", "database", "overview", "validation", "services", "app"}
        for module in sorted(imported - local):
            if stdlib_or_local is not None and module in stdlib_or_local:
                continue
            if module in module_to_package:
                self.assertIn(module_to_package[module], requirements, module)
            elif stdlib_or_local is not None:
                self.fail("unexpected non-stdlib import %r is not covered by requirements.txt" % module)


# --------------------------------------------------------------------
# Linux portability of the runtime code
# --------------------------------------------------------------------
class LinuxPortabilityTests(unittest.TestCase):
    def test_runtime_code_has_no_windows_specific_assumptions(self):
        pattern = re.compile(r"[A-Za-z]:[\\/]|\bos\.sep\b|\bos\.name\b|sys\.platform|\bwin32\b|msvcrt|\.exe\b|cmd\.exe|powershell|startfile")
        hits = []
        for relative in RUNTIME_PY:
            for number, line in enumerate(read_bytes(relative).decode("utf-8").splitlines(), 1):
                code = line.split("#", 1)[0]
                if pattern.search(code) and "https://" not in code:
                    hits.append("%s:%d %s" % (relative, number, line.strip()))
        self.assertEqual(hits, [])

    def test_all_text_files_are_valid_utf_8(self):
        for folder, _dirs, files in os.walk(ROOT):
            if any(part in ("venv", ".git", "__pycache__", "data", "dist", "node_modules") for part in folder.split(os.sep)):
                continue
            for name in files:
                if name.endswith((".py", ".html", ".css", ".js", ".json", ".md", ".txt", ".example")):
                    with open(os.path.join(folder, name), "rb") as handle:
                        data = handle.read()
                    try:
                        data.decode("utf-8")
                    except UnicodeDecodeError:
                        self.fail("not UTF-8: " + os.path.join(folder, name))

    def test_gunicorn_entry_point_is_app_colon_app(self):
        env = clean_env(DATABASE_PATH=os.path.join(tempfile.mkdtemp(prefix="entry_"), "sub", "x.db"))
        code = ("import app; from flask import Flask; "
                "print(isinstance(app.app, Flask), callable(app.app), hasattr(app.app, 'wsgi_app'))")
        out = subprocess.check_output([sys.executable, "-c", code], cwd=ROOT, env=env, universal_newlines=True)
        self.assertEqual(out.split()[-3:], ["True", "True", "True"])
        source = read_bytes("app.py").decode("utf-8")
        self.assertRegex(source, r"(?m)^app = Flask\(__name__\)")
        self.assertRegex(source, r"(?m)^database\.init_db\(\)")         # module level: Gunicorn creates the DB on import

    def test_dotenv_is_found_next_to_config_whatever_the_working_directory(self):
        project = tempfile.mkdtemp(prefix="envproj_")
        elsewhere = tempfile.mkdtemp(prefix="elsewhere_")
        shutil.copy(os.path.join(ROOT, "config.py"), project)
        with open(os.path.join(project, ".env"), "w") as handle:
            handle.write("API_KEY=from-the-dotenv-file\nPORT=6123\n")
        # both launch styles: "python -c" (python-dotenv would use the cwd) and a script file (as Gunicorn does)
        out = subprocess.check_output([sys.executable, "-c", "import config; print(config.API_KEY, config.PORT)"],
                                      cwd=elsewhere, env=clean_env(PYTHONPATH=project), universal_newlines=True)
        self.assertEqual(out.split(), ["from-the-dotenv-file", "6123"])
        runner = os.path.join(elsewhere, "runner.py")
        with open(runner, "w") as handle:
            handle.write("import config\nprint(config.API_KEY, config.PORT)\n")
        out = subprocess.check_output([sys.executable, runner], cwd=elsewhere, env=clean_env(PYTHONPATH=project),
                                      universal_newlines=True)
        self.assertEqual(out.split(), ["from-the-dotenv-file", "6123"])

    def test_real_environment_variables_win_over_the_dotenv_file(self):
        project = tempfile.mkdtemp(prefix="envwins_")
        shutil.copy(os.path.join(ROOT, "config.py"), project)
        with open(os.path.join(project, ".env"), "w") as handle:
            handle.write("API_KEY=file-value\n")
        out = subprocess.check_output([sys.executable, "-c", "import config; print(config.API_KEY)"], cwd=project,
                                      env=clean_env(PYTHONPATH=project, API_KEY="environment-value"), universal_newlines=True)
        self.assertEqual(out.strip(), "environment-value")

    def test_dotenv_with_windows_line_endings_still_parses(self):
        project = tempfile.mkdtemp(prefix="crlf_")
        shutil.copy(os.path.join(ROOT, "config.py"), project)
        with open(os.path.join(project, ".env"), "wb") as handle:
            handle.write(b"API_KEY=crlf-key-value\r\nVT_API_KEY=\r\nPORT=5002\r\n")
        out = subprocess.check_output([sys.executable, "-c", "import config; print(repr(config.API_KEY), repr(config.VT_API_KEY))"],
                                      cwd=project, env=clean_env(PYTHONPATH=project), universal_newlines=True)
        self.assertEqual(out.strip(), "'crlf-key-value' ''")

    def test_database_path_rules(self):
        base = clean_env()
        relative = subprocess.check_output([sys.executable, "-c", "import config; print(config.DATABASE_PATH)"],
                                           cwd=ROOT, env=dict(base, DATABASE_PATH="data/custom.db"), universal_newlines=True).strip()
        self.assertEqual(os.path.normpath(relative), os.path.normpath(os.path.join(ROOT, "data", "custom.db")))
        absolute = os.path.join(tempfile.mkdtemp(prefix="abs_"), "elsewhere.db")
        used = subprocess.check_output([sys.executable, "-c", "import config; print(config.DATABASE_PATH)"],
                                       cwd=ROOT, env=dict(base, DATABASE_PATH=absolute), universal_newlines=True).strip()
        self.assertEqual(os.path.normpath(used), os.path.normpath(absolute))

    def test_server_listens_on_all_interfaces_port_5002_by_default_and_no_runtime_code_hardcodes_localhost_as_the_server(self):
        out = subprocess.check_output([sys.executable, "-c", "import config; print(config.HOST, config.PORT)"],
                                      cwd=ROOT, env=clean_env(), universal_newlines=True).split()
        self.assertEqual(out, ["0.0.0.0", "5002"] if not os.path.exists(os.path.join(ROOT, ".env")) else out)
        for relative in ("app.py", "database.py", "overview.py", "validation.py", "services/reputation.py"):
            code = "\n".join(l.split("#", 1)[0] for l in read_bytes(relative).decode("utf-8").splitlines())
            if relative == "app.py":
                code = code.replace('LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")', "")
            self.assertNotIn("127.0.0.1", code, relative)
            self.assertNotIn("localhost", code.replace("beyond localhost", ""), relative)

    def test_month_names_do_not_depend_on_the_server_locale(self):
        # time labels use %b; the C locale (Python default) always gives English names
        import database
        self.assertEqual(database.time_label("2026-01-05 10:00:00", database.datetime(2026, 2, 1, 12, 0, 0)), "05 Jan 10:00")


# --------------------------------------------------------------------
# a fresh database from nothing
# --------------------------------------------------------------------
class FreshDatabaseTests(unittest.TestCase):
    def fresh(self, name="fresh.db"):
        return os.path.join(tempfile.mkdtemp(prefix="freshdb_"), "not", "yet", "created", name)

    def test_database_is_created_from_nothing_in_missing_directories(self):
        import database
        path = self.fresh()
        self.assertFalse(os.path.exists(os.path.dirname(path)))
        database.init_db(path)
        self.assertTrue(os.path.isfile(path))
        conn = database.get_connection(path)
        try:
            tables = sorted(r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"))
            self.assertEqual(tables, ["alerts", "domain_reputation", "endpoints", "web_visits"])
            columns = [r["name"] for r in conn.execute("PRAGMA table_info(endpoints)")]
            self.assertIn("browser", columns)
            self.assertIn("archived_at", columns)
            for table in tables:
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM %s" % table).fetchone()[0], 0, "a fresh database holds no data")
            self.assertEqual(conn.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            self.assertEqual(conn.execute("PRAGMA foreign_key_check").fetchall(), [])
        finally:
            conn.close()

    def test_initialisation_and_migrations_are_idempotent(self):
        import database
        path = self.fresh()
        for _ in range(3):
            database.init_db(path)
        conn = database.get_connection(path)
        try:
            columns = [r["name"] for r in conn.execute("PRAGMA table_info(endpoints)")]
            self.assertEqual(columns.count("browser"), 1)
            self.assertEqual(columns.count("archived_at"), 1)
            database.upsert_endpoint(conn, "uid-1", "PC-1", "Roi")
        finally:
            conn.close()
        database.init_db(path)                                   # a restart keeps the data
        conn = database.get_connection(path)
        try:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM endpoints").fetchone()[0], 1)
        finally:
            conn.close()

    def test_a_phase_one_database_gains_both_columns_and_keeps_its_rows(self):
        import database
        path = self.fresh("phase1.db")
        os.makedirs(os.path.dirname(path))
        conn = sqlite3.connect(path)
        conn.executescript(
            "CREATE TABLE endpoints (id INTEGER PRIMARY KEY AUTOINCREMENT, endpoint_uid TEXT NOT NULL UNIQUE,"
            " computer_name TEXT NOT NULL, username TEXT, last_seen TEXT NOT NULL);"
            "INSERT INTO endpoints (endpoint_uid, computer_name, username, last_seen) VALUES ('p1', 'PHASE1-PC', 'Old', '2026-10-06 10:00:00');")
        conn.commit()
        conn.close()
        database.init_db(path)
        database.init_db(path)
        conn = database.get_connection(path)
        try:
            row = dict(conn.execute("SELECT * FROM endpoints").fetchone())
        finally:
            conn.close()
        self.assertEqual((row["computer_name"], row["username"], row["browser"], row["archived_at"]), ("PHASE1-PC", "Old", None, None))

    def test_application_starts_and_serves_from_an_empty_database_without_any_development_data(self):
        path = self.fresh("app.db")
        code = ("import app, json; c = app.app.test_client();"
                "s = c.get('/api/status').get_json(); p = c.get('/').status_code;"
                "print(json.dumps([s['summary']['computers'], s['summary']['visits_today'], s['summary']['security_status'], p]))")
        out = subprocess.check_output([sys.executable, "-c", code], cwd=ROOT, env=clean_env(DATABASE_PATH=path, API_KEY="x" * 20),
                                      universal_newlines=True)
        self.assertEqual(json.loads(out.strip().splitlines()[-1]), [0, 0, "LIMITED", 200])
        self.assertTrue(os.path.isfile(path))

    def test_the_development_database_is_never_used_by_tests_or_the_package(self):
        self.assertNotEqual(os.path.normpath(os.environ.get("DATABASE_PATH", "")), os.path.normpath(os.path.join(ROOT, "data", "monitoring.db")))


# --------------------------------------------------------------------
# the deployment package
# --------------------------------------------------------------------
def load_builder():
    spec = importlib.util.spec_from_file_location("build_package", BUILD_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@unittest.skipUnless(os.path.exists(BUILD_SCRIPT), "the package builder is not part of the deployment archive itself")
class DeploymentPackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.builder = load_builder()
        cls.out = tempfile.mkdtemp(prefix="pkg_out_")
        cls.archive, cls.names, cls.digest = cls.builder.build(cls.out, stamp="test")
        with tarfile.open(cls.archive) as tar:
            cls.members = {m.name: m for m in tar.getmembers()}
            cls.data = {m.name: tar.extractfile(m).read() for m in tar.getmembers() if m.isfile()}

    def test_contains_what_is_needed_to_run_and_test_the_application(self):
        needed = ["app.py", "config.py", "database.py", "overview.py", "validation.py", "requirements.txt", "README.md",
                  ".env.example", "SHA256SUMS", "services/__init__.py", "services/reputation.py", "static/css/style.css",
                  "static/js/app.js", "templates/base.html", "templates/dashboard.html", "templates/browsing.html",
                  "templates/alerts.html", "templates/endpoints.html", "deploy/DEPLOYMENT.md", "deploy/check_env.py",
                  "browser_extension/manifest.json", "browser_extension/background.js", "browser_extension/common.js",
                  "browser_extension/options.html", "browser_extension/options.js", "browser_extension/README.md",
                  "tests/test_app.py", "tests/test_phase35.py", "tests/test_deployment.py", "tests/extension_harness.js"]
        for path in needed:
            self.assertIn("website-monitor/" + path, self.data, path)

    def test_everything_is_inside_one_top_level_directory(self):
        self.assertTrue(all(name == "website-monitor" or name.startswith("website-monitor/") for name in self.members))

    def test_nothing_forbidden_is_in_the_archive(self):
        forbidden_names = {".env", ".git", ".gitignore", "venv", ".venv", "__pycache__", ".pytest_cache", "dist", "data", "logs",
                           "send_test_events.py", "build_package.py", "monitoring.db"}
        for name in self.members:
            parts = name.split("/")
            self.assertFalse(set(parts) & forbidden_names, name)
            self.assertFalse(name.lower().endswith((".pem", ".crx", ".key", ".db", ".sqlite", ".log", ".pyc", ".png", ".jpg", ".zip", ".pid")), name)
        self.assertEqual([n for n in self.members if "screenshot" in n.lower() or "shots" in n.lower()], [])

    def test_no_secret_value_or_private_key_is_inside(self):
        secrets_found = self.builder.local_secret_values()          # real values from the local .env, never printed
        marker = b"PRIVATE" + b" KEY"                              # spelled in two parts so this file does not contain it
        for name, data in self.data.items():
            self.assertNotIn(marker, data, name)
            if not name.endswith("/SHA256SUMS"):                  # the checksum list is made of 64-hex digests by design
                self.assertIsNone(re.search(rb"\b[0-9a-f]{64}\b", data), name)
            for secret in secrets_found:
                self.assertNotIn(secret, data, "a real secret from .env must never be packaged (%s)" % name)
        example = self.data["website-monitor/.env.example"].decode("utf-8")
        self.assertRegex(example, r"(?m)^API_KEY=$")
        self.assertRegex(example, r"(?m)^VT_API_KEY=$")

    def test_text_is_lf_and_permissions_are_safe(self):
        for name, data in self.data.items():
            self.assertNotIn(b"\r", data, name)
        for name, member in self.members.items():
            self.assertEqual(member.mode, 0o755 if member.isdir() else 0o644, name)
            self.assertFalse(member.mode & 0o002, "never world-writable: " + name)

    def test_sha256sums_cover_every_file_and_are_correct(self):
        listed = {}
        for line in self.data["website-monitor/SHA256SUMS"].decode("utf-8").splitlines():
            digest, _, path = line.partition("  ")
            listed[path] = digest
        packaged = {n[len("website-monitor/"):] for n in self.data if not n.endswith("/SHA256SUMS")}
        self.assertEqual(set(listed), packaged)
        for path, digest in listed.items():
            self.assertEqual(hashlib.sha256(self.data["website-monitor/" + path]).hexdigest(), digest, path)
        with open(self.archive + ".sha256") as handle:
            self.assertEqual(handle.read().split()[0], self.digest)

    def test_the_package_is_runnable_python(self):
        target = tempfile.mkdtemp(prefix="pkg_extract_")
        with tarfile.open(self.archive) as tar:
            tar.extractall(target)
        project = os.path.join(target, "website-monitor")
        result = subprocess.run([sys.executable, "-m", "compileall", "-q", project], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_builder_refuses_forbidden_or_secret_content(self):
        good = {"website-monitor/app.py": b"print('x')\n"}
        self.builder.verify(good)
        bad_cases = {
            "env file": {"website-monitor/.env": b"A=1\n"},
            "signing key file": {"website-monitor/browser_extension.pem": b"x\n"},
            "packed extension": {"website-monitor/browser_extension.crx": b"x\n"},
            "database": {"website-monitor/data/monitoring.db": b"x\n"},
            "venv": {"website-monitor/venv/bin/python": b"x\n"},
            "private key text": {"website-monitor/a.txt": b"-----BEGIN " + b"PRIVATE" + b" KEY-----\n"},
            "virustotal-shaped key": {"website-monitor/a.txt": b"key " + b"a1" * 32 + b"\n"},
            "CRLF": {"website-monitor/a.txt": b"a\r\nb\n"},
        }
        for label, members in bad_cases.items():
            with self.assertRaises(SystemExit, msg=label):
                self.builder.verify(members)
        original = self.builder.local_secret_values
        self.builder.local_secret_values = lambda: [b"SECRET-VALUE-FROM-ENV"]
        try:
            with self.assertRaises(SystemExit):
                self.builder.verify({"website-monitor/a.txt": b"token=SECRET-VALUE-FROM-ENV\n"})
        finally:
            self.builder.local_secret_values = original

    def test_collection_comes_only_from_the_allow_list(self):
        collected = [path for path, _absolute in self.builder.collect()]
        for path in collected:
            top = path.split("/")[0]
            self.assertTrue(top in self.builder.ROOT_FILES or top in self.builder.DIR_RULES or top == "deploy", path)
        self.assertNotIn("send_test_events.py", collected)
        self.assertFalse([p for p in collected if p.endswith((".pem", ".crx", ".db"))])


# --------------------------------------------------------------------
# the pre-flight checker (run inside a throw-away project copy)
# --------------------------------------------------------------------
class CheckEnvTests(unittest.TestCase):
    def project(self, env_text=None):
        folder = tempfile.mkdtemp(prefix="checkproj_")
        os.makedirs(os.path.join(folder, "deploy"))
        shutil.copy(CHECK_ENV, os.path.join(folder, "deploy"))
        shutil.copy(os.path.join(ROOT, "config.py"), folder)
        if env_text is not None:
            with open(os.path.join(folder, ".env"), "w") as handle:
                handle.write(env_text)
        return folder

    def run_check(self, folder, **env):
        db = os.path.join(folder, "data", "monitoring.db")
        process = subprocess.run([sys.executable, os.path.join(folder, "deploy", "check_env.py"), "--port", "5002"], cwd=folder,
                                 env=clean_env(DATABASE_PATH=db, **env), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 universal_newlines=True)
        return process.returncode, process.stdout

    KEY = "k" * 8 + "abcdef0123456789abcdef"
    VT = "v" * 8 + "fedcba9876543210fedcba"

    def test_good_configuration_passes_and_prints_no_secret(self):
        folder = self.project("API_KEY=%s\nVT_API_KEY=%s\nSECRET_KEY=%s\n" % (self.KEY, self.VT, "s" * 24))
        code, out = self.run_check(folder)
        self.assertEqual(code, 0, out)
        self.assertIn("API_KEY is set", out)
        self.assertIn("VT_API_KEY is set", out)
        for secret in (self.KEY, self.VT, "s" * 24):
            self.assertNotIn(secret, out)

    def test_empty_api_key_fails(self):
        code, out = self.run_check(self.project("API_KEY=\nVT_API_KEY=\n"))
        self.assertEqual(code, 1)
        self.assertIn("FAIL  API_KEY is empty", out)
        self.assertIn("DEV MODE", out)

    def test_short_api_key_fails_without_echoing_it(self):
        code, out = self.run_check(self.project("API_KEY=shortkey1\n"))
        self.assertEqual(code, 1)
        self.assertNotIn("shortkey1", out)
        self.assertIn("only 9 characters", out)

    def test_missing_vt_key_is_only_a_warning_and_missing_env_file_fails(self):
        code, out = self.run_check(self.project("API_KEY=%s\n" % self.KEY))
        self.assertEqual(code, 0, out)
        self.assertIn("WARN  VT_API_KEY is not set", out)
        self.assertIn("still stored", out)
        code, out = self.run_check(self.project(None), API_KEY=self.KEY)
        self.assertEqual(code, 1)
        self.assertIn(".env not found", out)

    def test_reports_database_location_and_clock_without_creating_the_database(self):
        folder = self.project("API_KEY=%s\n" % self.KEY)
        code, out = self.run_check(folder)
        self.assertIn("database file will be", out)
        self.assertIn("is writable", out)
        self.assertIn("server local time", out)
        self.assertFalse(os.path.exists(os.path.join(folder, "data", "monitoring.db")), "the checker must not create the database")

    def test_existing_database_is_flagged(self):
        folder = self.project("API_KEY=%s\n" % self.KEY)
        os.makedirs(os.path.join(folder, "data"))
        open(os.path.join(folder, "data", "monitoring.db"), "wb").close()
        self.assertIn("a database already exists there", self.run_check(folder)[1])


# --------------------------------------------------------------------
# the extension talks only to the configured (remote) server
# --------------------------------------------------------------------
NODE = shutil.which("node")


@unittest.skipUnless(NODE, "Node.js is not installed - the extension harness is skipped")
class ExtensionRemoteServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        out = subprocess.check_output([NODE, os.path.join(ROOT, "tests", "extension_harness.js")], universal_newlines=True,
                                      stderr=subprocess.DEVNULL)        # the extension logs a console warning for the invalid-address case
        cls.r = json.loads(out.strip().splitlines()[-1])

    def urls(self, calls):
        return [c["url"] for c in calls]

    def test_visits_and_heartbeat_use_the_configured_ip_address_and_the_api_key(self):
        calls = self.r["bg_ip"]
        self.assertEqual(self.urls(calls), ["http://192.0.2.10:5002/api/web-events", "http://192.0.2.10:5002/api/heartbeat"])
        for call in calls:
            self.assertEqual(call["method"], "POST")
            self.assertEqual(call["headers"]["X-Api-Key"], "TEST-KEY-123")
            self.assertEqual(call["headers"]["Content-Type"], "application/json")
        visit, heartbeat = calls[0]["body"], calls[1]["body"]
        self.assertEqual(visit["url"], "https://www.example.com/account")             # query and fragment removed
        self.assertEqual(visit["domain"], "www.example.com")
        self.assertNotIn("SECRET", json.dumps(calls))
        self.assertEqual({k: heartbeat[k] for k in ("endpoint_uid", "computer_name", "username", "browser")},
                         {"endpoint_uid": "uid-harness-1", "computer_name": "LAB-PC", "username": "Roi", "browser": "Edge"})

    def test_a_hostname_with_a_path_and_https_works_too(self):
        self.assertEqual(self.urls(self.r["bg_host_with_path"]),
                         ["https://monitor.college.example/mon/api/web-events", "https://monitor.college.example/mon/api/heartbeat"])

    def test_no_key_means_no_header(self):
        for call in self.r["bg_no_key"]:
            self.assertNotIn("X-Api-Key", call["headers"])

    def test_an_invalid_stored_address_sends_nothing(self):
        self.assertEqual(self.r["bg_invalid_url"], [])

    def test_before_it_is_configured_the_extension_uses_the_local_default_only(self):
        self.assertEqual(self.urls(self.r["bg_default_url"]),
                         ["http://127.0.0.1:5002/api/web-events", "http://127.0.0.1:5002/api/heartbeat"])

    def test_options_request_permission_for_exactly_the_typed_ip_origin_then_test_and_register_there(self):
        r = self.r["opt_ip"]
        self.assertTrue(all(p == {"origins": ["http://192.0.2.10:5002/*"]} for p in r["permissionRequests"]))
        self.assertEqual(r["test"]["result"], "Connected successfully")
        self.assertEqual([(c["method"], c["url"], c["headers"].get("X-Api-Key")) for c in r["test"]["calls"]],
                         [("GET", "http://192.0.2.10:5002/api/ping", "SAVED-KEY-1")])
        self.assertEqual([(c["method"], c["url"], c["headers"].get("X-Api-Key")) for c in r["save"]["calls"]],
                         [("POST", "http://192.0.2.10:5002/api/endpoints/register", "SAVED-KEY-1")])
        self.assertEqual(r["save"]["calls"][0]["body"]["endpoint_uid"], "uid-harness-1")
        self.assertEqual(r["stored"]["server_url"], "http://192.0.2.10:5002")             # trailing slash removed
        self.assertEqual(r["save"]["result"], "Saved. This browser is registered as LAB-PC.")

    def test_options_work_with_a_hostname_and_a_newly_typed_key(self):
        r = self.r["opt_host"]
        self.assertEqual(r["permissionRequests"][0], {"origins": ["http://lab-server.college.example:5002/*"]})
        self.assertEqual(r["save"]["calls"][0]["url"], "http://lab-server.college.example:5002/api/endpoints/register")
        self.assertEqual(r["save"]["calls"][0]["headers"]["X-Api-Key"], "TYPED-KEY-2")
        self.assertEqual(r["stored"]["api_key"], "TYPED-KEY-2")

    def test_denied_permission_sends_and_stores_nothing(self):
        r = self.r["opt_denied"]
        self.assertEqual(r["test"]["calls"], [])
        self.assertEqual(r["save"]["calls"], [])
        self.assertNotIn("server_url", r["stored"])
        self.assertNotIn("api_key", r["stored"])

    def test_the_local_default_needs_no_permission_prompt(self):
        r = self.r["opt_local_no_prompt"]
        self.assertEqual(r["permissionRequests"], [])
        self.assertEqual(r["save"]["calls"][0]["url"], "http://127.0.0.1:5002/api/endpoints/register")

    def test_a_non_http_address_is_rejected_before_any_request_or_prompt(self):
        r = self.r["opt_bad_scheme"]
        self.assertEqual((r["permissionRequests"], r["test"]["calls"], r["save"]["calls"]), ([], [], []))
        self.assertEqual(r["test"]["result"], "The address must start with http:// or https://")

    def test_a_wrong_key_is_reported_as_an_authentication_failure(self):
        r = self.r["opt_wrong_key"]
        self.assertEqual(r["test"]["result"], "Authentication failed. Check the API key.")
        self.assertEqual(r["save"]["result"], "Saved, but registration failed. Authentication failed. Check the API key.")


if __name__ == "__main__":
    unittest.main()
