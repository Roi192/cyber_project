"""Build the clean, minimal COLLEGE package in a staging folder (Phase F3.29). Nothing in the source project is changed.

    venv\\Scripts\\python.exe deploy\\build_college_package.py C:\\Users\\Moshe\\cyber_project_college

creates  <target>\\cyber_project\\  holding exactly what `python app.py` needs on Linux and nothing else:

    app.py auth.py analytics.py bootstrap.py config.py database.py devices.py overview.py validation.py manage_admin.py (+ demo.py when present)
    services\\  templates\\  static\\   .env.example (the college template)   requirements.txt (the ONE file)   README.md   docs\\ (three short documents)

It does NOT contain: .env or any key, any database or backup, the Windows venv, tests, the Windows Agent, the browser extension (its private signing key included), Gunicorn/Apache
files, caches, logs. After copying it scans the result: forbidden names/suffixes, and every secret value of the local .env (never printed) must be absent. The target folder's
`cyber_project` is replaced; the folder that holds it is created if needed. Standard library only; Python 3.8 compatible.
"""
import hashlib
import io
import os
import re
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT_FILES = ["app.py", "auth.py", "analytics.py", "bootstrap.py", "config.py", "database.py", "devices.py", "overview.py", "validation.py", "manage_admin.py", "requirements.txt"]
SERVICES = None          # every *.py in services/
TEMPLATES = ".html"
STATIC_SUFFIXES = (".css", ".js")
RENAMED = {"deploy/env.college.example": ".env.example", "deploy/README_COLLEGE.md": "README.md"}
DOCS = ["docs/PROVIDERS.md", "docs/SEVERITY_POLICY.md"]
FORBIDDEN_NAMES = {".env", "venv", ".venv", "__pycache__", "tests", "agent", "browser_extension", "data", "dist", "logs", "requirements-lock.txt", "gunicorn.conf.py", "service.sh",
                   "send_test_events.py", "manage_db.py", ".git", ".gitignore"}
FORBIDDEN_SUFFIXES = (".pem", ".crx", ".key", ".db", ".db-journal", ".db-wal", ".sqlite", ".sqlite3", ".log", ".pyc", ".pid", ".zip", ".tar", ".gz", ".exe", ".bat", ".ps1")
SECRET_SHAPES = (re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----"), re.compile(rb"\b[0-9a-fA-F]{32,}\b"))
SECRET_NAMES = re.compile(r"^\s*([A-Z][A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD))\s*=\s*(.+?)\s*$")


def local_secret_values():
    """Values of every *KEY/*SECRET line of the local .env (never printed): the build proves none of them is in the package."""
    values = []
    path = os.path.join(ROOT, ".env")
    if os.path.isfile(path):
        with io.open(path, encoding="utf-8") as handle:
            for line in handle:
                match = SECRET_NAMES.match(line)
                if match and len(match.group(2).strip("'\"")) >= 8:
                    values.append(match.group(2).strip("'\"").encode("utf-8"))
    return values


def collect():
    """[(source path, destination relative path)] - the allowlist, nothing else."""
    pairs = []
    for name in ROOT_FILES:
        if os.path.isfile(os.path.join(ROOT, name)):
            pairs.append((name, name))
    for name in sorted(os.listdir(os.path.join(ROOT, "services"))):
        if name.endswith(".py"):
            pairs.append(("services/" + name, "services/" + name))
    for name in sorted(os.listdir(os.path.join(ROOT, "templates"))):
        if name.endswith(TEMPLATES):
            pairs.append(("templates/" + name, "templates/" + name))
    for folder, _, names in os.walk(os.path.join(ROOT, "static")):
        for name in sorted(names):
            if name.endswith(STATIC_SUFFIXES):
                rel = os.path.relpath(os.path.join(folder, name), ROOT).replace(os.sep, "/")
                pairs.append((rel, rel))
    pairs += [(src, dst) for src, dst in RENAMED.items()]
    for doc in DOCS:
        if os.path.isfile(os.path.join(ROOT, doc)):
            pairs.append((doc, doc))
    return pairs


def build(target, out=print):
    destination = os.path.join(os.path.abspath(target), "cyber_project")
    if os.path.isdir(destination):
        shutil.rmtree(destination)
    os.makedirs(destination)
    pairs = collect()
    for src, dst in pairs:
        source = os.path.join(ROOT, src)
        if not os.path.isfile(source):
            raise SystemExit("missing source file for the package: %s" % src)
        path = os.path.join(destination, dst.replace("/", os.sep))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with io.open(source, "rb") as handle:
            data = handle.read()
        if src.endswith((".py", ".html", ".css", ".js", ".md", ".txt", ".example")):
            data = data.replace(b"\r\n", b"\n")                      # Linux line endings everywhere
        with io.open(path, "wb") as handle:
            handle.write(data)
    problems = scan(destination)
    if problems:
        shutil.rmtree(destination)
        raise SystemExit("the package was NOT kept:\n  " + "\n  ".join(problems))
    out("Built %s (%d files)." % (destination, len(pairs)))
    return destination


def scan(destination):
    problems = []
    secrets = local_secret_values()
    for folder, dirs, names in os.walk(destination):
        for name in dirs + names:
            if name in FORBIDDEN_NAMES or name.endswith(FORBIDDEN_SUFFIXES):
                problems.append("forbidden item: %s" % os.path.relpath(os.path.join(folder, name), destination))
        for name in names:
            path = os.path.join(folder, name)
            with io.open(path, "rb") as handle:
                data = handle.read()
            rel = os.path.relpath(path, destination)
            if any(secret in data for secret in secrets):
                problems.append("a value from the local .env appears in %s" % rel)
            if SECRET_SHAPES[0].search(data):
                problems.append("a private key block appears in %s" % rel)
            if rel.endswith((".py", ".md", ".txt", ".example")) and re.search(rb"[A-Za-z]:\\Users\\", data) and not rel.endswith("README.md"):
                problems.append("a Windows user path appears in %s" % rel)
    return problems


def manifest(destination):
    rows = []
    for folder, _, names in os.walk(destination):
        for name in sorted(names):
            path = os.path.join(folder, name)
            with io.open(path, "rb") as handle:
                rows.append((os.path.relpath(path, destination).replace(os.sep, "/"), os.path.getsize(path), hashlib.sha256(handle.read()).hexdigest()[:12]))
    return sorted(rows)


DOCKER_FILES = {"deploy/docker/Dockerfile.college-test": "docker_test/Dockerfile.college-test", "deploy/docker/docker-compose.college-test.yml": "docker_test/docker-compose.college-test.yml",
                "deploy/docker/provider-test.env.example": "docker_test/provider-test.env.example", "deploy/docker/run_college_test.ps1": "docker_test/run_college_test.ps1",
                "deploy/docker/run_college_test.sh": "docker_test/run_college_test.sh", "deploy/docker/README.md": "docker_test/README.md",
                "deploy/docker/dockerignore.college-test": ".dockerignore", "deploy/docker/export_system_ca.py": "docker_test/export_system_ca.py",
                "deploy/docker/extra-ca-README.txt": "docker_test/extra-ca/README.txt", "deploy/verify_college_package.py": "docker_test/verify_college_package.py"}


def stage_docker(target):
    """The Docker test kit goes NEXT TO the package (build context = the target folder), never inside it."""
    base = os.path.abspath(target)
    for src, dst in DOCKER_FILES.items():
        path = os.path.join(base, dst.replace("/", os.sep))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with io.open(os.path.join(ROOT, src), "rb") as handle:
            data = handle.read().replace(b"\r\n", b"\n")
        with io.open(path, "wb") as handle:
            handle.write(data)
    return sorted(DOCKER_FILES.values())


def main(argv=None):
    args = list(argv if argv is not None else sys.argv[1:])
    if len(args) != 1:
        print("usage: build_college_package.py <target folder>")
        return 2
    destination = build(args[0])
    print("Docker test kit staged next to the package: %s" % ", ".join(stage_docker(args[0])))
    for rel, size, digest in manifest(destination):
        print("  %-42s %8d  %s" % (rel, size, digest))
    return 0


if __name__ == "__main__":
    sys.exit(main())
