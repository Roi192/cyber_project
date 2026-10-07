"""Builds the Linux deployment archive from an explicit ALLOW-LIST.

    python deploy/build_package.py              # writes dist/website-monitor-deploy-<time>.tar.gz

Only files named here can ever enter the archive, so a development database, .env,
keys, the packed-extension signing key, logs, caches, screenshots or a virtualenv can
not slip in by accident. After building, the archive is checked again:
  * no forbidden file name or extension,
  * no private-key marker, no 64-hex (VirusTotal-key shaped) string, and none of the
    actual secret values found in the local .env,
and the build FAILS if anything matches. Text files are normalized to LF line endings
and permissions are 0644 files / 0755 directories (never executable, never 777).
"""
import argparse
import hashlib
import io
import os
import re
import sys
import tarfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOP = "website-monitor"

ROOT_FILES = ["app.py", "config.py", "database.py", "overview.py", "validation.py",
              "requirements.txt", "README.md", ".env.example"]
# directory -> allowed file suffixes (or exact names for "deploy")
DIR_RULES = {
    "services": (".py",),
    "static": (".css", ".js"),
    "templates": (".html",),
    "tests": (".py", ".js"),
    "browser_extension": (".js", ".html", ".json", ".md"),
}
DEPLOY_FILES = ["DEPLOYMENT.md", "check_env.py"]

FORBIDDEN_BASENAMES = {".env", ".git", ".gitignore", "venv", ".venv", "__pycache__", ".pytest_cache", "dist", "data", "logs",
                       "send_test_events.py"}
FORBIDDEN_SUFFIXES = (".pem", ".crx", ".key", ".db", ".db-journal", ".db-wal", ".sqlite", ".sqlite3", ".log", ".pyc",
                      ".png", ".jpg", ".jpeg", ".gif", ".zip", ".gz", ".tar", ".pid")
SECRET_PATTERNS = (re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----"), re.compile(rb"\b[0-9a-f]{64}\b"))


def local_secret_values():
    """Secret values of the local .env (never printed) so the build can prove none leaked."""
    values = []
    path = os.path.join(ROOT, ".env")
    if os.path.isfile(path):
        with io.open(path, encoding="utf-8") as handle:
            for line in handle:
                name, _, value = line.strip().partition("=")
                if name in ("API_KEY", "VT_API_KEY", "SECRET_KEY") and len(value.strip()) >= 8:
                    values.append(value.strip().encode("utf-8"))
    return values


def collect():
    """[(archive path, absolute path)] sorted, from the allow-list only."""
    items = []
    for name in ROOT_FILES:
        items.append((name, os.path.join(ROOT, name)))
    for directory, suffixes in DIR_RULES.items():
        for folder, dirs, files in os.walk(os.path.join(ROOT, directory)):
            dirs[:] = sorted(d for d in dirs if d != "__pycache__")
            for filename in sorted(files):
                if filename.endswith(suffixes):
                    absolute = os.path.join(folder, filename)
                    items.append((os.path.relpath(absolute, ROOT).replace(os.sep, "/"), absolute))
    for name in DEPLOY_FILES:
        items.append(("deploy/" + name, os.path.join(ROOT, "deploy", name)))
    return sorted(set(items))


def to_lf(data):
    return data.replace(b"\r\n", b"\n")


def verify(members):
    """members: {archive path: bytes}. Raises SystemExit with a clear message on any problem."""
    secrets = local_secret_values()
    problems = []
    for path, data in members.items():
        parts = path.split("/")
        if any(part in FORBIDDEN_BASENAMES for part in parts):
            problems.append("forbidden name: " + path)
        if path.lower().endswith(FORBIDDEN_SUFFIXES):
            problems.append("forbidden file type: " + path)
        for pattern in SECRET_PATTERNS:
            if path.endswith("/SHA256SUMS") and pattern.pattern.startswith(rb"\b[0-9a-f]"):
                continue                         # the checksum list is made of 64-hex digests by design
            if pattern.search(data):
                problems.append("secret-looking content in %s (%s)" % (path, pattern.pattern[:24].decode("ascii")))
        for secret in secrets:
            if secret in data:
                problems.append("a real secret from .env appears in " + path)
        if b"\r" in data:
            problems.append("CR line ending left in " + path)
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            problems.append("not UTF-8 text: " + path)
    if problems:
        sys.exit("BUILD REFUSED:\n  " + "\n  ".join(problems))


def build(out_dir, stamp=None):
    """Create the archive in out_dir. Returns (archive path, sorted member names, sha256 hex)."""
    stamp = stamp or time.strftime("%Y%m%d-%H%M")
    members = {}
    for archive_path, absolute in collect():
        if not os.path.isfile(absolute):
            sys.exit("missing file: " + archive_path)
        with open(absolute, "rb") as handle:
            members[TOP + "/" + archive_path] = to_lf(handle.read())
    sums = "".join("%s  %s\n" % (hashlib.sha256(data).hexdigest(), name[len(TOP) + 1:]) for name, data in sorted(members.items()))
    members[TOP + "/SHA256SUMS"] = sums.encode("utf-8")
    verify(members)

    if not os.path.isdir(out_dir):
        os.makedirs(out_dir)
    target = os.path.join(out_dir, "website-monitor-deploy-%s.tar.gz" % stamp)
    now = int(time.time())
    directories = sorted({os.path.dirname(name) for name in members} - {""})
    with tarfile.open(target, "w:gz") as archive:
        added = set()
        for directory in directories:
            parts = directory.split("/")
            for depth in range(1, len(parts) + 1):
                current = "/".join(parts[:depth])
                if current not in added:
                    added.add(current)
                    info = tarfile.TarInfo(current)
                    info.type, info.mode, info.mtime = tarfile.DIRTYPE, 0o755, now
                    archive.addfile(info)
        for name in sorted(members):
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(members[name]), 0o644, now
            archive.addfile(info, io.BytesIO(members[name]))
    with open(target, "rb") as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()
    with open(target + ".sha256", "w") as handle:
        handle.write("%s  %s\n" % (digest, os.path.basename(target)))
    return target, sorted(members), digest


def main():
    parser = argparse.ArgumentParser(description="Build the Website Monitor Linux deployment archive")
    parser.add_argument("--out", default=os.path.join(ROOT, "dist"))
    args = parser.parse_args()
    target, names, digest = build(args.out)
    print("built   %s" % target)
    print("size    %d bytes, %d files" % (os.path.getsize(target), len(names)))
    print("sha256  %s" % digest)
    for name in names:
        print("  " + name)


if __name__ == "__main__":
    main()
