"""Build the PRIVATE college `.env` from your local one (Phase F3.29). The result is never placed inside the college package.

    venv\\Scripts\\python.exe deploy\\make_college_env.py                # writes C:\\Users\\Moshe\\cyber_project_college_private\\college.env
    venv\\Scripts\\python.exe deploy\\make_college_env.py --out D:\\private

It starts from the college template (deploy/env.college.example) and copies ONLY the seven providers' settings from your local .env (the keys, the *_ENABLED switches and the
budgets). Everything else is set for the college: HOST=127.0.0.1, PORT=5002, a separate SQLite file (data/monitoring.db), legacy alert policy, secure session defaults and a NEW
random SECRET_KEY and API_KEY (the Windows ones are not reused). Windows-only settings (REQUESTS_CA_BUNDLE, the Avast certificate, Windows paths) and every unknown variable are left out.
It prints only variable NAMES and a count, never a value; it restricts the file to your user (icacls on Windows, mode 600 elsewhere). Then transfer that one file to the server:

    scp college.env team2@<server>:/home/team2/cyber_project/.env  &&  ssh team2@<server> chmod 600 /home/team2/cyber_project/.env

(over SSH/SCP, or inside a password-protected archive; never in an ordinary ZIP, e-mail or chat) and delete the local copy when you are done. Standard library only; Python 3.8.
"""
import argparse
import getpass
import os
import re
import secrets
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_OUT = os.path.join(os.path.dirname(ROOT), "cyber_project_college_private")
PROVIDER_PREFIXES = ("VT_", "GSB_", "OTX_", "URLSCAN_", "APIVOID_", "METADEFENDER_", "ABUSEIPDB_")
FIXED = {"HOST": "127.0.0.1", "PORT": "5002", "TRUSTED_PROXY_HOPS": "0", "DATABASE_PATH": "data/monitoring.db", "SEVERITY_POLICY": "legacy", "SESSION_COOKIE_SECURE": "false"}


def read_env(path):
    values = {}
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                match = re.match(r"^\s*([A-Z][A-Z0-9_]*)\s*=\s*(.*?)\s*$", line.rstrip("\r\n"))
                if match:
                    values[match.group(1)] = match.group(2).strip("'\"")
    return values


def build(template_path, local_path):
    """(text, notes): the college .env text and sentences about it (names only)."""
    local = read_env(local_path)
    notes, out = [], []
    with open(template_path, encoding="utf-8") as handle:
        template = handle.read().replace("\r\n", "\n")
    copied = []
    for line in template.split("\n"):
        match = re.match(r"^([A-Z][A-Z0-9_]*)=(.*)$", line)
        if not match:
            out.append(line)
            continue
        name = match.group(1)
        if name == "SECRET_KEY":
            line = "SECRET_KEY=%s" % secrets.token_hex(32)
        elif name == "API_KEY":
            line = "API_KEY=%s" % secrets.token_hex(24)
        elif name in FIXED:
            line = "%s=%s" % (name, FIXED[name])
        elif name.startswith(PROVIDER_PREFIXES) and name in local:
            line = "%s=%s" % (name, local[name])
            copied.append(name)
        out.append(line)
    text = "\n".join(out)
    in_template = set(re.findall(r"(?m)^([A-Z][A-Z0-9_]*)=", template))
    skipped = sorted(n for n in local if n not in copied and n not in FIXED and n not in in_template and not n.startswith(PROVIDER_PREFIXES))
    keys = [n for n in copied if n.endswith("API_KEY") and local.get(n)]
    notes.append("provider settings copied from your local .env: %d (%d keys present: %s)" % (len(copied), len(keys), ", ".join(keys) or "none"))
    notes.append("switched on: %s" % (", ".join(n[:-8] for n in copied if n.endswith("_ENABLED") and local.get(n, "").lower() == "true") or "none (VirusTotal needs no switch)"))
    notes.append("new random SECRET_KEY and API_KEY generated (the Windows values are not reused)")
    notes.append("left out (not for Linux or not provider settings): %s" % (", ".join(skipped) or "nothing"))
    return text, notes


def restrict(path):
    if os.name == "nt":
        subprocess.run(["icacls", path, "/inheritance:r", "/grant:r", "%s:F" % getpass.getuser()], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        os.chmod(path, 0o600)


def main(argv=None, out=print):
    parser = argparse.ArgumentParser(description="Build the private college .env.")
    parser.add_argument("--out", default=DEFAULT_OUT)
    parser.add_argument("--local", default=os.path.join(ROOT, ".env"))
    args = parser.parse_args(argv)
    text, notes = build(os.path.join(ROOT, "deploy", "env.college.example"), args.local)
    if os.path.abspath(args.out).startswith(os.path.join(ROOT, "")):
        out("REFUSED: the private file must not be written inside the project/package folder.")
        return 2
    os.makedirs(args.out, exist_ok=True)
    target = os.path.join(args.out, "college.env")
    with open(target, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    restrict(target)
    out("Wrote %s (access restricted to your user)." % target)
    for note in notes:
        out("  - " + note)
    out("Next: scp it to the server as /home/team2/cyber_project/.env, chmod 600, and delete the local copy afterwards. It is not part of the package.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
