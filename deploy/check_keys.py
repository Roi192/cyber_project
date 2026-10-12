"""Local sanity check of the three new provider keys in .env (Phase F3.26). Sends NOTHING anywhere and prints NO part of any key.

    venv\\Scripts\\python.exe deploy\\check_keys.py

For each of APIVOID_API_KEY, METADEFENDER_API_KEY, ABUSEIPDB_API_KEY it reports: present or empty, the length, the character set (hex / letters+digits / other), whether it has stray
quotes or whitespace, and whether it is IDENTICAL to another provider's key or to another secret in .env (the classic paste-into-the-wrong-line mistake). It cannot say that a key is
VALID: only the provider can. Length is a hint, not proof - providers change their formats. A 401 from a real lookup is the definitive answer for that key.
Standard library only; Python 3.8 compatible.
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEYS = ("APIVOID_API_KEY", "METADEFENDER_API_KEY", "ABUSEIPDB_API_KEY")
OTHER_SECRETS = ("API_KEY", "SECRET_KEY", "VT_API_KEY", "GSB_API_KEY", "OTX_API_KEY", "URLSCAN_API_KEY")


def read_raw(path):
    """NAME -> raw value text (after the first '=', not stripped of quotes)."""
    values = {}
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                match = re.match(r"^\s*([A-Z][A-Z0-9_]*)\s*=(.*?)\r?\n?$", line)
                if match:
                    values[match.group(1)] = match.group(2)
    return values


def charset(value):
    if re.match(r"^[0-9a-f]+$", value):
        return "lowercase hex"
    if re.match(r"^[0-9a-fA-F]+$", value):
        return "hex"
    if re.match(r"^[A-Za-z0-9]+$", value):
        return "letters and digits"
    if re.match(r"^[A-Za-z0-9_\-]+$", value):
        return "letters, digits, - and _"
    return "contains other characters"


def run(path=None, out=print):
    values = read_raw(path or os.path.join(ROOT, ".env"))
    problems = 0
    seen = {}
    for name in KEYS:
        raw = values.get(name)
        if raw is None:
            out("%-22s MISSING from .env" % name)
            problems += 1
            continue
        value = raw.strip()
        notes = []
        if value != raw.rstrip("\r\n"):
            notes.append("surrounding whitespace (harmless, trimmed)")
        if value[:1] in ("'", '"') or value[-1:] in ("'", '"'):
            notes.append("quotes around the value")
        value = value.strip("'\"")
        if not value:
            out("%-22s empty" % name)
            problems += 1
            continue
        if re.search(r"\s", value):
            notes.append("contains whitespace inside")
        seen.setdefault(value, []).append(name)
        same = [n for n in OTHER_SECRETS if values.get(n, "").strip().strip("'\"") == value]
        if same:
            notes.append("IDENTICAL to %s" % ", ".join(same))
        out("%-22s present | %d characters | %s%s" % (name, len(value), charset(value), (" | " + "; ".join(notes)) if notes else ""))
        problems += 1 if (same or "contains whitespace inside" in notes) else 0
    for value, names in seen.items():
        if len(names) > 1:
            out("PROBLEM: %s hold the SAME value - a key was pasted into more than one line" % " and ".join(names))
            problems += 1
    out("")
    out("%s. This check cannot prove a key is valid; compare each with its provider's dashboard, and let the single approved lookup decide." % ("Nothing suspicious in the formats" if not problems else "%d problem(s) found" % problems))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(run())
