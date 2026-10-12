"""Put one or all three provider secrets into the project's .env without ever showing it (Phase F3.23).

    cd C:\\Users\\Moshe\\cyber_project
    venv\\Scripts\\python.exe deploy\\set_local_secret.py METADEFENDER_API_KEY

You are asked for the value with NO echo (nothing is shown while you type or paste), it is written into .env (the line is replaced when the variable already exists, appended otherwise),
and the program prints only the variable NAME and the LENGTH of what it stored - never the value. Run it in your own terminal: the value never passes through a chat, a log or a screenshot.
Only the variables listed in ALLOWED can be set. The rest of .env is left byte for byte as it was (line endings included), the file is replaced atomically, and NO plaintext copy is kept
(pass --backup to get .env.before-<timestamp>; that copy contains the old secrets).
Standard library only; Python 3.8 compatible.
"""
import getpass
import os
import re
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_PATH = os.path.join(ROOT, ".env")
ALLOWED = ("METADEFENDER_API_KEY", "APIVOID_API_KEY", "ABUSEIPDB_API_KEY")


def valid_value(value):
    """A key is printable ASCII without spaces or quotes, 8 to 200 characters."""
    return isinstance(value, str) and 8 <= len(value) <= 200 and re.match(r"^[\x21-\x7e]+$", value) is not None and '"' not in value and "'" not in value and "#" not in value


def with_variable(text, name, value):
    """`text` (the content of .env) with NAME=value set; every other byte unchanged. Returns (new text, replaced?)."""
    newline = "\r\n" if "\r\n" in text else "\n"
    lines = text.split(newline)
    found = False
    for index, line in enumerate(lines):
        if re.match(r"^\s*%s\s*=" % re.escape(name), line):
            lines[index] = "%s=%s" % (name, value)
            found = True
            break
    if not found:
        if lines and lines[-1] == "":
            lines.insert(len(lines) - 1, "%s=%s" % (name, value))
        else:
            lines.append("%s=%s" % (name, value))
    return newline.join(lines), found


def main(argv):
    args = argv[1:]
    keep_backup = "--backup" in args
    names = [a for a in args if a != "--backup"]
    if names == ["all"]:
        names = list(ALLOWED)
    if not names or len(set(names)) != len(names) or any(n not in ALLOWED for n in names):
        print("usage: set_local_secret.py [--backup] <all | one or more of: %s>" % ", ".join(ALLOWED))
        return 2
    if not os.path.isfile(ENV_PATH):
        print("%s does not exist; create it from .env.example first." % ENV_PATH)
        return 2
    with open(ENV_PATH, "r", encoding="utf-8", newline="") as handle:
        text = handle.read()
    original = text
    stored = []
    for name in names:
        value = getpass.getpass("%s (nothing is shown as you type or paste; empty = skip): " % name).strip()
        if not value:
            print("%s skipped." % name)
            continue
        if not valid_value(value):
            print("That does not look like an API key (printable characters only, no spaces, quotes or #, 8-200 long). Nothing was written.")
            return 1
        text, replaced = with_variable(text, name, value)
        stored.append((name, replaced, len(value)))
    if not stored:
        print("Nothing entered; .env is unchanged.")
        return 0
    backup = None
    if keep_backup:
        backup = "%s.before-%s" % (ENV_PATH, time.strftime("%Y%m%d-%H%M%S"))
        with open(backup, "w", encoding="utf-8", newline="") as handle:
            handle.write(original)
    temporary = ENV_PATH + ".tmp"
    with open(temporary, "w", encoding="utf-8", newline="") as handle:
        handle.write(text)
    os.replace(temporary, ENV_PATH)
    for name, replaced, size in stored:
        print("%s %s in .env (%d characters stored; the value is not shown)." % (name, "replaced" if replaced else "added", size))
    print("Previous .env kept as %s (it holds the old secrets: delete it when satisfied)." % os.path.basename(backup) if backup else "No plaintext copy of .env was made.")
    print("Each source stays OFF until its *_ENABLED switch is set to true at activation.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
