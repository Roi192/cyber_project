"""Prepare the database BEFORE the web server starts.

    python manage_db.py init     create the database file and every table, or bring an older database up to this version (additive and idempotent)
    python manage_db.py check    read-only: exit 0 when the database exists and has every table this version needs, else 1 (creates nothing)

Why a command: importing the application (`import app`, a shell one-liner, a test helper) must never create or migrate a database - once a one-line import check migrated the
production file. The server therefore does not initialise it by itself when it is merely imported:
  * `python app.py` (the Windows start) calls the same initialisation explicitly before it serves;
  * a Gunicorn start (deploy/service.sh) runs `python manage_db.py init` first, ONCE, before any worker exists (no race between workers);
  * a worker that finds an uninitialised database answers HTTP 503 with this command in the message instead of guessing.
Running `init` twice is harmless: it only adds what is missing and never touches existing rows. It prints the database location, never a secret.
Python 3.8 compatible; standard library plus the project's own modules (it does not import the web application).
"""
import argparse
import os
import sqlite3
import sys

import config
import database


def main(argv=None):
    parser = argparse.ArgumentParser(prog="manage_db.py", description="Prepare or check the Website Monitor database.")
    parser.add_argument("command", nargs="?", default="init", choices=("init", "check"))
    args = parser.parse_args(argv)
    path = config.DATABASE_PATH
    if args.command == "check":
        ready = database.is_initialized(path)
        print("%s: %s" % (path, "ready" if ready else "NOT initialised (run: python manage_db.py init)"))
        return 0 if ready else 1
    existed = os.path.exists(path)
    try:
        database.init_db(path)
    except (sqlite3.Error, OSError) as error:
        print("ERROR: the database could not be prepared (%s): %s" % (path, error))
        return 1
    print("Database %s: %s" % ("up to date" if existed else "created", path))
    return 0 if database.is_initialized(path) else 1


if __name__ == "__main__":
    sys.exit(main())
