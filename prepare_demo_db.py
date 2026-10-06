"""
prepare_demo_db.py

Builds (or rebuilds, from scratch) a clean, reproducible classroom
demo database, completely separate from the real development
database (cybersec.db) - never a cleaned copy of it.

Every run deletes the target file (if it exists) and recreates it
via the application's own real initialization path
(app.initialize_application(), the same function a real
`python app.py` or `gunicorn app:app` start uses) - never hand-
written CREATE TABLE statements. This makes every run of this
script idempotent by construction: run it any number of times and
you always land on the exact same clean starting state.

SAFETY:
  - Refuses to run without --yes-reset-demo-db.
  - Refuses an empty/blank --db-path.
  - Refuses if the target resolves (by filename OR by absolute
    path) to the real development database, cybersec.db - this
    script must NEVER be able to touch it.
  - Only ever deletes the exact target path (and its -journal
    sidecar) - no wildcard, no directory sweep.
  - Never creates a security_alerts, security_events,
    response_commands, global_block_policies, or
    global_block_policy_endpoints row - the demo DB starts with
    all of those empty and only ever gains rows when a real Agent/
    worker/Admin action happens live during the actual demo.

Usage:
    python prepare_demo_db.py --db-path cybersec_demo.db --yes-reset-demo-db
    python prepare_demo_db.py --db-path cybersec_demo.db --yes-reset-demo-db --env-file .env.demo
"""

import argparse
import os
import sys
from datetime import datetime


THIS_DIR = os.path.dirname(os.path.abspath(__file__))
LIVE_DB_PATH = os.path.join(THIS_DIR, "cybersec.db")

# The one controlled demo IOC. A real, public, well-known, benign
# IP is required - the automated detection pipeline structurally
# never reaches local-IOC correlation for RFC1918/RFC5737 test-net
# addresses (both the Agent's own capture filter and the worker's
# reputation gate key off ipaddress.is_global, which classifies
# every "documentation/test" range as non-global, identically to
# private space). 1.1.1.1 is Cloudflare's public DNS resolver -
# globally routable, extremely well-known, and connecting to it is
# ordinary, authorized internet usage - not malware, not an
# unauthorized target.
DEMO_IOC_TYPE = "IP"
DEMO_IOC_VALUE = "1.1.1.1"
DEMO_IOC_SEVERITY = "HIGH"
DEMO_IOC_DESCRIPTION = "Controlled classroom demonstration IOC"
DEMO_IOC_SOURCE = "Classroom Demo"
DEMO_IOC_CREATED_BY = "demo-setup"


def refuse(message):

    print(f"[REFUSED] {message}")
    sys.exit(1)


def main():

    parser = argparse.ArgumentParser(
        description=(
            "Build/rebuild the classroom demo database from "
            "scratch. Never operates on cybersec.db."
        )
    )

    parser.add_argument(
        "--db-path",
        required=True,
        help=(
            "Target demo database file (e.g. cybersec_demo.db). "
            "Must NOT be cybersec.db."
        )
    )

    parser.add_argument(
        "--yes-reset-demo-db",
        action="store_true",
        help="Required. Confirms you want to (re)build the target file."
    )

    parser.add_argument(
        "--env-file",
        default=".env.demo",
        help=(
            "Env file to load for FLASK_SECRET_KEY/AGENT_API_KEY/"
            "INITIAL_ADMIN_USERNAME/INITIAL_ADMIN_PASSWORD/etc. "
            "Defaults to .env.demo."
        )
    )

    args = parser.parse_args()

    # --------------------------------------------------
    # SAFETY GATES - all before any write
    # --------------------------------------------------

    if not args.yes_reset_demo_db:
        refuse(
            "Refusing to run without --yes-reset-demo-db. "
            "This flag is required to confirm you want to rebuild "
            "the target database from scratch."
        )

    raw_target = (args.db_path or "").strip()

    if not raw_target:
        refuse("Refusing: empty/ambiguous --db-path.")

    target_abs = os.path.abspath(raw_target)

    if os.path.basename(target_abs).lower() == "cybersec.db":
        refuse(
            "Refusing: --db-path resolves to a file named "
            "cybersec.db. This script will never operate on the "
            "development database."
        )

    if target_abs == os.path.abspath(LIVE_DB_PATH):
        refuse(
            "Refusing: --db-path resolves to the exact same file "
            "as this project's live cybersec.db. This script will "
            "never operate on the development database."
        )

    # --------------------------------------------------
    # DELETE (exact path only, never a wildcard) THEN REBUILD
    # --------------------------------------------------

    for candidate in (target_abs, target_abs + "-journal"):

        if os.path.exists(candidate):

            os.remove(candidate)

            print(f"[DEMO] Removed existing file: {candidate}")

    os.environ["SOC_DB_PATH"] = target_abs

    if os.path.exists(args.env_file):

        from dotenv import load_dotenv

        load_dotenv(args.env_file, override=True)

        print(f"[DEMO] Loaded env file: {args.env_file}")

    else:

        print(
            f"[DEMO WARNING] Env file '{args.env_file}' not found - "
            "proceeding with whatever environment variables are "
            "already set. INITIAL_ADMIN_USERNAME/PASSWORD must be "
            "set some other way or no admin will be created."
        )

    # Importing app triggers initialize_application() at module
    # level (the same WSGI-safe path gunicorn/python app.py use) -
    # this is what actually builds the full schema and bootstraps
    # the admin account. No hand-written CREATE TABLE anywhere here.
    import app as appmod

    # --------------------------------------------------
    # SEED EXACTLY ONE DEMO IOC (real app INSERT, replicated
    # verbatim - no lower-level function exists to call instead)
    # --------------------------------------------------

    conn = appmod.get_db_connection()

    existing = conn.execute("""
        SELECT id FROM threat_indicators WHERE indicator_value = ?
    """, (
        DEMO_IOC_VALUE,
    )).fetchone()

    if existing is None:

        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        conn.execute("""
            INSERT INTO threat_indicators (
                indicator_type,
                indicator_value,
                severity,
                description,
                source,
                created_by,
                created_at,
                active
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            DEMO_IOC_TYPE,
            DEMO_IOC_VALUE,
            DEMO_IOC_SEVERITY,
            DEMO_IOC_DESCRIPTION,
            DEMO_IOC_SOURCE,
            DEMO_IOC_CREATED_BY,
            created_at,
            1
        ))

        conn.commit()

        print(
            f"[DEMO] Seeded demo IOC: {DEMO_IOC_VALUE} "
            f"({DEMO_IOC_SEVERITY})"
        )

    conn.close()

    # Genuine audit trail for the seeded IOC - reuses the existing,
    # unmodified create_log(), matching what the real /threat-intel
    # route does on IOC creation. username_override avoids needing
    # a Flask session/request context.
    appmod.create_log(
        "IOC_CREATED",
        f"Threat indicator '{DEMO_IOC_VALUE}' was added.",
        username_override=DEMO_IOC_CREATED_BY
    )

    # --------------------------------------------------
    # SUMMARY
    # --------------------------------------------------

    conn = appmod.get_db_connection()

    tables = [
        "users", "endpoints", "web_events", "security_alerts",
        "security_events", "response_commands",
        "global_block_policies", "global_block_policy_endpoints",
        "threat_indicators", "threat_reputation",
        "scans", "scan_results", "findings", "system_logs"
    ]

    print(f"\n[DEMO] Database ready: {target_abs}\n")

    for table in tables:

        count = conn.execute(
            f"SELECT COUNT(*) FROM {table}"
        ).fetchone()[0]

        print(f"  {table}: {count}")

    conn.close()


if __name__ == "__main__":
    main()
