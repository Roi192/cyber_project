"""Phase 13B: operator CLI for the telemetry store (no network).

    python telemetry_admin.py stats
    python telemetry_admin.py retention --dry-run      (lists what WOULD be removed; always safe)
    python telemetry_admin.py retention --apply        (needs TELEMETRY_RETENTION_ENABLED=true)

Retention only ever removes telemetry_YYYYMMDD.db files inside the telemetry
directory whose filename day is older than TELEMETRY_RETENTION_DAYS. It never
touches cybersec.db or any other file, and it is never run automatically.
"""

import argparse
import os
import sys

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import security_contract as sc
import telemetry_store as ts


def main(argv=None):

    parser = argparse.ArgumentParser(description="Inspect / age out the telemetry store.")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("stats")

    p = sub.add_parser("retention")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--dry-run", action="store_true")
    group.add_argument("--apply", action="store_true")

    args = parser.parse_args(argv)

    directory = ts.telemetry_dir()

    if args.command == "stats":

        files = ts.list_day_files(directory)

        print(f"Telemetry directory: {directory}")
        print(f"Retention enabled: {sc.retention_enabled()} (days: {sc.retention_days()})")

        for day, path in files:
            print(f"  {day}  {os.path.getsize(path):>12} bytes")

        if not files:
            print("  (no telemetry files)")

        return 0

    try:
        report = ts.apply_retention(dry_run=args.dry_run)
    except ts.TelemetryStoreError as exc:
        print(f"ERROR: {exc.code}", file=sys.stderr)
        return 2

    print(f"Directory: {report['directory']}")
    print(f"Effective retention days: {report['effective_days']} | enabled: {report['enabled']} | dry-run: {report['dry_run']}")
    print(f"Candidates: {report['candidates'] or 'none'}")
    print(f"Deleted: {report['deleted'] or 'none'}")

    if report["note"] == "RETENTION_DISABLED":
        print("Retention is DISABLED (TELEMETRY_RETENTION_ENABLED is not true); nothing was deleted.")

    for error in report["errors"]:
        print(f"  error: {error}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
