"""Phase 13B: operator CLI for the sensor registry (no network, no web UI).

Usage (run from the project directory, inside the venv):

    python sensor_admin.py create <sensor_id> <source_engine> [--name NAME] [--description TEXT]
    python sensor_admin.py list
    python sensor_admin.py disable <sensor_id>
    python sensor_admin.py enable  <sensor_id>
    python sensor_admin.py rotate  <sensor_id>
    python sensor_admin.py revoke  <sensor_id>          (permanent)

The secret is printed ONCE by `create` and `rotate` and can never be shown
again. Requires SENSOR_CREDENTIAL_PEPPER in .env (see .env.example); without a
valid pepper every credential operation refuses (fail closed).
"""

import argparse
import getpass
import sys

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import security_sensors as ss


def _fail(message, code=2):
    print(f"ERROR: {message}", file=sys.stderr)
    return code


def main(argv=None):

    parser = argparse.ArgumentParser(description="Manage external security sensors.")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("create")
    p.add_argument("sensor_id")
    p.add_argument("source_engine")
    p.add_argument("--name")
    p.add_argument("--description")

    sub.add_parser("list")

    for name in ("disable", "enable", "rotate", "revoke"):
        p = sub.add_parser(name)
        p.add_argument("sensor_id")

    args = parser.parse_args(argv)

    try:
        ss.init_security_data_db()

        if args.command == "create":

            try:
                operator = getpass.getuser()
            except Exception:
                operator = None

            row, secret = ss.create_sensor(
                args.sensor_id, args.name or args.sensor_id, args.source_engine,
                description=args.description, created_by=operator
            )

            print(f"Sensor created: {row['sensor_id']} (engine: {row['source_engine']})")
            print("")
            print("SENSOR SECRET (shown ONCE - store it in the sensor's own secret store):")
            print(secret)
            print("")
            print("Send it as header X-Sensor-Key, with X-Sensor-Id: " + row["sensor_id"])
            return 0

        if args.command == "rotate":

            secret = ss.rotate_secret(args.sensor_id)

            print(f"Secret rotated for {args.sensor_id}; the previous secret no longer works.")
            print("")
            print("NEW SENSOR SECRET (shown ONCE):")
            print(secret)
            return 0

        if args.command == "list":

            rows = ss.list_sensors()

            if not rows:
                print("No sensors registered.")

            for r in rows:
                print(
                    f"{r['sensor_id']:<24} engine={r['source_engine']:<16} "
                    f"enabled={'yes' if r['enabled'] else 'no':<3} "
                    f"last_data_received={r['last_seen_at'] or 'never'} "
                    f"revoked={r['revoked_at'] or '-'}"
                )

            return 0

        if args.command == "disable":
            ss.set_enabled(args.sensor_id, False)
            print(f"{args.sensor_id}: disabled")
            return 0

        if args.command == "enable":
            ss.set_enabled(args.sensor_id, True)
            print(f"{args.sensor_id}: enabled")
            return 0

        if args.command == "revoke":
            ss.revoke_sensor(args.sensor_id)
            print(f"{args.sensor_id}: revoked permanently")
            return 0

    except ss.CredentialConfigError as exc:
        return _fail(
            f"credential verification is not configured ({exc.code}). Set a dedicated, "
            "random SENSOR_CREDENTIAL_PEPPER (>= 32 chars, not reused from any other secret) in .env."
        )

    except ss.SensorError as exc:
        return _fail(exc.code)

    return 0


if __name__ == "__main__":
    sys.exit(main())
