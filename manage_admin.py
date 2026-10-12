"""Create and manage dashboard administrators from a shell on the server.

    python manage_admin.py create              # asks for a user name and (twice, hidden) a password
    python manage_admin.py list
    python manage_admin.py set-password NAME   # asks for the new password twice, hidden
    python manage_admin.py disable NAME        # the person can no longer sign in
    python manage_admin.py enable NAME

There is no default account, no sign-up page and no way to give a password on the command line or in the environment (those end up in
shell history and process lists): the password is typed at a hidden prompt. Reaching this command already requires being logged in to the
server's operating system, which is the trust anchor for the very first administrator.
Run it from the project folder, as the user that runs the server, so it opens the same database (DATABASE_PATH in .env).
"""
import argparse
import getpass
import sys

import auth
import database

MAX_PASSWORD_TRIES = 3


def _ask_new_password(username, ask, out):
    for _ in range(MAX_PASSWORD_TRIES):
        first = ask("New password (at least %d characters, not shown): " % auth.MIN_PASSWORD_LENGTH)
        problem = auth.password_problem(first, username)
        if problem:
            out(problem)
            continue
        if ask("Repeat the password: ") != first:
            out("The two passwords are different. Try again.")
            continue
        return first
    raise auth.AuthError("No acceptable password was entered.")


def main(argv=None, ask=getpass.getpass, read=input, out=print):
    parser = argparse.ArgumentParser(prog="manage_admin.py", description="Manage dashboard administrators.")
    sub = parser.add_subparsers(dest="command")
    create = sub.add_parser("create", help="create an administrator")
    create.add_argument("--username", help="user name (asked for when omitted)")
    sub.add_parser("list", help="list administrators")
    for name in ("set-password", "disable", "enable"):
        item = sub.add_parser(name)
        item.add_argument("username")
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 2

    database.init_db()                                   # creates the tables if this database predates Phase B; never touches other data
    try:
        if args.command == "create":
            username = (args.username or read("User name: ")).strip()
            password = _ask_new_password(username, ask, out)
            auth.create_admin(username, password)
            out("Administrator '%s' created. Open the dashboard and sign in." % username)
        elif args.command == "list":
            rows = auth.list_admins()
            if not rows:
                out("No administrator exists yet. Create one with: python manage_admin.py create")
            for r in rows:
                out("%-24s %-9s created %s, last sign-in %s" % (r["username"], "active" if r["active"] else "disabled", r["created_at"],
                                                              r["last_login_at"] or "never"))
        elif args.command == "set-password":
            auth.set_password(args.username, _ask_new_password(args.username, ask, out))
            out("Password changed for '%s'. Every open session of that administrator has ended." % args.username)
        elif args.command in ("disable", "enable"):
            auth.set_active(args.username, args.command == "enable")
            out("Administrator '%s' %sd." % (args.username, args.command))
    except auth.AuthError as error:
        out("Not done: %s" % error)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
