# ==================================================
# EMERGENCY NETWORK RECOVERY (Phase 7)
# ==================================================
# Standalone, dependency-free safety net. Run this directly on
# an endpoint if it appears isolated and the SOC-based Restore
# workflow is not available or not working.
#
# It does EXACTLY two things, both scoped ONLY to what this
# project's Agent itself could have created:
#   1. Removes every firewall rule whose name starts with
#      "CyberProject_" (the prefix ALL rules created by
#      endpoint_agent_stable.py use - see Phase 7 report).
#   2. Resets the Windows Firewall's default outbound policy
#      back to "Allow" for all profiles (the Windows default -
#      this project's isolation feature is the only thing that
#      ever sets it to "Block").
#
# It does NOT touch any other firewall rule, does NOT reset the
# whole firewall, and does NOT disable Windows Firewall or any
# other security control.
#
# Usage (run as Administrator - firewall changes require it):
#   python restore_network.py
#
# Safe to run even if nothing is isolated - both operations are
# no-ops if there is nothing to remove/reset.
# ==================================================

import subprocess
import sys


FIREWALL_RULE_PREFIX = "CyberProject_"


def is_admin():

    try:

        import ctypes

        return bool(
            ctypes.windll.shell32.IsUserAnAdmin()
        )

    except Exception:

        return False


def run_powershell(script):

    return subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script
        ],
        capture_output=True,
        text=True,
        timeout=30
    )


def main():

    print("=" * 50)
    print("CyberProject Emergency Network Recovery")
    print("=" * 50)

    if not is_admin():

        print(
            "[ERROR] This script must be run as Administrator "
            "to modify firewall rules."
        )
        print(
            "Right-click your terminal/PowerShell and choose "
            "'Run as Administrator', then run this script again."
        )

        sys.exit(1)

    print(
        f"Removing all firewall rules starting with "
        f"'{FIREWALL_RULE_PREFIX}'..."
    )

    remove_result = run_powershell(
        f"Get-NetFirewallRule -DisplayName '{FIREWALL_RULE_PREFIX}*' "
        "-ErrorAction SilentlyContinue "
        "| Remove-NetFirewallRule -ErrorAction SilentlyContinue"
    )

    if remove_result.returncode != 0:

        print(
            "[WARNING] Rule removal reported an error (this is "
            "often harmless if there was nothing to remove):"
        )
        print(remove_result.stderr.strip()[:500])

    else:

        print("Done.")

    print(
        "Resetting default outbound firewall policy to Allow "
        "for all profiles..."
    )

    reset_result = run_powershell(
        "Set-NetFirewallProfile -All -DefaultOutboundAction Allow"
    )

    if reset_result.returncode != 0:

        print("[ERROR] Could not reset default outbound policy:")
        print(reset_result.stderr.strip()[:500])
        sys.exit(1)

    print("Done.")
    print()
    print(
        "Network recovery complete. This machine's outbound "
        "traffic is no longer restricted by this project, and "
        "no CyberProject_* firewall rules remain."
    )


if __name__ == "__main__":

    main()
