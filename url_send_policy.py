# ==================================================
# STEP 24B.1: SERVER-SIDE PRIVACY POLICY FOR SENDING A URL EXTERNALLY
# ==================================================
#
# The ONLY gate a URL must pass before this project ever sends it to an
# external threat-intel service (Google Safe Browsing, PhishTank). This
# is INDEPENDENT of the browser extension's own excludedDomains policy
# (Step 24A) - that policy decides what the extension COLLECTS in the
# first place; this module is the SERVER's own, separate check, run
# again right before every external call, so a misconfigured or
# bypassed extension policy can never result in an unwanted external
# send. Fail-closed throughout: any check that cannot positively
# confirm "this is safe to send" blocks the send.
#
# Pure, synchronous, no I/O other than reading the one env var below -
# directly unit-testable with no database/network involved.

import ipaddress
import os
import socket
from urllib.parse import urlparse

MAX_URL_LENGTH = 2048

# Conventionally-internal TLD-like suffixes - not an authoritative or
# exhaustive list (no such list exists), but a conservative, documented
# set of hostnames that are never meant to be looked up publicly.
_INTERNAL_SUFFIXES = (
    ".local", ".internal", ".lan", ".corp", ".home",
    ".test", ".localdomain", ".intranet",
)

_LOCAL_HOSTNAMES = {"localhost"}

# Path segments that suggest the URL may carry sensitive information
# even with no query string/fragment (which are already banned
# upstream - see below). A best-effort heuristic, not a guarantee -
# documented as a known limitation in the Step 24B.1 report. Checked
# case-insensitively against each '/'-separated path segment.
_SENSITIVE_PATH_KEYWORDS = (
    "password", "passwd", "secret", "token", "session", "auth",
    "login", "signin", "ssn", "social-security", "creditcard",
    "credit-card", "api-key", "apikey", "api_key", "private",
    "account", "billing", "payment", "reset-password", "verify",
)


def _env_excluded_domains():
    # Step 24B.1: a SEPARATE, server-side source of truth for excluded
    # domains - deliberately not read from the browser extension's own
    # managed policy (chrome.storage.managed is client-side only and
    # unavailable to the server anyway). Comma-separated, e.g.
    # "mybank.example,healthportal.example". Re-read on every call
    # (cheap - a single getenv) so a live .env change takes effect
    # without a restart being required to pass this specific check.
    raw = os.getenv("URL_INTEL_EXCLUDED_DOMAINS", "")
    return [d.strip().lower() for d in raw.split(",") if d.strip()]


def _is_excluded_domain(hostname, excluded_domains):

    hostname = (hostname or "").lower()

    for suffix in excluded_domains:
        if hostname == suffix or hostname.endswith("." + suffix):
            return True

    return False


def _is_internal_or_local_host(hostname):

    hostname = (hostname or "").lower()

    if not hostname:
        return True  # unparseable - never treated as "fine to send"

    if hostname in _LOCAL_HOSTNAMES:
        return True

    for suffix in _INTERNAL_SUFFIXES:
        if hostname == suffix.lstrip(".") or hostname.endswith(suffix):
            return True

    # An IP-literal host (canonical dotted-decimal, or bracketed IPv6 -
    # urlparse already strips the brackets into .hostname): block
    # loopback/private/link-local/reserved.
    try:
        addr = ipaddress.ip_address(hostname)
        return bool(
            addr.is_loopback or addr.is_private or addr.is_link_local
            or addr.is_reserved or addr.is_multicast or addr.is_unspecified
        )
    except ValueError:
        pass

    # Step 24B.1.1 Task 2 fix: non-canonical legacy IPv4 encodings
    # (decimal/octal/hex, with or without dots - e.g. "2130706433",
    # "0x7f.0.0.1", "127.1", "0177.0.0.1" ALL mean 127.0.0.1) are NOT
    # recognized by ipaddress.ip_address() above (it is deliberately
    # strict), yet still resolve to a real, possibly-private address
    # via the same legacy parsing libc's inet_aton implements and
    # Python's socket module exposes - confirmed by direct testing
    # that all of the forms above, otherwise, would have slipped past
    # this policy as if they were an ordinary domain name. IPv6 is
    # unaffected (inet_aton is IPv4-only; canonical IPv6 is already
    # handled by the ipaddress.ip_address() check above).
    try:
        legacy_ip = socket.inet_ntoa(socket.inet_aton(hostname))
        addr = ipaddress.ip_address(legacy_ip)
        return bool(
            addr.is_loopback or addr.is_private or addr.is_link_local
            or addr.is_reserved or addr.is_multicast or addr.is_unspecified
        )
    except OSError:
        pass

    # A bare single-label hostname (no dot at all) - e.g. "intranet",
    # "printer01" - is conservatively treated as internal; a real
    # public hostname always has at least one dot.
    if "." not in hostname:
        return True

    return False


def _path_looks_sensitive(path):

    path = (path or "").lower()

    for segment in path.split("/"):
        for keyword in _SENSITIVE_PATH_KEYWORDS:
            if keyword in segment:
                return True

    return False


def url_is_safe_to_send_externally(url, excluded_domains=None):
    """
    Returns (True, None) only if EVERY check below passes; otherwise
    (False, "<specific reason>"). Called immediately before every
    external URL-intel request (manual investigate button) - never
    bypassed, never cached as a one-time decision (checked fresh every
    time, since policy/.env can change between calls).
    """

    if not url or not isinstance(url, str):
        return False, "url is missing or not a string"

    if len(url) > MAX_URL_LENGTH:
        return False, "url exceeds the maximum allowed length"

    if any(ch.isspace() for ch in url):
        return False, "url contains whitespace"

    if not (url.startswith("http://") or url.startswith("https://")):
        return False, "only http:// and https:// URLs may be sent externally"

    if "?" in url or "#" in url:
        return False, "url contains a query string or fragment - never sent externally"

    try:
        parsed = urlparse(url)
    except ValueError:
        return False, "url could not be parsed"

    if "@" in (parsed.netloc or ""):
        return False, "url appears to contain embedded credentials"

    hostname = parsed.hostname

    if not hostname:
        return False, "url has no identifiable host"

    if _is_internal_or_local_host(hostname):
        return False, "url targets an internal, local, or non-public host"

    excluded_domains = excluded_domains if excluded_domains is not None else _env_excluded_domains()

    if _is_excluded_domain(hostname, excluded_domains):
        return False, "domain is on the organizational exclusion list"

    if _path_looks_sensitive(parsed.path):
        return False, "url path may contain sensitive information"

    return True, None
