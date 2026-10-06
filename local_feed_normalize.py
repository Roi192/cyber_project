# ==================================================
# STEP 24B.2A: LOCAL THREAT INTELLIGENCE FEED - DETERMINISTIC NORMALIZATION
# ==================================================
#
# Used identically on BOTH sides of a match: when a feed record is
# ingested (local_feed_store.ingest_snapshot) and when an event's
# candidate indicator is looked up (local_feed_evidence.py) - the SAME
# functions are called in both places so the two sides can never drift
# apart. Deliberately NOT threat_intel_framework.normalize_*_candidate:
# those are validate-and-pass-through functions for a different purpose
# (event candidate generation) and do not perform the matching-grade
# normalization (IDNA, default-port removal, percent-encoding
# canonicalization) this module requires.
#
# Approved rules (Step 24B.2A instructions) - deterministic and
# conservative:
#   ALLOWED : lowercase scheme; lowercase/canonical IDNA hostname;
#             remove a DEFAULT port only (80 for http, 443 for https);
#             canonicalize percent-encoding case (%2f -> %2F) without
#             decoding; remove the fragment (never part of any HTTP
#             request, so never part of a match).
#   FORBIDDEN in this step: stripping a trailing slash from a non-empty
#             path, prefix/path matching, fuzzy matching, any decoding
#             that could change meaning. "/login" and "/login/" are
#             different normalized values and must never collide.
#   QUERY STRING: preserved verbatim (after percent-encoding
#             canonicalization only) as part of the normalized key - a
#             feed URL with a query and a browser event URL without one
#             (browser collection strips query/fragment for privacy,
#             unchanged by this step) are NOT the same normalized value
#             and must never produce a MATCH.
#
# Every function here follows the same convention as
# threat_intel_framework.normalize_*_candidate: validate and either
# return the normalized value or None - never guess, never repair a
# genuinely malformed input.
# ==================================================

import ipaddress
import re
from urllib.parse import urlsplit

_PERCENT_RE = re.compile(r"%[0-9a-fA-F]{2}")

_DEFAULT_PORTS = {"http": 80, "https": 443}

_MAX_URL_LENGTH = 2048
_MAX_DOMAIN_LENGTH = 253


def _canonical_percent_encoding(value):

    return _PERCENT_RE.sub(lambda m: m.group(0).upper(), value)


def _normalize_hostname(host):
    """
    Lowercase + canonical IDNA/punycode. Returns None (never a guess)
    for an empty, malformed, or unencodable hostname (e.g. an empty
    label from "a..b", a label over 63 chars). An already-ASCII
    hostname (including an IP literal or an already-punycode name)
    passes through unchanged except for lowercasing - confirmed
    directly against Python's built-in idna codec before relying on it.
    """

    if not host:
        return None

    try:
        encoded = host.encode("idna")
    except UnicodeError:
        return None

    try:
        decoded = encoded.decode("ascii")
    except UnicodeDecodeError:
        return None

    return decoded.lower()


def normalize_url_for_matching(url):

    if not url or not isinstance(url, str):
        return None

    if any(ch.isspace() for ch in url):
        return None

    if len(url) > _MAX_URL_LENGTH:
        return None

    try:
        parsed = urlsplit(url)
    except ValueError:
        return None

    scheme = parsed.scheme.lower()

    if scheme not in _DEFAULT_PORTS:
        return None

    if not parsed.hostname:
        return None

    host = _normalize_hostname(parsed.hostname)

    if host is None:
        return None

    try:
        port = parsed.port
    except ValueError:
        return None  # malformed port (non-numeric / out of range)

    if port is not None and port == _DEFAULT_PORTS[scheme]:
        port = None

    port_suffix = f":{port}" if port is not None else ""

    # Path is preserved EXACTLY as parsed (including an empty path for
    # "scheme://host" with no trailing slash, and a trailing slash for
    # "scheme://host/path/") - percent-encoding is canonicalized only,
    # never decoded, never trimmed.
    path = _canonical_percent_encoding(parsed.path or "")

    # Query string is preserved verbatim (after percent-encoding
    # canonicalization) - see module header. `has_query` is based on
    # literal "?" presence before any fragment (not on parsed.query
    # truthiness), so "no query" and "present-but-empty query (?)"
    # stay distinguishable from each other and from "has a query".
    has_query = "?" in url.split("#", 1)[0]
    query_suffix = f"?{_canonical_percent_encoding(parsed.query)}" if has_query else ""

    # Fragment is intentionally dropped entirely - never part of a
    # match (see module header).

    return f"{scheme}://{host}{port_suffix}{path}{query_suffix}"


def normalize_domain_for_matching(domain):

    if not domain or not isinstance(domain, str):
        return None

    if any(ch.isspace() for ch in domain):
        return None

    candidate = domain

    if candidate.endswith("."):
        candidate = candidate[:-1]

    if not candidate or len(candidate) > _MAX_DOMAIN_LENGTH:
        return None

    # An IP-shaped value must never become a DOMAIN candidate (same
    # rule as threat_intel_framework.normalize_domain_candidate) - IP
    # and DOMAIN are separate indicator scopes, never interchangeable.
    try:
        ipaddress.ip_address(candidate)
        return None
    except ValueError:
        pass

    return _normalize_hostname(candidate)


def normalize_ip_for_matching(ip_value):

    if not ip_value or not isinstance(ip_value, str):
        return None

    if any(ch.isspace() for ch in ip_value):
        return None

    try:
        return str(ipaddress.ip_address(ip_value))
    except ValueError:
        return None


_NORMALIZERS = {
    "URL": normalize_url_for_matching,
    "DOMAIN": normalize_domain_for_matching,
    "IP": normalize_ip_for_matching,
}


def classify_and_normalize(indicator_type, raw_value):
    """
    Single entry point used by BOTH the feed-ingest side and the
    event-lookup side (see module header). indicator_type is always
    explicit (supplied by the feed record's own format, or by the
    event-candidate builder) - this function never GUESSES a type from
    an unlabeled string, which would be a form of fuzzy matching.
    Returns (normalized_indicator_type, normalized_value), or
    (None, None) if the type is unsupported or the value does not
    normalize to anything usable.
    """

    if not indicator_type or not isinstance(indicator_type, str):
        return None, None

    key = indicator_type.strip().upper()
    normalizer = _NORMALIZERS.get(key)

    if normalizer is None:
        return None, None

    normalized_value = normalizer(raw_value)

    if normalized_value is None:
        return None, None

    return key, normalized_value
