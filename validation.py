"""Input validation and privacy sanitization for data sent by endpoints.

Nothing from the client is trusted: every field is type-checked, length-
limited and normalized. URLs lose their query string, fragment and any
embedded credentials before they are stored or shown.
"""
import re
from datetime import datetime
from urllib.parse import urlsplit, urlunsplit

MAX_URL_LENGTH = 2048
UID_PATTERN = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")
LABEL_PATTERN = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
KNOWN_BROWSERS = ("Chrome", "Edge", "Firefox", "Safari", "Opera", "Brave")

# Navigations the BROWSER makes by itself (not the employee). Each entry is an
# exact host plus an exact path, so ordinary browsing to the same company
# (www.msn.com, msn.com/en-us/...) is never affected. Keep this list tiny and
# add a pattern only after observing it in real traffic. Mirrored in
# browser_extension/common.js (BROWSER_NOISE).
#   ntp.msn.com + /edge/ntp  -> the Microsoft Edge "New Tab Page"
BROWSER_NOISE = (("ntp.msn.com", "/edge/ntp"),)


class ValidationError(ValueError):
    pass


def _text(value, field, max_len, required=True):
    if value is None or (isinstance(value, str) and value.strip() == ""):
        if required:
            raise ValidationError("%s is required" % field)
        return None
    if not isinstance(value, str):
        raise ValidationError("%s must be a string" % field)
    value = value.strip()
    if len(value) > max_len:
        raise ValidationError("%s is too long (max %d)" % (field, max_len))
    if any(ord(ch) < 32 for ch in value):
        raise ValidationError("%s contains control characters" % field)
    return value


def validate_endpoint_uid(value):
    value = _text(value, "endpoint_uid", 64)
    if not UID_PATTERN.match(value):
        raise ValidationError("endpoint_uid may only contain letters, digits, dash and underscore")
    return value


def normalize_domain(value):
    """Lower-case, strip trailing dot and port, require a real hostname
    with at least two labels. Bare IP addresses and URLs are rejected -
    monitoring is domain-level only."""
    value = _text(value, "domain", 253).lower().rstrip(".")
    if "/" in value or "@" in value or value.startswith("http"):
        raise ValidationError("domain must be a hostname, not a URL")
    if ":" in value:
        value = value.split(":", 1)[0]
    labels = value.split(".")
    if len(labels) < 2 or not all(LABEL_PATTERN.match(label) for label in labels):
        raise ValidationError("domain is not a valid hostname")
    if all(label.isdigit() for label in labels):
        raise ValidationError("bare IP addresses are not accepted")
    return value


def sanitize_url(value, domain):
    """Keep scheme + host + path only. Query string, fragment and any
    user:password part are dropped. The host must equal `domain`."""
    value = _text(value, "url", MAX_URL_LENGTH, required=False)
    if value is None:
        return None
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https"):
        raise ValidationError("url must use http or https")
    host = (parts.hostname or "").lower().rstrip(".")
    if host != domain:
        raise ValidationError("url host does not match domain")
    path = parts.path or "/"
    return urlunsplit((parts.scheme, host, path, "", ""))


def is_browser_noise(domain, sanitized_url):
    """True when this visit is a known browser-generated page (see BROWSER_NOISE).
    Without a URL the path is unknown, so nothing is ever treated as noise."""
    if not sanitized_url:
        return False
    path = urlsplit(sanitized_url).path.rstrip("/")
    return any(domain == host and path == noise_path for host, noise_path in BROWSER_NOISE)


def validate_browser(value):
    value = _text(value, "browser", 50, required=False)
    if value is None:
        return "Other"
    for known in KNOWN_BROWSERS:
        if value.lower().startswith(known.lower()):
            return known
    return "Other"


def validate_timestamp(value):
    """Accept ISO-8601 (with or without T / Z / offset / fraction).
    Missing timestamp means now."""
    if value is None or str(value).strip() == "":
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    text = str(value).strip().replace("T", " ").replace("Z", "")
    text = text.split("+")[0].split(".")[0]
    try:
        return datetime.strptime(text, "%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        raise ValidationError("timestamp must be ISO-8601, e.g. 2026-10-06T12:00:00")


def validate_registration(data):
    if not isinstance(data, dict):
        raise ValidationError("a JSON object is expected")
    browser = data.get("browser")
    return {
        "endpoint_uid": validate_endpoint_uid(data.get("endpoint_uid")),
        "computer_name": _text(data.get("computer_name"), "computer_name", 100),
        "username": _text(data.get("username"), "username", 100, required=False),
        # when the client sends a "username" key (even empty) it is authoritative,
        # so the label can be changed or cleared; when absent the stored one is kept
        "username_provided": "username" in data,
        "browser": validate_browser(browser) if browser not in (None, "") else None,
    }


def validate_web_event(data):
    if not isinstance(data, dict):
        raise ValidationError("a JSON object is expected")
    domain = normalize_domain(data.get("domain"))
    event = {
        "endpoint_uid": validate_endpoint_uid(data.get("endpoint_uid")),
        "computer_name": _text(data.get("computer_name"), "computer_name", 100),
        "username": _text(data.get("username"), "username", 100, required=False),
        "username_provided": "username" in data,
        "domain": domain,
        "sanitized_url": sanitize_url(data.get("url"), domain),
        "browser": validate_browser(data.get("browser")),
        "visited_at": validate_timestamp(data.get("timestamp")),
    }
    # "Other" means "not reported" - do not overwrite a known browser with it
    event["endpoint_browser"] = event["browser"] if event["browser"] != "Other" else None
    return event
