"""Input validation and privacy sanitization for data sent by endpoints.

Nothing from the client is trusted: every field is type-checked, length-
limited and normalized. URLs lose their query string, fragment and any
embedded credentials before they are stored or shown.
"""
import ipaddress
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

# Names that exist only inside a network or as DNS plumbing. The Windows agent sees every
# lookup a computer makes, including these; they are not Internet destinations, so the
# network-event route ignores them (the agent also drops them before sending).
NON_PUBLIC_TOP_LABELS = ("arpa", "local", "localhost", "localdomain", "internal", "lan", "home", "corp", "invalid")
AGENT_VERSION_PATTERN = re.compile(r"^[0-9A-Za-z.+\-]{1,32}$")
# A program file name only: letters/digits (any language), space, dot, underscore, parentheses, plus, dash.
# No slash, backslash, colon or quote, so a path or a command line can never fit.
PROCESS_NAME_PATTERN = re.compile(r"^\w[\w .()+\-]{0,63}$")
PROCESS_KINDS = ("BROWSER", "SYSTEM", "APPLICATION", "UNKNOWN")
MAX_PID = 4294967295


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


def is_non_public_domain(domain):
    """True for internal / infrastructure names (for example x.in-addr.arpa, printer.local, nas.lan)."""
    return domain.rsplit(".", 1)[-1] in NON_PUBLIC_TOP_LABELS


def validate_agent_version(value):
    value = _text(value, "agent_version", 32, required=False)
    if value is None:
        return None
    if not AGENT_VERSION_PATTERN.match(value):
        raise ValidationError("agent_version may only contain letters, digits, dot, plus and dash")
    return value


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


HISTORY_BROWSERS = ("Chrome", "Edge")


def validate_history_browsers(value):
    """The browsers whose history the agent can read right now (Chrome, Edge), as a sorted comma list; '' for none.
    Anything that is not a known history browser is ignored."""
    if not isinstance(value, (list, tuple)):
        return ""
    return ",".join(sorted(set(item for item in value if item in HISTORY_BROWSERS)))


def _uid(value, field):
    value = _text(value, field, 64)
    if not UID_PATTERN.match(value):
        raise ValidationError("%s may only contain letters, digits, dash and underscore" % field)
    return value


def validate_enrollment(data):
    """The Windows agent announcing its device: a random device UID, its own sensor UID, its name and version."""
    if not isinstance(data, dict):
        raise ValidationError("a JSON object is expected")
    return {
        "device_uid": _uid(data.get("device_uid"), "device_uid"),
        "sensor_uid": _uid(data.get("sensor_uid"), "sensor_uid"),
        "computer_name": _text(data.get("computer_name"), "computer_name", 100),
        "agent_version": validate_agent_version(data.get("agent_version")),
    }


def validate_grant_request(data):
    """An enrolled agent asking permission for one extension installation to join its device."""
    if not isinstance(data, dict):
        raise ValidationError("a JSON object is expected")
    return {"endpoint_uid": validate_endpoint_uid(data.get("endpoint_uid")), "sensor_uid": _uid(data.get("sensor_uid"), "sensor_uid")}


def validate_pairing(data):
    """An extension installation presenting a grant."""
    if not isinstance(data, dict):
        raise ValidationError("a JSON object is expected")
    grant = _text(data.get("grant"), "grant", 128)
    browser = data.get("browser")
    return {
        "grant": grant,
        "endpoint_uid": validate_endpoint_uid(data.get("endpoint_uid")),
        "computer_name": _text(data.get("computer_name"), "computer_name", 100),
        "username": _text(data.get("username"), "username", 100, required=False),
        "browser": validate_browser(browser) if browser not in (None, "") else None,
        "sensor_version": validate_agent_version(data.get("sensor_version")),
    }


def validate_registration(data):
    if not isinstance(data, dict):
        raise ValidationError("a JSON object is expected")
    browser = data.get("browser")
    return {
        # only the Windows agent sends this; the key being present (even empty) is the current truth, absent keeps what is stored
        "history_browsers": validate_history_browsers(data.get("history_browsers")) if "history_browsers" in data else None,
        "endpoint_uid": validate_endpoint_uid(data.get("endpoint_uid")),
        "computer_name": _text(data.get("computer_name"), "computer_name", 100),
        "username": _text(data.get("username"), "username", 100, required=False),
        # when the client sends a "username" key (even empty) it is authoritative,
        # so the label can be changed or cleared; when absent the stored one is kept
        "username_provided": "username" in data,
        "browser": validate_browser(browser) if browser not in (None, "") else None,
        # only the Windows agent sends this; absent keeps what the server already knows
        "agent_version": validate_agent_version(data.get("agent_version")),
        # only a browser extension sends this (its own version); optional and purely informational
        "sensor_version": validate_agent_version(data.get("sensor_version")),
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


def normalize_destination_ip(value):
    """A destination IP address as the network agent saw it: IPv4 or IPv6, no port, no zone id.
    An IPv4-mapped IPv6 address is reduced to the IPv4 address; the result is the canonical text."""
    text = _text(value, "destination_ip", 64)
    if "%" in text:
        raise ValidationError("destination_ip must not contain a zone id")
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        raise ValidationError("destination_ip is not a valid IP address")
    mapped = getattr(address, "ipv4_mapped", None)
    return str(mapped if mapped is not None else address)


def is_public_address(text):
    """True for an address on the public internet. Private, loopback, link-local, shared (carrier-grade
    NAT), documentation and multicast ranges are not public: they say nothing about an outside website."""
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return False
    # Python calls some multicast ranges "global"; a multicast group is not a website on the internet.
    return address.is_global and not address.is_multicast


def validate_process_name(value):
    """The file name of the program (never a path, never a command line), or None when it is not
    usable. A name that does not fit the allowed shape is dropped rather than rejecting the whole
    observation: the connection still happened, only the program label is unknown."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value if PROCESS_NAME_PATTERN.match(value) else None


def validate_process_kind(value):
    return value.strip().upper() if isinstance(value, str) and value.strip().upper() in PROCESS_KINDS else "UNKNOWN"


def validate_pid(value):
    """A process id is transient diagnostic information only; anything unusable becomes None."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 1 <= value <= MAX_PID else None


def validate_network_event(data):
    """One observation from the Windows network agent.

    Two kinds, never mixed in one event:
      * {"domain": ...}          this computer looked up a domain name (DNS-cache collector)
      * {"destination_ip": ...}  a program on this computer opened a connection to a public IP
                                 address (native collector); no domain is claimed or invented
    The native collector may add process_name (a file name only), process_kind and pid.

    Everything else is deliberately absent: no URL, path, query, command line, port or payload -
    a lookup or a connection shows none of them, and a field the server accepted but could not
    trust would only invite false claims. Any extra field a client sends is ignored, never stored.
    """
    if not isinstance(data, dict):
        raise ValidationError("a JSON object is expected")
    has_domain = data.get("domain") not in (None, "")
    has_ip = data.get("destination_ip") not in (None, "")
    if has_domain and has_ip:
        raise ValidationError("send either domain or destination_ip, not both")
    via = data.get("via")
    if via not in (None, "", "browser_history"):
        raise ValidationError("via is not recognised")
    history = via == "browser_history"          # a new local visit found in the browser's own history: a website visit, host only
    history_browser = None
    if history:
        if has_ip:
            raise ValidationError("a browser-history event carries a domain, not an address")
        history_browser = validate_browser(data.get("browser"))
        if history_browser not in HISTORY_BROWSERS:
            raise ValidationError("browser must be Chrome or Edge")
    event = {
        "endpoint_uid": validate_endpoint_uid(data.get("endpoint_uid")),
        "computer_name": _text(data.get("computer_name"), "computer_name", 100),
        "username": _text(data.get("username"), "username", 100, required=False),
        "username_provided": "username" in data,
        "agent_version": validate_agent_version(data.get("agent_version")),
        "domain": None if has_ip else normalize_domain(data.get("domain")),
        "destination_ip": normalize_destination_ip(data.get("destination_ip")) if has_ip else None,
        "observed_at": validate_timestamp(data.get("timestamp")),
        "process_name": None, "process_kind": None, "pid": None,
        "via": "BROWSER_HISTORY" if history else None, "browser": history_browser,
    }
    if has_ip:           # program details only travel with a connection observation
        event["process_name"] = validate_process_name(data.get("process_name"))
        event["process_kind"] = validate_process_kind(data.get("process_kind"))
        event["pid"] = validate_pid(data.get("pid"))
    return event
