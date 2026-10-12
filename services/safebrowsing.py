"""Google Safe Browsing: URL canonicalization, host-suffix / path-prefix expressions and hashing (Phase F3.2). Pure functions, standard library only (Python 3.8).

This follows Google's published procedure ("URLs and Hashing": https://developers.google.com/safe-browsing/v4/urls-hashing, which the v5 API reuses) step by step, and
tests/test_phaseF32.py runs the documented test vectors against it:

  canonicalization   remove tab/CR/LF; remove the fragment; percent-unescape repeatedly; hostname: strip leading/trailing dots, collapse dots, normalise any legal IP form
                     (decimal, octal, hex, fewer than four parts) to four decimal values, lowercase; path: resolve /./ and /../ and collapse slashes (not in the query);
                     finally percent-escape every character <= 32, >= 127, '#' and '%' with UPPERCASE hex.
  host expressions   the exact host plus up to four more made from its LAST FIVE labels by dropping the leading label (never the top-level label alone; none for an IP).
  path expressions   the exact path with the query, the exact path without the query, and up to four directory prefixes from the root (with the trailing slash).
  hashing            SHA-256 of "host/path"; hashes.search receives only the first 4 bytes of each (base64) and returns full hashes, which are compared in full here.

PRIVACY: whatever the scope (host only, or host and path) only 4-byte hash prefixes leave this computer. A path-level check uses the URL's path, never its query or fragment
(the application stores no query), and the web address itself is never sent.
"""
import base64
import hashlib
import re
from urllib.parse import unquote_to_bytes

MAX_HOST_EXPRESSIONS = 5
MAX_PATH_DIRECTORY_PREFIXES = 4
_DURATION = re.compile(r"^\s*(\d+(?:\.\d+)?)s\s*$")


def _unescape_repeatedly(text):
    try:
        data = text.encode("latin-1")                 # a character below 256 is one byte (the documented vectors use raw bytes such as ) ...
    except UnicodeEncodeError:
        data = text.encode("utf-8")                   # ... anything else is sent as its UTF-8 bytes
    while True:
        new = unquote_to_bytes(data)
        if new == data:
            return data
        data = new


def _escape(data):
    out = []
    for byte in data:
        if byte <= 32 or byte >= 127 or byte in (0x23, 0x25):
            out.append("%%%02X" % byte)
        else:
            out.append(chr(byte))
    return "".join(out)


def _ip_component(text):
    """One IP component in decimal, octal (leading 0) or hex (0x); None when it is not a number."""
    try:
        if text.lower().startswith("0x"):
            return int(text[2:] or "0", 16)
        if len(text) > 1 and text.startswith("0"):
            return int(text, 8)
        return int(text, 10) if text.isdigit() else None
    except ValueError:
        return None


def normalise_ip(host):
    """'3279880203' / '0xC3.0x7F.0.0xB' / '195.127.11' -> '195.127.0.11'; None when the host is not an IP address in any legal encoding."""
    parts = host.split(".")
    if not 1 <= len(parts) <= 4:
        return None
    values = [_ip_component(p) for p in parts]
    if any(v is None or v < 0 for v in values):
        return None
    *leading, last = values
    if any(v > 255 for v in leading) or last >= 256 ** (4 - len(leading)):
        return None
    number = 0
    for v in leading:
        number = number * 256 + v
    number = number * 256 ** (4 - len(leading)) + last
    return ".".join(str((number >> shift) & 255) for shift in (24, 16, 8, 0))


def canonicalize(url):
    """The canonical form of a URL as Safe Browsing defines it: 'scheme://host/path[?query]'. A bare 'host/path' gets 'http://'."""
    text = (url or "").strip()
    text = text.replace("\t", "").replace("\r", "").replace("\n", "")
    text = text.split("#", 1)[0]
    data = _unescape_repeatedly(text)
    decoded = data.decode("latin-1")                      # one character per byte from here on, so the escaping below works on bytes
    scheme = "http"
    match = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*)://", decoded)
    if match:
        scheme, decoded = match.group(1).lower(), decoded[match.end():]
    end = len(decoded)
    for terminator in "/?":
        position = decoded.find(terminator)
        if position != -1:
            end = min(end, position)
    authority, rest = decoded[:end], decoded[end:]
    if "@" in authority:
        authority = authority.rsplit("@", 1)[1]
    authority = re.sub(r":\d*$", "", authority)           # a port is not part of the key
    host = re.sub(r"\.+", ".", authority.strip(".")).lower()
    ip = normalise_ip(host) if host else None
    if ip:
        host = ip
    query = None
    if "?" in rest:
        rest, query = rest.split("?", 1)
    path = rest if rest.startswith("/") or not rest else "/" + rest
    segments = path.split("/")
    kept = []
    for segment in segments:
        if segment in ("", "."):
            continue
        if segment == "..":
            if kept:
                kept.pop()
            continue
        kept.append(segment)
    trailing = path.endswith("/") or (bool(segments) and segments[-1] in (".", ".."))
    path = "/" + "/".join(kept) + ("/" if kept and trailing else "")
    out = "%s://%s%s" % (scheme, _escape(host.encode("latin-1")), _escape(path.encode("latin-1")))
    if query is not None:
        out += "?" + _escape(query.encode("latin-1"))
    return out


def split_canonical(canonical):
    """'http://host/path?query' -> (scheme, host, path, query-or-None) of an already canonical URL."""
    scheme, _, remainder = canonical.partition("://")
    host, slash, rest = remainder.partition("/")
    rest = slash + rest
    path, question, query = rest.partition("?")
    return scheme, host, path, (query if question else None)


def host_expressions(host):
    """The host and up to four suffixes (see the module text); an IP address is used as it is."""
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
        return [host]
    labels = host.split(".")
    found = [host]
    tail = labels[-5:]
    for start in range(len(tail) - 1):
        candidate = ".".join(tail[start:])
        if candidate not in found:
            found.append(candidate)
    return found[:MAX_HOST_EXPRESSIONS]


def path_expressions(path, query):
    """The exact path with the query, the exact path, then up to four directory prefixes from the root."""
    found = []
    if query is not None:
        found.append(path + "?" + query)
    found.append(path)
    directories = [part for part in path.split("/")[1:-1]]
    prefix = "/"
    if prefix not in found:
        found.append(prefix)
    for part in directories[:MAX_PATH_DIRECTORY_PREFIXES - 1]:
        prefix = prefix + part + "/"
        if prefix not in found:
            found.append(prefix)
    return found


def url_expressions(url):
    """Every 'host/path' expression Safe Browsing checks for this URL (at most 5 x 6 = 30), most specific first, host-major as in Google's worked example."""
    _, host, path, query = split_canonical(canonicalize(url))
    return [h + p for h in host_expressions(host) for p in path_expressions(path, query)]


def host_level_expressions(domain):
    """The expressions for a bare domain: each host variant with the root path only. This is what the domain-level cache can honestly hold."""
    _, host, _, _ = split_canonical(canonicalize("http://%s/" % (domain or "").strip()))
    if not host:
        return []
    return [h + "/" for h in host_expressions(host)]


def full_hash(expression):
    return hashlib.sha256(expression.encode("latin-1", "replace")).digest()


def prefix_b64(expression, padded=False):
    """The first 4 bytes of the SHA-256 in base64. Unpadded by default, the form of Google's own worked example ('hashPrefixes=WwuJdQ' is the prefix of
    testsafebrowsing.appspot.com/s/malware.html); the protobuf JSON rules accept padded and unpadded forms alike, and the REST reference shows the padded one."""
    text = base64.b64encode(full_hash(expression)[:4]).decode("ascii")
    return text if padded else text.rstrip("=")


def parse_cache_duration(text, default_seconds=300):
    """'300s' / '3.5s' -> seconds (float). Anything else (missing, malformed, negative) -> the default: a short, conservative validity, never a long one."""
    match = _DURATION.match(text) if isinstance(text, str) else None
    if not match:
        return float(default_seconds)
    return float(match.group(1))
