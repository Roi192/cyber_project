"""Which page addresses may be checked at ADDRESS level (Google Safe Browsing lookup_url), and which must never leave the machine - even as a 4-byte hash prefix.

A page address (scheme + host + path; the application has already dropped the query, the fragment and any user:password part) is eligible only when
  * it is http or https and its path says something about a page ("/" alone is the host, which the host-level check already covers), and
  * the path does not look like it carries a private link or a secret.

The second rule is a HEURISTIC. It recognises common shapes: password-reset / recovery / activation / invitation words, authentication and OAuth/SAML callback words, words such as
token / secret / session / key, JWTs, UUIDs, long hexadecimal or base64-like identifiers, long digit runs, `name=value` path parameters (";jsessionid=...") and over-long paths. It is
deliberately cautious (a false "sensitive" only means the page was not checked at address level; the host still is) - and it CANNOT guarantee that every sensitive path is
recognised: a secret that looks like an ordinary word, or a short token, passes. Only 4-byte SHA-256 prefixes of path prefixes are ever sent, which reveals very little, but it is not nothing.

Percent-encoding (Phase F3.11): the path is screened as sent AND after decoding, up to MAX_DECODE_ROUNDS times, so `/%72eset`, `/a%2Freset` (an encoded slash) and double-encoded
forms are caught. Decoding is conservative and bounded: a malformed escape (a `%` not followed by two hex digits), bytes that are not valid UTF-8, a control character (`%00`), a
decoded path longer than MAX_PATH_LENGTH, or text that is STILL encoded after the last round all mean "skip" - never "safe". Fullwidth and similar look-alike letters are folded
(NFKC) before the words are compared. Decoding is only used for screening: the address that is hashed and looked up is the sanitized address exactly as the application stored it.

Nothing here returns, logs or stores the path: a result is a verdict plus a short generic code. Standard library only; Python 3.8 compatible.
"""
import hashlib
import math
import re
import unicodedata
from urllib.parse import unquote_to_bytes, urlsplit

MAX_PATH_LENGTH = 300
MAX_DECODE_ROUNDS = 3
_BAD_PERCENT = re.compile(r"%(?![0-9A-Fa-f]{2})")
SENSITIVE_WORDS = frozenset("""
reset resetpassword forgot forgotten forgetpassword recover recovery restore password passwd pwd passcode passphrase
token tokens accesstoken refreshtoken idtoken bearer jwt secret secrets apikey apikeys credential credentials
callback oauth oauth2 openid oidc saml sso auth authorize authorization authenticate signin2fa twofactor otp mfa totp
activate activation invite invitation invited magic magiclink verify verification confirm confirmation unsubscribe optout
session sessionid sid sig signature signed presigned
""".split())
_WORD_SPLIT = re.compile(r"[^a-z0-9]+")
_UUID = re.compile(r"^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$", re.I)
_JWT = re.compile(r"^eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*$")
_HEX = re.compile(r"^[0-9a-fA-F]+$")


def _entropy(text):
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum(n / len(text) * math.log(n / len(text), 2) for n in counts.values())


def _looks_like_identifier(word):
    """A run of letters and digits that looks like a generated identifier rather than a word."""
    if len(word) >= 16 and _HEX.match(word):
        return True                                           # md5 / sha / random hex id
    if len(word) >= 16 and word.isdigit():
        return True                                           # long numeric id (order, account, card-like)
    if len(word) >= 20 and any(c.isdigit() for c in word) and any(c.isalpha() for c in word) and _entropy(word) >= 3.0:
        return True                                           # mixed letters and digits: base32 / base62 token
    if len(word) >= 24 and word.isalpha() and _entropy(word) >= 3.9:
        return True                                           # a long run of random-looking letters
    return False


def _decoded_variants(path):
    """([path as sent, then each decoded round], problem). problem is a generic code when the encoding cannot be trusted, else None. Bounded: at most MAX_DECODE_ROUNDS rounds."""
    variants = [path]
    current = path
    for _ in range(MAX_DECODE_ROUNDS):
        if "%" not in current:
            return variants, None
        if _BAD_PERCENT.search(current):
            return variants, "malformed-encoding"
        try:
            decoded = unquote_to_bytes(current).decode("utf-8")
        except UnicodeDecodeError:
            return variants, "malformed-encoding"
        if any(ord(c) < 32 or ord(c) == 127 for c in decoded):
            return variants, "malformed-encoding"
        if len(decoded) > MAX_PATH_LENGTH:
            return variants, "over-long-path"
        variants.append(decoded)
        current = decoded
    return variants, ("over-encoded" if "%" in current else None)


def sensitive_reason(path):
    """None when the path looks ordinary, else a short GENERIC code (never any part of the path). The path is screened as sent and after (bounded) percent-decoding."""
    if len(path) > MAX_PATH_LENGTH:
        return "over-long-path"
    variants, problem = _decoded_variants(path)
    if problem:
        return problem
    for variant in variants:
        code = _screen(unicodedata.normalize("NFKC", variant))
        if code:
            return code
    return None


def _screen(path):
    """The shape rules, applied to one (already decoded) form of the path."""
    segments = [s for s in path.split("/") if s]
    for segment in segments:
        if ";" in segment or "=" in segment:
            return "path-parameter"                           # e.g. ;jsessionid=... or /a=secret
        if _JWT.match(segment) or segment.count(".") >= 2 and segment.startswith("eyJ"):
            return "token-pattern"
        if _UUID.match(segment):
            return "token-pattern"
        stem = segment.rsplit(".", 1)[0] if "." in segment else segment
        for word in _WORD_SPLIT.split(segment.lower()):
            if word in SENSITIVE_WORDS:
                return "sensitive-word"
        pieces = [w for w in re.split(r"[-_.~]+", stem) if w]
        if any(_looks_like_identifier(w) for w in pieces) or _looks_like_identifier(stem.replace("-", "").replace("_", "")):
            return "high-entropy-identifier"
    return None


def assess(sanitized_url):
    """{"eligible": bool, "skip": None | "not-http" | "no-path" | "sensitive", "code": generic reason code or None}. Never contains any part of the address."""
    try:
        parts = urlsplit(sanitized_url or "")
    except ValueError:
        return {"eligible": False, "skip": "not-http", "code": "unparseable"}
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return {"eligible": False, "skip": "not-http", "code": "not-http"}
    path = parts.path or "/"
    if path.strip("/") == "":
        return {"eligible": False, "skip": "no-path", "code": "no-path"}
    code = sensitive_reason(path)
    if code:
        return {"eligible": False, "skip": "sensitive", "code": code}
    return {"eligible": True, "skip": None, "code": None}


def url_key(expressions):
    """The cache key of an address check: SHA-256 of the exact expression set the provider is asked about (so equal questions share one answer). It cannot be reversed to the address."""
    return hashlib.sha256("\n".join(sorted(expressions)).encode("latin-1", "replace")).hexdigest()


def display_path(sanitized_url):
    """The path of an eligible address, for the person reading an alert. Only ever called for an address that passed assess() (a sensitive path is never shown)."""
    return urlsplit(sanitized_url).path or "/"
