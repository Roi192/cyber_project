"""Domain reputation: check_domain(conn, domain) -> {"status", "source", "reason"}.

Statuses: SAFE, SUSPICIOUS, MALICIOUS, UNKNOWN.

Flow:  cache (domain_reputation table, not expired)  ->  provider  ->  cache
       provider missing / cooling down / failing     ->  UNKNOWN (never raises,
                                                          never SAFE on error)

Only one provider exists (VirusTotal, active only when VT_API_KEY is set).

EVIDENCE vs DECISION (Phase 5.4).  What a provider FOUND and what the system DECIDED are separate things:
  * each provider returns a normalised result (its verdict, a short reason and - for VirusTotal - the engine counts) and
    its outcome is kept per domain and provider in the reputation_evidence table: malicious / suspicious / harmless /
    undetected / timeout counts, when it was checked, until when that evidence is reused, and - when the provider could not
    answer - why. Nothing else of the provider's response is kept (no raw payload, no URL, never the API key);
  * decide() turns the provider results into ONE overall verdict. With a single provider that is exactly the provider's own
    verdict, so the thresholds below are unchanged; with several, the most serious verdict wins (a failing provider never
    outranks a successful one and never produces SAFE);
  * the overall verdict is cached per domain (domain_reputation) as before.
A provider is any ReputationProvider: a class with a `name` and `lookup(domain)` that returns
{"status", "source", "reason", optional "evidence": {...counts}} or raises ProviderError. Adding a source is: write the class,
return it from configured_providers(), done - the event pipeline and the dashboard read only the normalised evidence.
Sources that are listed in FUTURE_PROVIDERS but not set up are shown on the analysis page as "Not configured"; no evidence is ever invented for them.

VERDICT RULES (VirusTotal v3 /domains/{domain}, field last_analysis_stats):
    engines = harmless + malicious + suspicious + undetected + timeout
    engines == 0                       -> UNKNOWN  (nobody analysed it)
    malicious >= 3                     -> MALICIOUS
    1 <= malicious <= 2 or suspicious >= 2 -> SUSPICIOUS
    otherwise                          -> SAFE
    HTTP 404                           -> UNKNOWN  (domain not known to VT)
    401/403/429/5xx/timeout/network/bad JSON -> UNKNOWN + provider cooldown
Why 3: popular legitimate domains routinely carry 1-2 low-quality vendor
hits; three independent vendors is a meaningful signal.

CACHE TTLs:  SAFE 24h (REPUTATION_CACHE_HOURS) | SUSPICIOUS/MALICIOUS 6h |
             UNKNOWN 30 min.
COOLDOWNS (no provider calls while active):  429 -> 15 min | 401/403 -> 60 min |
             5xx/timeout/network/bad JSON -> 5 min.
The cooldown/status state is per process (gunicorn workers each keep their own).
"""
import base64
import hashlib
import json
import math
import re
import threading
import time
from datetime import datetime, timedelta

import requests

import config
from services import evidence, resolve, risk, safebrowsing, safebrowsing_pb, urlcheck

SAFE = "SAFE"
SUSPICIOUS = "SUSPICIOUS"
MALICIOUS = "MALICIOUS"
UNKNOWN = "UNKNOWN"
STATUSES = (SAFE, SUSPICIOUS, MALICIOUS, UNKNOWN)

TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
PROVIDER_TIMEOUT_SECONDS = 8
# Phase F3.11 - the time one telemetry request may take. The browser extension and the Windows agent give up after 5 seconds, so a request is answered well inside that:
# the host-level providers (asked in parallel when there are several) must be back within HOST_STAGE_SECONDS, and the address-level check only starts when ADDRESS_MIN_SECONDS
# are left and is given what remains (never more than its own 4 s timeout). A provider that is not back in time is recorded as UNAVAILABLE ("timeout") - never as SAFE - and
# the visit is stored all the same. One provider alone (VirusTotal only) is asked in place, exactly as before.
REQUEST_BUDGET_SECONDS = 4.0
HOST_STAGE_SECONDS = 3.2
ADDRESS_MIN_SECONDS = 0.6
# Address-level checks (one more Google request per new page) may use at most this share of Google's per-minute and per-day allowance; the rest is kept for host-level checks,
# which protect every new site. Cached answers cost nothing.
ADDRESS_BUDGET_SHARE = 0.5


class Deadline(object):
    """The clock of ONE telemetry request (monotonic). Created when the request starts and handed to check_domain / check_visit_url."""

    def __init__(self, total=None):
        self.started = time.monotonic()
        self.total = REQUEST_BUDGET_SECONDS if total is None else total

    def elapsed(self):
        return time.monotonic() - self.started

    def remaining(self):
        return max(0.0, self.total - self.elapsed())

    def host_remaining(self):
        return max(0.0, min(HOST_STAGE_SECONDS, self.total) - self.elapsed())
FAST_PROVIDER_TIMEOUT_SECONDS = 4          # Google Safe Browsing and the other list-style sources: small answers; a slow one is given up on sooner so it cannot hold a request

UNKNOWN_CACHE_MINUTES = 30
THREAT_CACHE_HOURS = 6

MALICIOUS_MIN_VENDORS = 3
SUSPICIOUS_MIN_SUSPICIOUS_VENDORS = 2

COOLDOWN_RATE_LIMIT_MINUTES = 15
COOLDOWN_AUTH_MINUTES = 60
COOLDOWN_ERROR_MINUTES = 5
OTX_TIMEOUT_COOLDOWN_MINUTES = 1

# Provider status for the dashboard (ACTIVE / NOT_CONFIGURED / TEMPORARILY_UNAVAILABLE)
STATUS_ACTIVE = "ACTIVE"
STATUS_NOT_CONFIGURED = "NOT_CONFIGURED"
STATUS_UNAVAILABLE = "TEMPORARILY_UNAVAILABLE"

# What happened when a provider was asked (shown on the analysis page; never "safe" unless CHECKED and the verdict says so)
STATE_CHECKED = "CHECKED"
STATE_UNAVAILABLE = "UNAVAILABLE"      # rate limited, server error, timeout, cooling down: try again later
STATE_ERROR = "ERROR"                  # key rejected, malformed answer, unexpected reply
STATE_NOT_CHECKED = "NOT_CHECKED"      # deliberately not asked yet (lookup budget)
STATE_NO_PROVIDER = "NO_PROVIDER"      # no provider configured
STATE_NO_EVIDENCE = "NO_EVIDENCE"      # a verdict exists but no per-provider evidence was recorded (older rows)
STATE_LABELS = {STATE_CHECKED: "Checked", STATE_UNAVAILABLE: "Provider unavailable", STATE_ERROR: "Provider error",
                STATE_NOT_CHECKED: "Not checked", STATE_NO_PROVIDER: "No provider configured",
                STATE_NO_EVIDENCE: "No detailed evidence recorded"}
EVIDENCE_KEYS = ("malicious", "suspicious", "harmless", "undetected", "timeout")      # the only evidence ever stored
# Sources the design has room for. Nothing here is called: they are only listed as "Not configured".
FUTURE_PROVIDERS = ("Google Safe Browsing", "AlienVault OTX", "urlscan.io", "APIVoid", "MetaDefender Cloud", "AbuseIPDB")
# The SEVEN sources, in display order. The last three are observation-only (risk.OBSERVED_PROVIDERS): shown, never part of a verdict, score or alert.
ALL_PROVIDERS = ("VirusTotal", "Google Safe Browsing", "AlienVault OTX", "urlscan.io", "APIVoid", "MetaDefender Cloud", "AbuseIPDB")
OBSERVED_PROVIDERS = risk.OBSERVED_PROVIDERS
# Evidence that an earlier version stored for a source the application no longer uses stays in the database untouched, but is never read back: analysis_bulk() skips these rows, so
# nothing about them reaches a page, a score, a decision or a status counter.
LEGACY_EVIDENCE_PROVIDERS = ("URLhaus",)

# Cooldown bookkeeping per provider name (only "VirusTotal" exists today).
_state = {}
_provider_cache = {"key": None, "provider": None}


def _result(status, source, reason):
    return {"status": status, "source": source, "reason": reason}


def _now():
    return datetime.now()


# --------------------------------------------------------------------
# Provider
# --------------------------------------------------------------------
def classify_error(message):
    """UNAVAILABLE for 'try again later' problems, ERROR for the rest (key rejected, malformed, unexpected)."""
    text = (message or "").lower()
    if "timeout" in text or "connection" in text or "429" in text or "rate" in text or "http 5" in text:
        return STATE_UNAVAILABLE
    return STATE_ERROR


def network_failure(error):
    """The fixed, key-free message for a failed connection, naming the reason when the exception chain shows it (Phase F3.26). Never contains the exception text, a URL or a header:
    only one of these sentences. Every sentence contains 'connection' so classify_error() keeps treating it as a temporary (UNAVAILABLE) problem. The reason is recognised by the
    exception's class name or well-known text, so that this module needs no network or TLS import."""
    seen, queue = set(), [error]
    while queue and len(seen) < 12:
        item = queue.pop(0)
        if not isinstance(item, BaseException) or id(item) in seen:
            continue
        seen.add(id(item))
        names = [c.__name__ for c in type(item).__mro__]
        text = str(item)
        if "SSLCertVerificationError" in names or "CERTIFICATE_VERIFY_FAILED" in text:
            return "connection error: TLS certificate not trusted (a proxy, antivirus or firewall that re-signs HTTPS is the usual cause)"
        if "SSLError" in names:
            return "connection error: TLS handshake failed"
        if "gaierror" in names or "NameResolutionError" in names or "getaddrinfo failed" in text or "Name or service not known" in text:
            return "connection error: DNS lookup failed"
        if isinstance(item, ConnectionRefusedError):
            return "connection error: connection refused"
        if isinstance(item, ConnectionResetError):
            return "connection error: connection reset by the server"
        queue.extend([item.__cause__, item.__context__, getattr(item, "reason", None)] + [a for a in item.args if isinstance(a, BaseException)])
    return "connection error"


class ProviderError(Exception):
    """Raised by a provider for any non-verdict outcome; carries the cooldown and what kind of problem it was."""

    def __init__(self, message, cooldown_minutes, kind=None):
        Exception.__init__(self, message)
        self.cooldown_minutes = cooldown_minutes
        self.kind = kind or classify_error(message)
        text = (message or "").lower()
        # the provider refused our credentials: opens the circuit breaker (no request is repeated with them). A rate limit that happens to wait as long (Retry-After is capped at the same 60
        # minutes) is NOT a credential problem.
        self.auth = cooldown_minutes == COOLDOWN_AUTH_MINUTES and "429" not in text and "rate limit" not in text


class ReputationProvider(object):
    """The contract of a reputation source. `name` identifies it in the evidence; lookup() answers for one domain:
        {"status": SAFE|SUSPICIOUS|MALICIOUS|UNKNOWN, "source": name, "reason": short text,
         "evidence": {optional integer counts, see EVIDENCE_KEYS}}
    or raises ProviderError(message, cooldown_minutes) when it cannot answer. It must never return or log its API key."""
    name = "provider"

    def lookup(self, domain):
        raise NotImplementedError


def retry_after_minutes(headers):
    """How long to leave a rate-limited provider alone: its Retry-After header (seconds) rounded up to whole minutes, between 1 and 60; the default when there is none or it
    is not a number. A HTTP date form is not interpreted (the default applies)."""
    try:
        seconds = float((headers or {}).get("Retry-After"))
    except (TypeError, ValueError, AttributeError):
        return COOLDOWN_RATE_LIMIT_MINUTES
    if seconds != seconds or seconds < 0:
        return COOLDOWN_RATE_LIMIT_MINUTES
    return int(max(1, min(60, math.ceil(seconds / 60.0))))


class VirusTotalProvider(ReputationProvider):
    name = "VirusTotal"
    shared_budget = True                # its requests are counted against the one provider budget (see SharedBudget)

    @staticmethod
    def budget_limits():
        return config.VT_MAX_PER_MINUTE, config.VT_MAX_PER_DAY
    url = "https://www.virustotal.com/api/v3/domains/{domain}"

    def __init__(self, api_key, session=None):
        self.api_key = api_key
        self.session = session or requests.Session()

    def lookup(self, domain):
        try:
            response = self.session.get(
                self.url.format(domain=domain),
                headers={"x-apikey": self.api_key, "accept": "application/json"},
                timeout=PROVIDER_TIMEOUT_SECONDS,
            )
        except requests.Timeout:
            raise ProviderError("timeout", COOLDOWN_ERROR_MINUTES)
        except requests.RequestException as error:
            raise ProviderError(network_failure(error), COOLDOWN_ERROR_MINUTES)

        code = response.status_code
        if code == 404:
            result = _result(UNKNOWN, self.name, "This website is not known to VirusTotal yet.")
            result["evidence"] = {}
            return result
        if code in (401, 403):
            raise ProviderError("HTTP %d (API key rejected)" % code, COOLDOWN_AUTH_MINUTES)
        if code == 429:
            raise ProviderError("HTTP 429 (rate limited)", retry_after_minutes(getattr(response, "headers", None)))
        if code >= 500:
            raise ProviderError("HTTP %d (provider error)" % code, COOLDOWN_ERROR_MINUTES)
        if code != 200:
            raise ProviderError("HTTP %d" % code, COOLDOWN_ERROR_MINUTES)

        try:
            attributes = response.json()["data"]["attributes"]
            stats = attributes["last_analysis_stats"]
            counts = dict((k, max(0, int(stats.get(k, 0)))) for k in EVIDENCE_KEYS)          # only these five numbers are kept
            malicious, suspicious = counts["malicious"], counts["suspicious"]
            engines = sum(counts.values())
            detections = evidence.vt_detections(attributes.get("last_analysis_results"))       # only the engines that FLAGGED it: name, category, result
            intel = vt_intel(attributes)
        except (ValueError, KeyError, TypeError, AttributeError):
            raise ProviderError("malformed response", COOLDOWN_ERROR_MINUTES)

        result = interpret_stats(malicious, suspicious, engines, self.name)
        result["evidence"] = counts
        assessment = evidence.assess_virustotal(counts, detections)
        result["details"] = evidence.build_details(evidence.INDICATOR_DOMAIN, assessment, detections, {evidence.INTEL_KEY: intel})          # always recorded, whatever policy decides alerts
        if config.SEVERITY_POLICY == "evidence":
            result.update(status=assessment["status"], reason=assessment["reason"], level=assessment["level"], alert_severity=assessment["alert_severity"])
        return result


def _epoch_stamp(value, with_time=True):
    """A Unix timestamp from a provider (seconds) -> text, or None for anything that is not a plausible timestamp (a bool, a string, an absurd number)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 < value < 4102444800:
        return None
    return evidence.stamp(datetime.utcfromtimestamp(value), with_time)


def vt_intel(attributes):
    """Phase F3.20: bounded context from the SAME domain answer (no extra request): when VirusTotal last analysed it, its community reputation score, how its vendors categorise the
    site, and the registrar and creation date. Deliberately NOT kept: WHOIS text (it contains contact records), tags, votes, DNS records, certificates. A key is present only when the
    answer had a usable value for it."""
    intel = {}
    when = _epoch_stamp(attributes.get("last_analysis_date"))
    if when:
        intel["last_analysis"] = when
    reputation = attributes.get("reputation")
    if isinstance(reputation, int) and not isinstance(reputation, bool) and -100000 < reputation < 100000:
        intel["reputation"] = reputation
    categories = attributes.get("categories")
    if isinstance(categories, dict):
        counts = {}
        for value in categories.values():
            text = evidence.clean_text(value if isinstance(value, str) else "", 30)
            if text:
                counts[text] = counts.get(text, 0) + 1
        intel["categories"] = [name for name, _ in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))][:6]
    registrar = evidence.clean_text(attributes.get("registrar") if isinstance(attributes.get("registrar"), str) else "", 60)
    if registrar:
        intel["registrar"] = registrar
    created = _epoch_stamp(attributes.get("creation_date"), with_time=False)
    if created:
        intel["created"] = created
    return intel


def _http_failure(code, headers=None):
    """The ProviderError for a non-200 answer, shared by the list-based providers. The message never contains a URL, a header or a key."""
    if code in (401, 403):
        return ProviderError("HTTP %d (API key rejected)" % code, COOLDOWN_AUTH_MINUTES)
    if code == 429:
        return ProviderError("HTTP 429 (rate limited)", retry_after_minutes(headers))
    if 300 <= code < 400:
        return ProviderError("HTTP %d (redirect refused)" % code, COOLDOWN_ERROR_MINUTES, kind=STATE_ERROR)          # never followed: the credential must not leave for another address
    if code >= 500:
        return ProviderError("HTTP %d (provider error)" % code, COOLDOWN_ERROR_MINUTES)
    return ProviderError("HTTP %d" % code, COOLDOWN_ERROR_MINUTES)


def _get_json(call):
    """Run one HTTP call and return (status, response). Network problems become ProviderErrors with a fixed, key-free message."""
    try:
        return call()
    except requests.Timeout:
        raise ProviderError("timeout", COOLDOWN_ERROR_MINUTES)
    except requests.RequestException as error:
        raise ProviderError(network_failure(error), COOLDOWN_ERROR_MINUTES)


def _decode_hash(text):
    """A base64 hash as Google sends it (standard or URL-safe alphabet, with or without padding) -> bytes. Anything else raises ValueError (a malformed response)."""
    if not isinstance(text, str):
        raise ValueError("fullHash")
    text = text.strip().replace("-", "+").replace("_", "/")
    return base64.b64decode((text + "=" * (-len(text) % 4)).encode("ascii"), validate=True)


safe_browsing_expressions = safebrowsing.host_level_expressions          # kept under its F3.1 name

_JSON_NAMES = {type(None): "null", bool: "a boolean", int: "a number", float: "a number", str: "a string", list: "an array", dict: "an object"}


def _json_name(value):
    return _JSON_NAMES.get(type(value), "an unexpected type")


PROTOBUF_TYPES = ("application/x-protobuf", "application/protobuf", "application/x-google-protobuf")


def _media_type(response):
    """The media type of an answer without its parameters ('application/json; charset=UTF-8' -> 'application/json'); '' when there is none."""
    headers = getattr(response, "headers", None)
    raw = headers.get("Content-Type") if headers is not None and hasattr(headers, "get") else None
    return str(raw).split(";", 1)[0].strip().lower() if raw else ""


def _answer_facts(response):
    """Safe facts about an answer for a diagnostic message: its size, whether it is binary, the KIND of its first character if it is text, its content type - never any content."""
    parts = []
    media = _media_type(response)
    content = getattr(response, "content", None)
    if isinstance(content, (bytes, bytearray)):
        parts.append("%d bytes" % len(content))
        head = bytes(content).lstrip()[:1]
        if media in PROTOBUF_TYPES:
            parts.append("binary data")
        elif head:
            kind = {b"{": "an opening brace", b"[": "an opening bracket", b"<": "a markup tag"}.get(head, "a digit" if head.isdigit() else ("a letter" if head.isalpha() else "another character"))
            parts.append("starts with %s" % kind)
    if media:
        parts.append("content type %s" % evidence.clean_text(media, 60))
    return ", ".join(parts)


def _malformed(rule, response=None):
    """The ProviderError for an answer that breaks the documented shape. Says WHICH rule failed and shows only safe facts (see _answer_facts)."""
    facts = _answer_facts(response) if response is not None else ""
    return ProviderError("malformed response: %s%s" % (rule, " (%s)" % facts if facts else ""), COOLDOWN_ERROR_MINUTES)


def _json_entries(response):
    """The JSON form (documented in the REST reference): normalised to ([{"digest": bytes(32), "details": [(threat type name, [attribute names])]}], cache seconds or None).
    Strict where the schema is; unknown fields are ignored; every field is optional at the top level."""
    try:
        body = response.json()
    except ValueError:
        raise _malformed("the body is not JSON", response)
    if not isinstance(body, dict):
        raise _malformed("the JSON is %s, not an object" % _json_name(body), response)
    entries = body.get("fullHashes")
    if entries is None:
        entries = []
    if not isinstance(entries, list):
        raise _malformed("fullHashes is %s, not an array" % _json_name(entries), response)
    duration = body.get("cacheDuration")
    if duration is not None and not isinstance(duration, str):
        raise _malformed("cacheDuration is %s, not a string" % _json_name(duration), response)
    out = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise _malformed("fullHashes[%d] is %s, not an object" % (index, _json_name(entry)), response)
        raw = entry.get("fullHash")
        if not isinstance(raw, str):
            raise _malformed("fullHashes[%d].fullHash is %s, not a string" % (index, _json_name(raw)), response)
        try:
            digest = _decode_hash(raw)
        except ValueError:
            raise _malformed("fullHashes[%d].fullHash is not valid base64" % index, response)
        if len(digest) != 32:
            raise _malformed("fullHashes[%d].fullHash is %d bytes, 32 are required" % (index, len(digest)), response)
        details = entry.get("fullHashDetails")
        if details is None:
            details = []
        if not isinstance(details, list):
            raise _malformed("fullHashes[%d].fullHashDetails is %s, not an array" % (index, _json_name(details)), response)
        parsed = []
        for number, detail in enumerate(details):
            if not isinstance(detail, dict):
                raise _malformed("fullHashDetails[%d] is %s, not an object" % (number, _json_name(detail)), response)
            kind = detail.get("threatType")
            attributes = detail.get("attributes")
            if attributes is None:
                attributes = []
            if not isinstance(kind, str):
                raise _malformed("fullHashDetails[%d].threatType is %s, not a string" % (number, _json_name(kind)), response)
            if not isinstance(attributes, list) or any(not isinstance(a, str) for a in attributes):
                raise _malformed("fullHashDetails[%d].attributes is not an array of strings" % number, response)
            parsed.append((kind, list(attributes)))
        out.append({"digest": digest, "details": parsed})
    seconds = safebrowsing.parse_cache_duration(duration) if duration is not None else None        # an unreadable string: the conservative default
    return out, seconds


def _protobuf_entries(response):
    """The binary form the live endpoint sends (Content-Type application/x-protobuf), decoded with services/safebrowsing_pb.py against Google's published schema; normalised exactly
    like the JSON form. An empty body is the valid empty message (no hashes, no cache duration). Any decoding problem is a failed lookup."""
    content = getattr(response, "content", None)
    if not isinstance(content, (bytes, bytearray)):
        raise _malformed("the protobuf body is missing", response)
    try:
        message = safebrowsing_pb.decode_search_hashes_response(bytes(content))
    except safebrowsing_pb.ProtobufError as problem:
        raise _malformed("the protobuf body is not a valid SearchHashesResponse - %s" % problem, response)
    out = []
    for entry in message["full_hashes"]:
        parsed = []
        for detail in entry["details"]:
            kind = safebrowsing_pb.THREAT_TYPES.get(detail["threat_type"], "UNKNOWN_THREAT_TYPE_%d" % detail["threat_type"])
            parsed.append((kind, [safebrowsing_pb.THREAT_ATTRIBUTES.get(a, "UNKNOWN_ATTRIBUTE_%d" % a) for a in detail["attributes"]]))
        out.append({"digest": entry["full_hash"], "details": parsed})
    return out, message["cache_seconds"]


def _parse_search_response(response, wanted):
    """Validate a v5 hashes.search answer and return (threat types of OUR hashes, count of uninterpretable details, cache seconds, facts).

    The decoder is chosen from the Content-Type: application/x-protobuf (what the endpoint really sends) -> protobuf; application/json (and +json) -> JSON; anything else, or no content
    type, is a failed lookup - never a no-match. Both forms are normalised and then judged by the same rules: only a returned full hash that EQUALS one we computed is a match (a 4-byte
    prefix collision is not); a threat type or attribute this client does not know is disregarded (as Google requires) but is not "no threat" either (UNKNOWN); CANARY and FRAME_ONLY
    are not for enforcement. A valid answer with no full hashes is a NO-MATCH: no known threat, not proof of safety. cacheDuration absent: the conservative 5 minutes."""
    media = _media_type(response)
    if media in PROTOBUF_TYPES:
        form = "protobuf"
        entries, seconds = _protobuf_entries(response)
    elif media == "application/json" or media.endswith("+json"):
        form = "json"
        entries, seconds = _json_entries(response)
    else:
        raise _malformed("the content type is %s: neither protobuf nor JSON" % (evidence.clean_text(media, 60) or "missing"), response)
    known_attributes = ("THREAT_ATTRIBUTE_UNSPECIFIED",) + evidence.GSB_IGNORED_ATTRIBUTES
    threat_types, uninterpretable = [], 0
    for entry in entries:
        if entry["digest"] not in wanted:
            continue                          # the 4-byte prefix matched but the full hash is another address's: no match
        for kind, attributes in entry["details"]:
            if kind not in evidence.GSB_THREAT_LEVELS or any(a not in known_attributes for a in attributes):
                uninterpretable += 1          # a value this client does not know: the whole detail is disregarded, as Google requires - but it is not "no threat" either
                continue
            if any(a in evidence.GSB_IGNORED_ATTRIBUTES for a in attributes):
                continue                      # CANARY / FRAME_ONLY: not for enforcement
            threat_types.append(kind)
    cache_seconds = float(seconds) if seconds is not None else safebrowsing.parse_cache_duration(None)
    return threat_types, uninterpretable, cache_seconds, {"entries": len(entries), "cache_duration_given": seconds is not None, "format": form}


class GoogleSafeBrowsingProvider(ReputationProvider):
    """Google Safe Browsing API v5, hashes.search (the v4 APIs are documented as deprecated).
    PRIVACY: names and addresses are turned into SHA-256 hashes (services/safebrowsing.py follows Google's canonicalization and expression rules) and only the first 4 bytes of each
    leave this computer; the full hashes Google returns are compared here. At most 30 prefixes per request (Google's own recommendation).
    SCOPE: lookup(domain) is HOST-level ("host/" for the host and its suffixes) and its answer may be cached for the domain. lookup_url(url) also checks path prefixes; its answer is
    only about THAT address ("scope": "url") and is never stored in a domain-level table (store() / store_evidence() refuse it). The live pipeline uses lookup() only.
    CACHE: the answer is valid for the response's cacheDuration, also when nothing matched; the result carries cache_seconds and every cache above it is shortened to that.
    Authentication: API key as the `key` query parameter (as documented); it is never logged and never appears in an error message."""
    name = "Google Safe Browsing"
    shared_budget = True
    list_based = True
    url = "https://safebrowsing.googleapis.com/v5/hashes:search"

    def __init__(self, api_key, session=None):
        self.api_key = api_key
        self.session = session or requests.Session()

    @staticmethod
    def budget_limits():
        return config.GSB_MAX_PER_MINUTE, config.GSB_MAX_PER_DAY

    def lookup(self, domain):
        return self._search(safebrowsing.host_level_expressions(domain), "host")

    def lookup_url(self, address, timeout=None):
        """Path-specific threats: the same protocol with host-suffix x path-prefix expressions. Returns a URL-scoped result (never cached by domain). `timeout` (seconds) can only
        shorten the request, never lengthen it."""
        return self._search(safebrowsing.url_expressions(address), "url", timeout)

    def _search(self, expressions, scope, timeout=None):
        if not self.api_key:
            raise ProviderError("API key missing", COOLDOWN_AUTH_MINUTES)
        if not expressions:
            return dict(_result(UNKNOWN, self.name, "No website name to look up."), evidence={}, list_based=True)
        expressions = expressions[:30]
        full = dict((safebrowsing.full_hash(e), e) for e in expressions)
        prefixes = sorted(set(safebrowsing.prefix_b64(e) for e in expressions))
        response = _get_json(lambda: self.session.get(self.url, params={"key": self.api_key, "hashPrefixes": prefixes},
                                                      headers={"accept": "application/json"},
                                                      timeout=min(FAST_PROVIDER_TIMEOUT_SECONDS, timeout) if timeout else FAST_PROVIDER_TIMEOUT_SECONDS,
                                                      allow_redirects=False))          # the key is in the query string: a redirect would carry it to another host
        if response.status_code != 200:
            raise _http_failure(response.status_code, getattr(response, "headers", None))
        threat_types, uninterpretable, cache_seconds, facts = _parse_search_response(response, full)
        if uninterpretable and not threat_types:
            return dict(_result(UNKNOWN, self.name, "Google Safe Browsing returned a match this client cannot interpret, so it is not treated as safe."), evidence={},
                        list_based=True, scope=scope, cache_seconds=cache_seconds)
        assessment = evidence.assess_gsb(threat_types)
        detections = [{"engine": self.name, "category": "malicious" if t in ("MALWARE", "SOCIAL_ENGINEERING") else "suspicious", "result": evidence.clean_text(t, 40)}
                      for t in sorted(set(threat_types))]
        result = _list_result(self.name, assessment, detections, {"prefixes_sent": len(prefixes), "expressions_checked": len(expressions), "scope": scope,
                                                                   "cache_duration_seconds": cache_seconds, "answer_entries": facts["entries"], "cache_duration_given": facts["cache_duration_given"], "answer_format": facts["format"],
                                                                   "answer_form": "no match" if not threat_types else "match"})
        result["scope"] = scope
        result["cache_seconds"] = cache_seconds
        return result


def _parse_time(text):
    """An ISO-8601 timestamp from a provider ('2026-10-01T12:30:45.123000', '...Z', '2026-10-01') -> naive UTC datetime, or None. Never raises."""
    if not isinstance(text, str):
        return None
    text = text.strip().rstrip("Z")
    for form, size in (("%Y-%m-%dT%H:%M:%S.%f", 26), ("%Y-%m-%dT%H:%M:%S", 19), ("%Y-%m-%d", 10)):
        try:
            return datetime.strptime(text[:size], form)
        except ValueError:
            continue
    return None


def _age_days(moment, now=None):
    if moment is None:
        return None
    return max(0, int(((now or datetime.utcnow()) - moment).total_seconds() // 86400))


OTX_PULSES_SHOWN = 5


def otx_intel(pulses):
    """Phase F3.20: the newest pulses the answer already lists - name, author, date, TLP, and the malware families the pulse EXPLICITLY names (a tag or a title is never promoted to a
    family) - plus the distinct authors, the TLP mix and the date range of all pulses read. Descriptions, references and indicator lists are not kept. A pulse is community context."""
    rows, authors, tlps, dates = [], [], {}, []
    for pulse in pulses:
        if not isinstance(pulse, dict):
            continue
        moment = _parse_time(pulse.get("modified") or pulse.get("created"))
        author_field = pulse.get("author")
        author = pulse.get("author_name") or (author_field.get("username") if isinstance(author_field, dict) else None)
        author = evidence.clean_text(author if isinstance(author, str) else "", 30)
        tlp = evidence.clean_text(str(pulse.get("TLP") or pulse.get("tlp") or ""), 10).lower()
        if author:
            authors.append(author)
        if tlp:
            tlps[tlp] = tlps.get(tlp, 0) + 1
        if moment:
            dates.append(moment)
        families = evidence.short_list([(f.get("display_name") or f.get("name")) if isinstance(f, dict) else f for f in (pulse.get("malware_families") or []) if f], limit=3, width=24)
        rows.append((moment, {"name": evidence.clean_text(str(pulse.get("name") or "(unnamed pulse)"), 60), "author": author, "date": evidence.stamp(moment, with_time=False) or "",
                              "tlp": tlp, "families": families}))
    rows.sort(key=lambda r: r[0] or datetime.min, reverse=True)
    intel = {"pulses": [r[1] for r in rows[:OTX_PULSES_SHOWN]], "authors": evidence.short_list(authors), "tlp": dict(sorted(tlps.items())[:5])}
    if dates:
        intel["newest"], intel["oldest"] = evidence.stamp(max(dates), with_time=False), evidence.stamp(min(dates), with_time=False)
    return intel


class OtxProvider(ReputationProvider):
    """AlienVault OTX, domain indicator: GET https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general with the key in the X-OTX-API-KEY header (the SDK's own
    convention; 403 = key rejected). PRIVACY: only the website name is sent. The answer is community CONTEXT (pulses that mention the domain): see evidence.assess_otx - alone it
    can reach MEDIUM at most, never HIGH.
    The response layout (pulse_info.count / pulses[] / validation[]) follows OTX's public SDKs; it has NOT been confirmed against the live service yet."""
    name = "AlienVault OTX"
    shared_budget = True
    list_based = True
    url = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"

    def __init__(self, api_key, session=None):
        self.api_key = api_key
        self.session = session or requests.Session()

    @staticmethod
    def budget_limits():
        return config.OTX_MAX_PER_MINUTE, config.OTX_MAX_PER_DAY

    def lookup(self, domain):
        if not self.api_key:
            raise ProviderError("API key missing", COOLDOWN_AUTH_MINUTES)
        try:
            response = _get_json(lambda: self.session.get(self.url.format(domain=domain), headers={"X-OTX-API-KEY": self.api_key, "accept": "application/json"},
                                                          timeout=FAST_PROVIDER_TIMEOUT_SECONDS, allow_redirects=False))
        except ProviderError as error:
            if str(error) == "timeout":                 # measured live: OTX does not answer for some heavily referenced domains (example.com: nothing within 40 s) - that is that
                raise ProviderError("timeout", OTX_TIMEOUT_COOLDOWN_MINUTES)          # domain, not an outage: back off briefly, not for five minutes
            raise
        if response.status_code != 200:
            raise _http_failure(response.status_code, getattr(response, "headers", None))
        try:
            body = response.json()
            info = body["pulse_info"]
            count = info["count"]
            if not isinstance(body, dict) or not isinstance(info, dict) or isinstance(count, bool) or not isinstance(count, int) or count < 0:
                raise ValueError("shape")
            pulses = info.get("pulses") or []
            if not isinstance(pulses, list):
                raise ValueError("pulses")
            validation = body.get("validation") or []
            false_positive = body.get("false_positive") or []
            if not isinstance(validation, list) or not isinstance(false_positive, list):
                raise ValueError("validation")
        except (ValueError, KeyError, TypeError, AttributeError):
            raise ProviderError("malformed response", COOLDOWN_ERROR_MINUTES)
        now = datetime.utcnow()
        read, recent, authors, attributed, families, adversaries, tags, ages, shown = 0, 0, set(), 0, [], [], [], [], []
        for pulse in pulses[:evidence.OTX_MAX_PULSES_READ]:
            if not isinstance(pulse, dict):
                continue
            read += 1
            age = _age_days(_parse_time(pulse.get("modified") or pulse.get("created")), now)
            if age is not None:
                ages.append(age)
            is_recent = age is not None and age <= evidence.OTX_RECENT_DAYS
            author_field = pulse.get("author")
            author = pulse.get("author_name") or (author_field.get("username") if isinstance(author_field, dict) else None)
            family_names = [(f.get("display_name") or f.get("name")) if isinstance(f, dict) else f for f in (pulse.get("malware_families") or []) if f]
            named = bool(pulse.get("adversary")) or bool(family_names) or bool(pulse.get("attack_ids"))
            if is_recent:
                recent += 1
                attributed += 1 if named else 0
                if isinstance(author, str) and author:
                    authors.add(author.lower())
            families += [evidence.clean_text(str(f), 30) for f in family_names if isinstance(f, str)]
            adversaries += [evidence.clean_text(str(pulse["adversary"]), 30)] if pulse.get("adversary") else []
            tags += [evidence.clean_text(str(x), 24) for x in (pulse.get("tags") or [])[:5] if isinstance(x, str)]
            if len(shown) < 5:
                shown.append({"engine": "OTX pulse", "category": "suspicious", "result": evidence.clean_text(str(pulse.get("name") or "(unnamed pulse)"), 40)})
        intel = otx_intel(pulses[:evidence.OTX_MAX_PULSES_READ])
        marks = [str(v).lower() for entry in validation if isinstance(entry, dict) for v in (entry.get("source"), entry.get("name"), entry.get("message"))]
        whitelisted = any("whitelist" in m or "false positive" in m or "false_positive" in m for m in marks) or bool(false_positive)
        assessment = evidence.assess_otx(count, recent, len(authors), attributed, whitelisted)
        facts = {"pulse_count": count, "pulses_read": read, "recent_pulses": recent, "recent_authors": len(authors), "attributed_recent": attributed, "whitelisted": bool(whitelisted),
                 "newest_pulse_age_days": min(ages) if ages else None, "newest_age_days": min(ages) if ages else None, "malware_families": sorted(set(families))[:5],
                 "adversaries": sorted(set(adversaries))[:3], "tags": sorted(set(tags))[:8], "source_group": "otx", "scope": "host",
                 evidence.INTEL_KEY: intel}
        return _list_result(self.name, assessment, shown if count else [], facts)


def urlscan_intel(items):
    """Phase F3.20: infrastructure metadata the plain search already returns for the scans it lists (at most ten): the scanned pages' server IP addresses, countries, ASNs and server
    software, and when the newest / oldest of those scans ran. It describes the SCANNED pages' servers - not this visit, and never a verdict. Page addresses, screenshots and result
    links are not kept."""
    import ipaddress
    ips, countries, asns, servers, times = [], [], [], [], []
    for item in items:
        page = item.get("page") if isinstance(item.get("page"), dict) else {}
        ip = page.get("ip")
        if isinstance(ip, str):
            try:
                ips.append(str(ipaddress.ip_address(ip)))
            except ValueError:
                pass
        country = page.get("country")
        if isinstance(country, str) and re.match(r"^[A-Za-z]{2}$", country):
            countries.append(country.upper())
        asn = page.get("asn")
        if isinstance(asn, str) and re.match(r"^AS[0-9]{1,10}$", asn):
            asns.append((asn + " " + evidence.clean_text(page.get("asnname") if isinstance(page.get("asnname"), str) else "", 30)).strip())
        servers.append(page.get("server"))
        task = item.get("task") if isinstance(item.get("task"), dict) else {}
        moment = _parse_time(task.get("time"))
        if moment:
            times.append(moment)
    intel = {"scans_read": len(items), "ips": evidence.short_list(ips, 5, 45), "countries": evidence.short_list(countries, 5, 2), "asns": evidence.short_list(asns, 5, 45),
             "servers": evidence.short_list(servers, 5, 40)}
    if times:
        intel["newest_scan"], intel["oldest_scan_read"] = evidence.stamp(max(times)), evidence.stamp(min(times))
    return intel


class PlanLimited(Exception):
    """urlscan.io answered 403 because the account's plan may not search that field (not a rejected key)."""


class UrlscanProvider(ReputationProvider):
    """urlscan.io Search API (https://urlscan.io/api/v1/search/, optional `api-key` header): looks up EXISTING public scans whose page is on this host. It never submits a scan, so no
    browsing address is ever published.
    WHAT THE LIVE SERVICE TURNED OUT TO ALLOW (checked 2026-10-09, example.com, no key): the plain search `page.domain:"host"` works and lists the scans newest first (total, task.time,
    task.visibility, page.*), but those items carry NO verdict; searching the verdict field (`verdicts.malicious:true`) answers 403 "Your current plan does not allow you to search
    field 'verdicts.malicious'", and the Result API answers 403 "You're not logged in!". So without a key (or on a plan that may not search verdicts) this source can only say that scans
    EXIST and how old the newest is - never whether they are malicious. That is reported as a coverage gap (UNKNOWN), not as a clean result.
    With a key whose plan allows it, a second search asks for scans with a malicious verdict (guarded: if the items themselves say 'not malicious' the filter evidently was not applied
    and the lookup fails). Whether a free key's plan allows that has NOT been tested yet. The 429 limits seen live: 30 searches a minute per IP address without a key."""
    name = "urlscan.io"
    shared_budget = True
    list_based = True
    url = "https://urlscan.io/api/v1/search/"

    def __init__(self, api_key, session=None):
        self.api_key = api_key                 # optional
        self.session = session or requests.Session()
        self.verdict_search_allowed = bool(api_key)          # becomes False once the plan is seen to refuse it: no point asking again

    @staticmethod
    def budget_limits():
        return config.URLSCAN_MAX_PER_MINUTE, config.URLSCAN_MAX_PER_DAY

    def _search(self, query, size):
        headers = {"accept": "application/json"}
        if self.api_key:
            headers["api-key"] = self.api_key
        response = _get_json(lambda: self.session.get(self.url, params={"q": query, "size": size}, headers=headers, timeout=FAST_PROVIDER_TIMEOUT_SECONDS, allow_redirects=False))
        if response.status_code == 403:
            try:
                message = str(response.json().get("message", ""))
            except (ValueError, AttributeError):
                message = ""
            if "plan does not allow" in message:
                raise PlanLimited()
        if response.status_code != 200:
            raise _http_failure(response.status_code, getattr(response, "headers", None))
        try:
            body = response.json()
            results = body["results"]
            if not isinstance(body, dict) or not isinstance(results, list):
                raise ValueError("shape")
            total = body.get("total", len(results))
            if isinstance(total, bool) or not isinstance(total, int) or total < 0:
                raise ValueError("total")
            return max(total, len(results)), [r for r in results if isinstance(r, dict)]
        except (ValueError, KeyError, TypeError, AttributeError):
            raise ProviderError("malformed response", COOLDOWN_ERROR_MINUTES)

    @staticmethod
    def _says_not_malicious(item):
        verdicts = item.get("verdicts")
        if not isinstance(verdicts, dict):
            return False
        for part in (verdicts.get("overall"), verdicts.get("urlscan"), verdicts):
            if isinstance(part, dict) and "malicious" in part:
                return part.get("malicious") is False
        return False

    @staticmethod
    def _newest_age(items, now):
        ages = [a for a in (_age_days(_parse_time((i.get("task") or {}).get("time")), now) for i in items) if a is not None]
        return min(ages) if ages else None

    def lookup(self, domain):
        quoted = 'page.domain:"%s"' % domain
        now = datetime.utcnow()
        total, items = self._search(quoted, 10)                         # request 1: do scans of this host exist, and how old is the newest?
        newest_scan = self._newest_age(items, now)
        facts = {"search_authenticated": bool(self.api_key), "scope": "host", "source_group": "urlscan", "scans_never_submitted": True, "total_scans": total,
                 "newest_scan_age_days": newest_scan, "newest_age_days": newest_scan, evidence.INTEL_KEY: urlscan_intel(items)}
        if total <= 0:
            return self._gap(evidence.assess_urlscan(0, 0, None), facts)
        malicious_total, malicious_items = None, []
        if self.verdict_search_allowed:
            try:
                malicious_total, malicious_items = self._search(quoted + " AND verdicts.malicious:true", 10)          # request 2: only with a plan that may search verdicts
            except PlanLimited:
                self.verdict_search_allowed = False
        if malicious_total is None:
            facts.update(verdicts_readable=False, malicious_scans=None)
            return self._gap(evidence.assess_urlscan_unreadable(total, newest_scan), facts)
        if any(self._says_not_malicious(i) for i in malicious_items):
            raise ProviderError("malformed response: the verdict filter was not applied", COOLDOWN_ERROR_MINUTES)
        facts.update(verdicts_readable=True, malicious_scans=malicious_total)
        if malicious_total > 0:
            newest = self._newest_age(malicious_items, now)
            categories = sorted(set(evidence.clean_text(str(c), 24) for i in malicious_items for c in (((i.get("verdicts") or {}).get("urlscan") or {}).get("categories") or [])
                                    if isinstance(c, str)))[:5]
            facts.update(newest_malicious_age_days=newest, newest_age_days=newest, categories=categories)
            detections = [{"engine": "urlscan.io", "category": "malicious", "result": "%d malicious scan(s)" % malicious_total}]
            return dict(_list_result(self.name, evidence.assess_urlscan(total, malicious_total, newest), detections, facts))
        return _list_result(self.name, evidence.assess_urlscan(total, 0, None), [], facts)

    def _gap(self, assessment, facts):
        result = _list_result(self.name, assessment, [], facts)
        result["coverage_gap"] = True
        result["details"]["coverage_gap"] = True
        return result


# ======================================================================================================================================================================================
# Phase F3.22: APIVoid, MetaDefender Cloud and AbuseIPDB - OBSERVATION-ONLY sources.
# Their answers are stored (reputation_evidence) and shown on the analysis page, but they never enter decide(), a risk score, the alert policy or the shadow policy
# (risk.OBSERVED_PROVIDERS). Each answer is bounded and sanitised like every other source: no raw response, no credential, no free text from the provider beyond short labels.
# The response layouts below follow each provider's PUBLISHED documentation and have NOT been confirmed against the live services yet (no key, no live request in this phase).
# ======================================================================================================================================================================================
REPEATED_SOURCE_GROUPS = (("safebrowsing", "google"), ("virustotal", "virustotal"))


def _derived_groups(names):
    """Which of OUR other sources a list of upstream engine names repeats (so a future scoring step can count them once): 'google', 'virustotal'."""
    found = set()
    for name in names or []:
        text = str(name).lower().replace(" ", "")
        for needle, group in REPEATED_SOURCE_GROUPS:
            if needle in text:
                found.add(group)
    return sorted(found)


def _count(value):
    """A non-negative integer from a provider field (a number or digits), else None. A bool is not a count."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _parse_json_object(response):
    try:
        body = response.json()
    except ValueError:
        raise _malformed("the body is not JSON", response)
    if not isinstance(body, dict):
        raise _malformed("the JSON is %s, not an object" % _json_name(body), response)
    return body


def _date_text(value):
    moment = _parse_time(value) if isinstance(value, str) else None
    return evidence.stamp(moment, with_time=False) if moment else None


class ApivoidProvider(ReputationProvider):
    """APIVoid (the service behind URLVoid) domain reputation, API v2: POST https://api.apivoid.com/v2/domain-reputation with {"host": name}, key in the X-API-Key header. PRIVACY: only the
    website NAME and the key are sent. The answer aggregates many blacklists; engines that merely repeat a source we ask ourselves (Google Safe Browsing, VirusTotal) are
    recorded in `derived_from` so they are never counted twice. OBSERVATION ONLY."""
    name = "APIVoid"
    shared_budget = True
    list_based = True
    observe_only = True
    url = "https://api.apivoid.com/v2/domain-reputation"

    def __init__(self, api_key, session=None):
        self.api_key = api_key
        self.session = session or requests.Session()

    @staticmethod
    def budget_limits():
        return config.APIVOID_MAX_PER_MINUTE, config.APIVOID_MAX_PER_DAY

    @staticmethod
    def _failure_in_answer(body):
        """A 200 answer that says it failed: key problems open the circuit breaker, quota problems back off for hours, anything else is an unusable answer. The provider's own wording is never kept."""
        text = str(body.get("error") or body.get("message") or "").lower()
        if "key" in text and any(w in text for w in ("invalid", "not valid", "unauthor", "denied", "disabled", "revoked", "expired", "missing")):
            return ProviderError("API key rejected (APIVoid)", COOLDOWN_AUTH_MINUTES)
        if any(w in text for w in ("credit", "quota", "limit", "balance")):
            return ProviderError("credits or quota exhausted (rate limited)", 360, kind=STATE_UNAVAILABLE)
        return ProviderError("malformed response: the answer reports an error", COOLDOWN_ERROR_MINUTES, kind=STATE_ERROR)

    def lookup(self, domain):
        if not self.api_key:
            raise ProviderError("API key missing", COOLDOWN_AUTH_MINUTES)
        response = _get_json(lambda: self.session.post(self.url, json={"host": domain}, headers={"X-API-Key": self.api_key, "accept": "application/json"},
                                                       timeout=FAST_PROVIDER_TIMEOUT_SECONDS, allow_redirects=False))
        if response.status_code != 200:
            raise _http_failure(response.status_code, getattr(response, "headers", None))
        body = _parse_json_object(response)
        if body.get("success") is False or (body.get("error") and "blacklists" not in body):
            raise self._failure_in_answer(body)
        data = body.get("data") if isinstance(body.get("data"), dict) else body
        blacklists = data.get("blacklists")
        if not isinstance(blacklists, dict):
            raise _malformed("the answer has no blacklists object", response)
        engines = blacklists.get("engines")
        entries = list(engines.values()) if isinstance(engines, dict) else (engines if isinstance(engines, list) else [])
        entries = [e for e in entries if isinstance(e, dict)]
        detected = [evidence.clean_text(str(e.get("engine") or ""), 30) for e in entries if e.get("detected") is True]
        detected = [n for n in detected if n]
        detections = _count(blacklists.get("detections"))
        detections = len(detected) if detections is None else detections
        engines_count = _count(blacklists.get("engines_count"))
        engines_count = len(entries) if engines_count is None else engines_count
        flags = []
        for section in ("category", "security_checks"):
            block = data.get(section)
            if isinstance(block, dict):
                flags += [evidence.clean_text(k.replace("is_", "").replace("_", " "), 30) for k, v in sorted(block.items()) if v is True and isinstance(k, str)]
        risk_block = data.get("risk_score")
        score = _count(risk_block.get("result")) if isinstance(risk_block, dict) else None
        intel = {}
        age = data.get("domain_age") if isinstance(data.get("domain_age"), dict) else {}
        created = _date_text(age.get("domain_creation_date"))
        if created:
            intel["created"] = created
        age_days = _count(age.get("domain_age_in_days"))
        if age_days is not None:
            intel["age_days"] = age_days
        server = data.get("server_details") if isinstance(data.get("server_details"), dict) else {}
        ip = resolve.normalized(server.get("ip")) if isinstance(server.get("ip"), str) else None
        if ip:
            intel["ip"] = ip
        country = server.get("country_code")
        if isinstance(country, str) and re.match(r"^[A-Za-z]{2}$", country):
            intel["country"] = country.upper()
        isp = evidence.clean_text(server.get("isp") if isinstance(server.get("isp"), str) else "", 40)
        if isp:
            intel["isp"] = isp
        assessment = evidence.assess_apivoid(detections, engines_count, detected)
        shown = [{"engine": n, "category": "suspicious", "result": "blacklisted"} for n in detected[:10]]
        result = _list_result(self.name, assessment, shown, {"blacklist_detections": detections, "engines_count": engines_count, "risk_score": score, "detected_engines": detected[:15],
                                                           "categories": short_flags(flags), "derived_from": _derived_groups(detected), "source_group": "apivoid", "scope": "host",
                                                           evidence.INTEL_KEY: intel})
        if assessment.get("coverage_gap"):
            result["coverage_gap"] = True
            result["details"]["coverage_gap"] = True
        return result


def short_flags(values):
    return evidence.short_list(values, limit=8, width=30)


BENIGN_ASSESSMENTS = ("trustworthy", "unknown", "whitelisted", "none", "benign", "clean", "safe", "")


class MetaDefenderProvider(ReputationProvider):
    """OPSWAT MetaDefender Cloud domain reputation: GET https://api.metadefender.com/v4/domain/{name}, key in the `apikey` header. PRIVACY: only the website NAME and the key are sent.
    The answer lists the sources that assessed the domain (`lookup_results.sources[]`, each with an assessment word); it need not contain any malicious verdict, and a domain with no
    assessments is a coverage gap, never clean. OBSERVATION ONLY."""
    name = "MetaDefender Cloud"
    shared_budget = True
    list_based = True
    observe_only = True
    url = "https://api.metadefender.com/v4/domain/{domain}"

    def __init__(self, api_key, session=None):
        self.api_key = api_key
        self.session = session or requests.Session()

    @staticmethod
    def budget_limits():
        return config.METADEFENDER_MAX_PER_MINUTE, config.METADEFENDER_MAX_PER_DAY

    def lookup(self, domain):
        if not self.api_key:
            raise ProviderError("API key missing", COOLDOWN_AUTH_MINUTES)
        response = _get_json(lambda: self.session.get(self.url.format(domain=domain), headers={"apikey": self.api_key, "accept": "application/json"},
                                                      timeout=FAST_PROVIDER_TIMEOUT_SECONDS, allow_redirects=False))
        headers = getattr(response, "headers", None)
        if response.status_code == 404:
            return self._answer(evidence.assess_metadefender(0, 0, []), [], {"detected_by": 0, "sources_count": 0, "flagged_sources": [], "categories": [], "derived_from": [], "coverage_gap": True,
                                                                          "quota": self._quota(headers)})
        if response.status_code == 429:
            raise ProviderError("HTTP 429 (rate limited)", self._reset_minutes(headers))          # MetaDefender documents error code 429000 and X-RateLimit-Reset-In
        if response.status_code != 200:
            raise _http_failure(response.status_code, headers)
        body = _parse_json_object(response)
        results = body.get("lookup_results")
        sources = [s for s in (results.get("sources") if isinstance(results, dict) and isinstance(results.get("sources"), list) else []) if isinstance(s, dict)]
        rows = []
        for s in sources:
            status = s.get("status") if isinstance(s.get("status"), int) and not isinstance(s.get("status"), bool) else None
            assessment = evidence.clean_text(str(s.get("assessment") or ""), 24).lower()
            rows.append({"provider": evidence.clean_text(str(s.get("provider") or ""), 30), "assessment": assessment, "status": status, "category": s.get("category"),
                         "detect_time": s.get("detect_time"), "update_time": s.get("update_time")})
        # documented status codes: 0 allowlisted, 1 blocklisted, 3 failed to scan, 5 unknown. Only a source that actually gave an opinion counts as having assessed the domain.
        failed = [r for r in rows if r["status"] == 3]
        opinions = [r for r in rows if r["status"] not in (3, 5) and r["assessment"] not in ("", "unknown")]
        flagged = [r for r in opinions if r["status"] == 1 or r["assessment"] not in BENIGN_ASSESSMENTS]
        detected_by = _count(results.get("detected_by")) if isinstance(results, dict) else None
        detected_by = len(flagged) if detected_by is None else detected_by
        updated = [m for m in (_parse_time(r["update_time"]) for r in rows if isinstance(r["update_time"], str)) if m]
        detected = [m for m in (_parse_time(r["detect_time"]) for r in flagged if isinstance(r["detect_time"], str)) if m]
        intel = {}
        if updated:
            intel["newest_update"] = evidence.stamp(max(updated), with_time=False)
        if detected:
            intel["newest_detection"] = evidence.stamp(max(detected), with_time=False)
        started = _date_text(results.get("start_time")) if isinstance(results, dict) else None
        if started:
            intel["scan_time"] = started
        geo = body.get("geo_info") if isinstance(body.get("geo_info"), dict) else {}
        country = geo.get("country") if isinstance(geo.get("country"), dict) else {}
        code = country.get("code")
        if isinstance(code, str) and re.match(r"^[A-Za-z]{2}$", code):
            intel["country"] = code.upper()
        site_categories = []
        for r in opinions:                         # vendor classification of the site ("Business and Economy;Computer and Internet Info"): context, never a verdict
            if isinstance(r["category"], str):
                site_categories += [part.strip() for part in r["category"].split(";")]
        shown = [{"engine": r["provider"] or "source", "category": "malicious" if r["assessment"] in ("malware", "malicious", "phishing", "botnet") else "suspicious", "result": r["assessment"]}
                 for r in flagged[:10]]
        facts = {"detected_by": detected_by, "sources_count": len(opinions), "sources_failed": len(failed), "sources_unknown": len(rows) - len(opinions) - len(failed),
                 "flagged_sources": [r["provider"] for r in flagged[:15] if r["provider"]], "categories": evidence.short_list([r["assessment"] for r in flagged], limit=8, width=24),
                 "site_categories": evidence.short_list(site_categories, limit=8, width=30), "derived_from": _derived_groups([r["provider"] for r in flagged]), "quota": self._quota(headers),
                 evidence.INTEL_KEY: intel}
        return self._answer(evidence.assess_metadefender(detected_by, len(opinions), [r["assessment"] for r in flagged]), shown, facts)

    @staticmethod
    def _quota(headers):
        """What MetaDefender says about this key's allowance (documented headers X-RateLimit-Limit / -Remaining / -Used / -Reset-In). Integers only; absent = not sent."""
        out = {}
        for key, name in (("limit", "X-RateLimit-Limit"), ("remaining", "X-RateLimit-Remaining"), ("used", "X-RateLimit-Used"), ("reset_in_seconds", "X-RateLimit-Reset-In")):
            try:
                value = int(str((headers or {}).get(name)).strip())
            except (TypeError, ValueError, AttributeError):
                continue
            if 0 <= value < 10 ** 9:
                out[key] = value
        return out

    @staticmethod
    def _reset_minutes(headers):
        """How long to leave the provider alone after a 429: until its window resets (X-RateLimit-Reset-In seconds), between 1 and 60 minutes; the default when it is not given."""
        seconds = MetaDefenderProvider._quota(headers).get("reset_in_seconds")
        if seconds is None:
            return retry_after_minutes(headers)          # a plain Retry-After, else the default
        return int(max(1, min(60, math.ceil(seconds / 60.0))))

    def _answer(self, assessment, shown, facts):
        facts = dict(facts, source_group="metadefender", scope="host")
        result = _list_result(self.name, assessment, shown, facts)
        if assessment.get("coverage_gap"):
            result["coverage_gap"] = True
            result["details"]["coverage_gap"] = True
        return result


IP_CACHE_SECONDS = 6 * 3600


class AbuseIpdbProvider(ReputationProvider):
    """AbuseIPDB API v2 Check: GET https://api.abuseipdb.com/api/v2/check?ipAddress=...&maxAgeInDays=90, key in the `Key` header. It is about an IP ADDRESS, never about a website: the
    website name is resolved locally (services/resolve.py) and only a validated PUBLIC address is ever sent. A shared CDN or hosting address carries reports about other tenants, so the
    result is at most a WEAK, IP-scoped observation (evidence.assess_abuseipdb) and never a verdict about the site. One address is asked about at most once every six hours however
    many websites share it. OBSERVATION ONLY."""
    name = "AbuseIPDB"
    shared_budget = True
    list_based = True
    observe_only = True
    url = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key, session=None, resolver=None):
        self.api_key = api_key
        self.session = session or requests.Session()
        self.resolver = resolver or resolve.public_addresses
        self._ip_cache = {}
        self._ip_lock = threading.Lock()

    @staticmethod
    def budget_limits():
        return config.ABUSEIPDB_MAX_PER_MINUTE, config.ABUSEIPDB_MAX_PER_DAY

    def _cached(self, ip):
        with self._ip_lock:
            held = self._ip_cache.get(ip)
        if held and time.monotonic() - held[0] < IP_CACHE_SECONDS:
            return held[1]
        return None

    def lookup(self, domain):
        if not self.api_key:
            raise ProviderError("API key missing", COOLDOWN_AUTH_MINUTES)
        addresses = [a for a in (resolve.normalized(x) for x in (self.resolver(domain) or [])) if a]          # validated again here: nothing but a public address is ever sent
        if not addresses:
            assessment = evidence.assess_abuseipdb(None, None, False, None)
            result = _list_result(self.name, assessment, [], {"scope": "ip", "ip": None, "addresses_resolved": 0, "source_group": "abuseipdb"})
            result["coverage_gap"] = True
            result["details"]["coverage_gap"] = True
            return result
        ip = addresses[0]
        data = self._cached(ip)
        reused = data is not None
        quota = {}
        if data is None:
            response = _get_json(lambda: self.session.get(self.url, params={"ipAddress": ip, "maxAgeInDays": 90}, headers={"Key": self.api_key, "Accept": "application/json"},
                                                          timeout=FAST_PROVIDER_TIMEOUT_SECONDS, allow_redirects=False))
            if response.status_code != 200:
                raise _http_failure(response.status_code, getattr(response, "headers", None))
            quota = {k: v for k, v in MetaDefenderProvider._quota(getattr(response, "headers", None)).items() if k in ("limit", "remaining")}          # documented X-RateLimit-Limit / -Remaining
            body = _parse_json_object(response)
            data = body.get("data")
            if not isinstance(data, dict):
                raise _malformed("the answer has no data object", response)
            score = _count(data.get("abuseConfidenceScore"))
            if score is None or score > 100:
                raise _malformed("abuseConfidenceScore is missing or not 0-100", response)
            with self._ip_lock:
                self._ip_cache[ip] = (time.monotonic(), data)
        score = _count(data.get("abuseConfidenceScore"))
        reports = _count(data.get("totalReports"))
        usage = evidence.clean_text(data.get("usageType") if isinstance(data.get("usageType"), str) else "", 40)
        whitelisted = data.get("isWhitelisted") is True
        assessment = evidence.assess_abuseipdb(score, reports, whitelisted, usage)
        country = data.get("countryCode")
        intel = {"ip": ip}
        isp = evidence.clean_text(data.get("isp") if isinstance(data.get("isp"), str) else "", 40)
        for key, value in (("isp", isp), ("usage_type", usage), ("country", country.upper() if isinstance(country, str) and re.match(r"^[A-Za-z]{2}$", country) else "")):
            if value:
                intel[key] = value
        last = _date_text(data.get("lastReportedAt"))
        facts = {"scope": "ip", "ip": ip, "ip_version": data.get("ipVersion") if data.get("ipVersion") in (4, 6) else None, "abuse_score": score, "total_reports": reports,
                 "distinct_reporters": _count(data.get("numDistinctUsers")), "last_reported": last, "whitelisted": whitelisted, "is_tor": data.get("isTor") is True,
                 "shared_infrastructure": any(t in usage.lower() for t in evidence.SHARED_USAGE_TYPES), "addresses_resolved": len(addresses), "ip_reused": reused,
                 "quota": quota, "source_group": "abuseipdb", evidence.INTEL_KEY: intel}
        return _list_result(self.name, assessment, [], facts)


def _list_result(name, assessment, detections, extra):
    """The normalised result of a list-based source. `status` is the source's native verdict. Unlike VirusTotal (whose legacy rule is kept), these NEW sources always carry their own
    decision (`level` and `alert_severity`): a weak or historical finding is a SUSPICIOUS verdict WITHOUT an alert, whatever SEVERITY_POLICY says."""
    extra = dict(extra)
    extra["list_based"] = True
    extra["looked_up_at"] = _now().strftime(TIME_FORMAT)
    result = _result(assessment["status"], name, assessment["reason"])
    result["evidence"] = {}
    result["list_based"] = True
    result["level"] = assessment["level"]
    result["alert_severity"] = assessment["alert_severity"]
    extra["applied_level"] = assessment["level"]
    extra["applied_alert_severity"] = assessment["alert_severity"]
    result["details"] = evidence.build_details(evidence.INDICATOR_DOMAIN, assessment, detections, extra)
    return result


def interpret_stats(malicious, suspicious, engines, source="VirusTotal"):
    """The documented, deterministic mapping (see module docstring)."""
    if engines <= 0:
        return _result(UNKNOWN, source, "No security vendor has analysed this website yet.")
    if malicious >= MALICIOUS_MIN_VENDORS:
        return _result(MALICIOUS, source, "%d security vendors classified this website as malicious." % malicious)
    if malicious >= 1 or suspicious >= SUSPICIOUS_MIN_SUSPICIOUS_VENDORS:
        return _result(SUSPICIOUS, source, "%d vendor(s) flagged this website as malicious and %d as suspicious."
                       % (malicious, suspicious))
    return _result(SAFE, source, "No security vendor flagged this website (%d vendors checked)." % engines)


def configured_providers():
    """Every provider that is set up, in the order they are asked: VirusTotal when its key is set, then the other sources ONLY when their feature flag is on AND
    their credential is present (all are off by default). A flag without a credential adds nothing and is reported by provider_states() as NOT_CONFIGURED.
    A new source is added here (and nowhere else in the pipeline)."""
    providers = []
    for build in (build_provider, build_gsb_provider, build_otx_provider, build_urlscan_provider, build_apivoid_provider, build_metadefender_provider,
                  build_abuseipdb_provider):
        provider = build()
        if provider is not None:
            providers.append(provider)
    return providers


_extra_providers = {}


def _extra(name, key, factory):
    held = _extra_providers.get(name)
    if held is None or held[0] != key:
        held = _extra_providers[name] = (key, factory(key))
    return held[1]


def build_gsb_provider():
    if not (config.GSB_ENABLED and config.GSB_API_KEY):
        return None
    return _extra("gsb", config.GSB_API_KEY, GoogleSafeBrowsingProvider)


def build_apivoid_provider():
    if not (config.APIVOID_ENABLED and config.APIVOID_API_KEY):
        return None
    return _extra("apivoid", config.APIVOID_API_KEY, ApivoidProvider)


def build_metadefender_provider():
    if not (config.METADEFENDER_ENABLED and config.METADEFENDER_API_KEY):
        return None
    return _extra("metadefender", config.METADEFENDER_API_KEY, MetaDefenderProvider)


def build_abuseipdb_provider():
    if not (config.ABUSEIPDB_ENABLED and config.ABUSEIPDB_API_KEY):
        return None
    return _extra("abuseipdb", config.ABUSEIPDB_API_KEY, AbuseIpdbProvider)


def build_otx_provider():
    if not (config.OTX_ENABLED and config.OTX_API_KEY):
        return None
    return _extra("otx", config.OTX_API_KEY, OtxProvider)


def build_urlscan_provider():
    if not config.URLSCAN_ENABLED:                  # the key is optional: searches work without one
        return None
    return _extra("urlscan", config.URLSCAN_API_KEY, UrlscanProvider)


SOURCE_CAPABILITIES = {
    "VirusTotal": "The site's reputation from about seventy security engines",
    "Google Safe Browsing": "Google's lists of unsafe sites, and of this exact page (only hash prefixes leave this computer)",
    "AlienVault OTX": "Community threat reports (pulses) that mention the site",
    "urlscan.io": "Existing public scans of the site (the application never submits a scan)",
    "APIVoid": "Blacklist and reputation checks of the site by many lists (the service behind URLVoid); observation only",
    "MetaDefender Cloud": "OPSWAT's multi-source domain reputation; observation only",
    "AbuseIPDB": "Abuse reports about the IP address the site resolves to (the address, not the site); observation only",
}


# the environment variables behind each source: (key variable or None, flag variable or None, key is required?)
SOURCE_SETTINGS = {
    "VirusTotal": ("VT_API_KEY", None, True),
    "Google Safe Browsing": ("GSB_API_KEY", "GSB_ENABLED", True),
    "AlienVault OTX": ("OTX_API_KEY", "OTX_ENABLED", True),
    "urlscan.io": ("URLSCAN_API_KEY", "URLSCAN_ENABLED", False),
    "APIVoid": ("APIVOID_API_KEY", "APIVOID_ENABLED", True),
    "MetaDefender Cloud": ("METADEFENDER_API_KEY", "METADEFENDER_ENABLED", True),
    "AbuseIPDB": ("ABUSEIPDB_API_KEY", "ABUSEIPDB_ENABLED", True),
}
STATUS_RECENT_FAILURE_MINUTES = 60


def _evidence_times(conn, name):
    """(latest successful lookup, latest failed lookup with its error text) of a source, from the stored evidence: it survives a restart. A failed row is UNAVAILABLE / ERROR;
    NOT_CHECKED (budget) is neither. The error text is one of the fixed, key-free messages."""
    ok = conn.execute("SELECT MAX(checked_at) FROM reputation_evidence WHERE provider = ? AND state = ?", (name, STATE_CHECKED)).fetchone()[0]
    bad = conn.execute("SELECT checked_at, error FROM reputation_evidence WHERE provider = ? AND state IN (?, ?) ORDER BY checked_at DESC LIMIT 1", (name, STATE_UNAVAILABLE, STATE_ERROR)).fetchone()
    return ok, (bad[0], bad[1]) if bad else (None, None)


def _urlscan_verdicts_unreadable(conn):
    """True when the newest successful urlscan.io lookup says its verdicts could not be read (no key, or a plan that refuses verdict search)."""
    row = conn.execute("SELECT details_json FROM reputation_evidence WHERE provider = ? AND state = ? ORDER BY checked_at DESC LIMIT 1", ("urlscan.io", STATE_CHECKED)).fetchone()
    details = evidence.read_details(row[0]) if row and row[0] else None
    return bool(details and details.get("verdicts_readable") is False)


def source_overview(conn=None, now=None):
    """The five engines for the dashboard, never with a credential. For each: the variables that control it, `configured` (everything it needs is present), `enabled` (switched on),
    and ONE status word:
        NOT CONFIGURED  a required key is missing (whatever the switch says)
        CONFIGURED      everything is present but the source is switched off
        ENABLED         switched on and used for new websites; no lookup has succeeded yet
        OPERATIONAL     switched on and its latest lookup succeeded
        RATE LIMITED    the provider asked us to slow down; it is left alone for a while
        ERROR           the key was rejected, the answer was unusable, or the provider is unreachable
    With a database connection the latest success / failure come from the stored evidence (so they survive a restart); without one only this process's memory is used."""
    now = now or _now()
    states = dict((r["name"], r) for r in provider_states(now))
    present_key = {"VirusTotal": bool(config.VT_API_KEY), "Google Safe Browsing": bool(config.GSB_API_KEY),
                   "AlienVault OTX": bool(config.OTX_API_KEY), "urlscan.io": bool(config.URLSCAN_API_KEY), "APIVoid": bool(config.APIVOID_API_KEY),
                   "MetaDefender Cloud": bool(config.METADEFENDER_API_KEY), "AbuseIPDB": bool(config.ABUSEIPDB_API_KEY)}
    rows = []
    for name in ALL_PROVIDERS:
        key_var, flag_var, required = SOURCE_SETTINGS[name]
        present = present_key[name]
        state = states[name]
        enabled = state["enabled"]
        configured = present or not required
        memory = _entry(name)
        last_ok = memory["last_success_at"].strftime(TIME_FORMAT) if memory.get("last_success_at") else None
        last_error, last_error_at = state["last_error"], None
        if conn is not None:
            db_ok, (db_bad_at, db_bad) = _evidence_times(conn, name)
            if db_ok and (not last_ok or db_ok > last_ok):
                last_ok = db_ok
            if db_bad and not last_error:
                last_error, last_error_at = db_bad, db_bad_at
        if required and not present:
            status, detail = "NOT CONFIGURED", "Put the key in .env as %s=... and restart the server." % key_var
        elif not enabled:
            status, detail = "CONFIGURED", "Everything needed is present, but the source is switched off. Set %s=true in .env and restart the server." % flag_var
        elif state.get("breaker"):
            status, detail = "ERROR", "The provider rejected the key (%s). Nothing is sent with it again until the key is changed in .env and the server restarted; answers are shown as not checked." % last_error
        elif state["state"] == "RATE_LIMITED":
            status, detail = "RATE LIMITED", "The provider asked us to slow down (%s). It is left alone until %s." % (last_error, state["retry_at"] or "later")
        elif state["state"] in ("UNAVAILABLE", "ERROR"):
            status, detail = "ERROR", "%s. It is retried at %s; meanwhile its answers are shown as not checked." % (last_error, state["retry_at"] or "a later time")
        elif last_error_at and (not last_ok or last_error_at > last_ok) and (now - datetime.strptime(last_error_at, TIME_FORMAT)) < timedelta(minutes=STATUS_RECENT_FAILURE_MINUTES):
            limited = "rate limit" in (last_error or "").lower() or "429" in (last_error or "")
            status, detail = ("RATE LIMITED" if limited else "ERROR"), "Its latest lookup failed: %s." % last_error
        elif last_ok:
            status, detail = "OPERATIONAL", "Its latest lookup succeeded."
            if name == "urlscan.io" and conn is not None and _urlscan_verdicts_unreadable(conn):
                detail = ("Its latest lookup succeeded, but only scan counts and dates can be read at this access level (the plan refuses verdict search): urlscan.io reports a "
                          "coverage gap for every site, never 'clean' and never 'malicious'.")
        else:
            status, detail = "ENABLED", "Switched on and used for every new website; no lookup has succeeded yet."
        controls = key_var + ((" + " + flag_var) if flag_var else " (no switch: used whenever the key is set)") + ("" if required else " (key optional)")
        rows.append({"name": name, "controls": controls, "configured": configured, "enabled": enabled, "status": status, "detail": detail, "last_success_at": last_ok,
                     "key": "set" if present else ("not set (optional)" if not required else "MISSING"), "key_ok": configured, "state": state["state"], "last_error": last_error,
                     "can_tell": SOURCE_CAPABILITIES[name], "role": "observation only" if name in OBSERVED_PROVIDERS else "scoring"})
    return rows


def source_counts(rows):
    """What the dashboard may honestly say about the sources: how many are listed, and how many are in each state. Only a source whose latest lookup succeeded is `operational` - a source that
    is configured, enabled, rate limited or failing is never counted as working, so 'seven working sources' appears only when seven actually answered."""
    status = [r["status"] for r in rows]
    return {"total": len(rows), "operational": status.count("OPERATIONAL"), "enabled_not_yet_answered": status.count("ENABLED"), "unavailable": status.count("ERROR") + status.count("RATE LIMITED"),
            "configured_off": status.count("CONFIGURED"), "not_configured": status.count("NOT CONFIGURED")}


def provider_states(now=None):
    """One row per reputation source for a status page: {name, enabled, configured, state, last_success_at, last_error, retry_at}. state: DISABLED (switched off), NOT_CONFIGURED
    (switched on without a credential), ACTIVE (configured, no recent failure), RATE_LIMITED, UNAVAILABLE (network, timeout, server error, cooling down), ERROR (key rejected,
    malformed answer). Never contains a credential."""
    now = now or _now()
    rows = []
    for name, enabled, configured in (("VirusTotal", True, bool(config.VT_API_KEY)),
                                      ("Google Safe Browsing", config.GSB_ENABLED, bool(config.GSB_API_KEY)),
                                      ("AlienVault OTX", config.OTX_ENABLED, bool(config.OTX_API_KEY)),
                                      ("urlscan.io", config.URLSCAN_ENABLED, True),          # urlscan.io needs no key; its optional key is reported by key_state()
                                      ("APIVoid", config.APIVOID_ENABLED, bool(config.APIVOID_API_KEY)),
                                      ("MetaDefender Cloud", config.METADEFENDER_ENABLED, bool(config.METADEFENDER_API_KEY)),
                                      ("AbuseIPDB", config.ABUSEIPDB_ENABLED, bool(config.ABUSEIPDB_API_KEY))):
        entry = _entry(name)
        if not enabled:
            state = "DISABLED"
        elif not configured:
            state = "NOT_CONFIGURED"
        elif _breaker_open(name):
            state = "ERROR"
        elif _in_cooldown(name, now):
            state = entry.get("last_kind") or "UNAVAILABLE"
        else:
            state = "ACTIVE"
        rows.append({"name": name, "enabled": bool(enabled), "configured": configured, "state": state, "breaker": _breaker_open(name),
                     "last_success_at": entry["last_success_at"].strftime(TIME_FORMAT) if entry.get("last_success_at") else None,
                     "last_error": entry["last_error"] if state not in ("DISABLED", "ACTIVE") else None,
                     "retry_at": entry["unavailable_until"].strftime(TIME_FORMAT) if state in ("RATE_LIMITED", "UNAVAILABLE", "ERROR") and entry["unavailable_until"] and not _breaker_open(name) else None})
    return rows


def build_provider():
    """The configured provider (one shared instance so the HTTP session is reused), or None."""
    key = config.VT_API_KEY
    if not key:
        return None
    if _provider_cache["key"] != key:
        _provider_cache["key"] = key
        _provider_cache["provider"] = VirusTotalProvider(key)
    return _provider_cache["provider"]


# --------------------------------------------------------------------
# Provider state (cooldown + dashboard status)
# --------------------------------------------------------------------
def _entry(name):
    return _state.setdefault(name, {"unavailable_until": None, "last_error": None, "last_success_at": None})


def _in_cooldown(name, now):
    until = _entry(name)["unavailable_until"]
    return until is not None and now < until


BACKOFF_CAP_MINUTES = 60


def _fingerprint(credential):
    """A short, one-way fingerprint of a credential - only ever compared with another fingerprint, never shown or stored."""
    return hashlib.sha256((credential or "").encode("utf-8")).hexdigest()[:12]


def _provider_fingerprint(provider):
    return _fingerprint(getattr(provider, "api_key", None) or getattr(provider, "auth_key", None) or "")


def _config_fingerprint(name):
    """The fingerprint of the credential CONFIGURED for a source now (so a changed key closes the breaker)."""
    settings = SOURCE_SETTINGS.get(name)
    return _fingerprint(getattr(config, settings[0], "") if settings else "")


def _breaker_open(name):
    """Circuit breaker: the provider refused the configured credential, so NOTHING is sent with it again until the key changes or the server restarts."""
    fp = _entry(name).get("breaker_fp")
    return fp is not None and fp == _config_fingerprint(name)


def _record_failure(name, message, cooldown_minutes, now, kind=None, auth=False, fingerprint=None):
    """Remember a failure. Rate limits wait as long as the provider asked; other failures back off EXPONENTIALLY (cooldown x 2 for every consecutive failure, at most
    BACKOFF_CAP_MINUTES); a rejected credential opens the circuit breaker (`breaker_fp`): no further request is made with that key."""
    entry = _entry(name)
    entry["last_error"] = message
    text = (message or "").lower()
    entry["last_kind"] = "RATE_LIMITED" if ("429" in text or "rate limit" in text) else ("ERROR" if kind == STATE_ERROR else "UNAVAILABLE")
    entry["failures"] = entry.get("failures", 0) + 1
    minutes = cooldown_minutes
    if auth:
        entry["breaker_fp"] = fingerprint if fingerprint is not None else _config_fingerprint(name)
        entry["last_kind"] = "ERROR"
    elif entry["last_kind"] != "RATE_LIMITED":
        minutes = min(BACKOFF_CAP_MINUTES, cooldown_minutes * (2 ** (entry["failures"] - 1)))
    entry["unavailable_until"] = now + timedelta(minutes=minutes)


def _record_success(name, now):
    entry = _entry(name)
    entry["unavailable_until"] = None
    entry["last_error"] = None
    entry["last_success_at"] = now
    entry["failures"] = 0
    entry["breaker_fp"] = None


class LookupBudget(object):
    """Caps how many provider lookups ONE telemetry source may start.

    The network agent sees every lookup a computer makes, including dozens of background
    Windows and application domains. Without a cap it would use up the provider's small free
    quota (VirusTotal: 4 per minute, 500 per day) and leave nothing for checking the websites
    people actually visit. When the budget is spent the domain is simply answered as UNKNOWN
    (shown as "Not checked") and NOT cached, so it is checked later when budget is available.
    Process-local, like the provider back-off state."""

    def __init__(self, per_minute, per_day):
        self.per_minute = per_minute
        self.per_day = per_day
        self.stamps = []
        self._lock = threading.Lock()          # the web server is multi-threaded: the check and the booking must be one step

    def allow(self, now=None):
        now = now or _now()
        with self._lock:
            return self._allow(now)

    def _allow(self, now):
        self.stamps = [t for t in self.stamps if t > now - timedelta(days=1)]
        recent = sum(1 for t in self.stamps if t > now - timedelta(seconds=60))
        return recent < self.per_minute and len(self.stamps) < self.per_day

    def record(self, now=None):
        with self._lock:
            self.stamps.append(now or _now())

    def try_acquire(self, now=None):
        """Atomically: is there budget left? If so, book one lookup and say True."""
        now = now or _now()
        with self._lock:
            if not self._allow(now):
                return False
            self.stamps.append(now)
            return True

    def refund(self, now=None):
        """Give back the most recent booking (a lookup that was booked here but then not sent)."""
        with self._lock:
            if self.stamps:
                self.stamps.pop()

    def reset(self):
        with self._lock:
            self.stamps = []


class SharedBudget(object):
    """The ONE request budget of a provider, shared by every telemetry source (the browser extension, the agent's browser history, the agent's DNS lookups).
    Thread-safe. Fair: no single source may take the last slot of the minute or more than three quarters of the day, so a burst from one source can never starve another
    (with one request a minute neither can be locked out; with the defaults of 3 a minute each source can use at most 2). Over budget a lookup is simply not sent."""

    def __init__(self, per_minute, per_day):
        self.per_minute = per_minute
        self.per_day = per_day
        self.stamps = []                       # (moment, source)
        self._lock = threading.Lock()

    def acquire(self, source, now=None, reserve=None):
        """Book one request. `reserve` (a share between 0 and 1) marks a LOWER-PRIORITY request: it is refused once the minute's or the day's use, by every source, has reached
        that share of the limit, so the rest stays available for the requests that matter more. Without it nothing changes."""
        now = now or _now()
        source = source or "other"
        with self._lock:
            self.stamps = [(t, s) for (t, s) in self.stamps if t > now - timedelta(days=1)]
            minute = [(t, s) for (t, s) in self.stamps if t > now - timedelta(seconds=60)]
            if len(minute) >= self.per_minute or len(self.stamps) >= self.per_day:
                return False
            if reserve is not None and (len(minute) >= max(1, int(self.per_minute * reserve)) or len(self.stamps) >= max(1, int(self.per_day * reserve))):
                return False
            if self.per_minute > 1 and sum(1 for (_, s) in minute if s == source) >= self.per_minute - 1:
                return False
            if self.per_day > 1 and sum(1 for (_, s) in self.stamps if s == source) >= self.per_day - self.per_day // 4:
                return False
            self.stamps.append((now, source))
            return True

    def reset(self):
        with self._lock:
            self.stamps = []


_shared_budgets = {}
_shared_budgets_lock = threading.Lock()


def shared_budget_for(provider):
    """The shared budget of a provider that declares one (VirusTotal), created from the configured limits; None for a provider without a quota."""
    if not getattr(provider, "shared_budget", False):
        return None
    with _shared_budgets_lock:
        limits = provider.budget_limits() if hasattr(provider, "budget_limits") else (config.VT_MAX_PER_MINUTE, config.VT_MAX_PER_DAY)
        budget = _shared_budgets.get(provider.name)
        if budget is None or (budget.per_minute, budget.per_day) != limits:
            budget = _shared_budgets[provider.name] = SharedBudget(*limits)
        return budget


# One lock per domain (a fixed number of them, chosen by the domain's hash): two requests for the same new domain at the same moment - the extension and the agent's history
# report one visit together - make ONE provider call, the second waits and then finds the answer in the cache.
_DOMAIN_LOCKS = [threading.Lock() for _ in range(256)]


def _domain_lock(domain):
    return _DOMAIN_LOCKS[hash(domain) % len(_DOMAIN_LOCKS)]


# Network-agent lookups get at most this many provider calls (browser visits are not limited here).
# 2 per minute leaves half of VirusTotal's per-minute allowance and 200 per day leaves 300 of its 500.
AGENT_BUDGET = LookupBudget(per_minute=2, per_day=200)
NOT_CHECKED_YET_REASON = "Not checked yet: the lookup limit for network observations was reached."
SHARED_LIMIT_REASON = "Not checked yet: the reputation service's request limit was reached; it will be checked again later."


def reset_state():
    _state.clear()
    with _shared_budgets_lock:
        _shared_budgets.clear()
    _extra_providers.clear()
    _missing_probe.clear()
    _provider_cache["key"] = None
    _provider_cache["provider"] = None
    AGENT_BUDGET.reset()


UNAVAILABLE_REASON_PREFIX = "Reputation service temporarily unavailable"

# Business-readable text for the dashboard. `detail` (technical, may contain an
# HTTP code) is only shown inside "Technical details".
SUMMARY_ACTIVE = "Website reputation checks are running."
SUMMARY_NOT_CONFIGURED = "Not configured: no reputation service is set up, so websites are shown as Not checked."
SUMMARY_UNAVAILABLE = ("Temporarily unavailable: the reputation service cannot check new websites right now. "
                       "They are shown as Not checked until it recovers.")


def _recent_failure(conn, now):
    """Reason of the most recent VirusTotal lookup if it failed and that result is
    still cached (UNKNOWN entries live 30 min), else None. Unlike the in-process
    cooldown this survives a server restart, so the status stays truthful."""
    row = conn.execute(
        "SELECT reason, expires_at FROM domain_reputation WHERE source = ? ORDER BY checked_at DESC, id DESC LIMIT 1",
        (VirusTotalProvider.name,),
    ).fetchone()
    if row and row["expires_at"] > now.strftime(TIME_FORMAT) and (row["reason"] or "").startswith(UNAVAILABLE_REASON_PREFIX):
        return row["reason"]
    return None


def provider_status(conn=None):
    """Small dashboard indicator - no provider-health subsystem.
    ACTIVE: configured and not failing. TEMPORARILY_UNAVAILABLE (shown to users as
    "Limited"): configured but in a back-off after an error, or - when `conn` is
    given - the last cached lookup failed. NOT_CONFIGURED: no VT_API_KEY."""
    if not config.VT_API_KEY:
        return {"status": STATUS_NOT_CONFIGURED, "provider": None, "summary": SUMMARY_NOT_CONFIGURED,
                "detail": "No VT_API_KEY configured - websites are shown as Unknown."}
    now = _now()
    name = VirusTotalProvider.name
    if _in_cooldown(name, now):
        entry = _entry(name)
        remaining = int((entry["unavailable_until"] - now).total_seconds() // 60) + 1
        return {"status": STATUS_UNAVAILABLE, "provider": name, "summary": SUMMARY_UNAVAILABLE,
                "detail": "%s - next attempt in about %d min. New websites are shown as Unknown meanwhile."
                          % (entry["last_error"], remaining)}
    if conn is not None:
        reason = _recent_failure(conn, now)
        if reason:
            return {"status": STATUS_UNAVAILABLE, "provider": name, "summary": SUMMARY_UNAVAILABLE,
                    "detail": "The last reputation check failed: " + reason}
    return {"status": STATUS_ACTIVE, "provider": name, "summary": SUMMARY_ACTIVE,
            "detail": "Website reputation checks are running."}


# --------------------------------------------------------------------
# Cache
# --------------------------------------------------------------------
def get_cached(conn, domain):
    row = conn.execute(
        "SELECT status, source, reason, expires_at, level, alert_severity FROM domain_reputation WHERE domain = ?", (domain,)
    ).fetchone()
    if row is None or row["expires_at"] < _now().strftime(TIME_FORMAT):
        return None
    result = _result(row["status"], row["source"], row["reason"])
    if row["level"] is not None:              # decided by the evidence policy: the stored decision is kept with the verdict
        result.update(level=row["level"], alert_severity=row["alert_severity"])
    return result


def alert_severity_for(verdict):
    """HIGH / MEDIUM / None: does this verdict raise an alert? A verdict decided by the evidence policy carries its own decision (a weak finding is a
    SUSPICIOUS verdict WITHOUT an alert); every other verdict - all of today's, while SEVERITY_POLICY=legacy - maps by status exactly as before."""
    if verdict.get("level") is not None:
        return verdict.get("alert_severity")
    return ALERT_SEVERITY.get(verdict["status"])


def ttl_for(status):
    if status == UNKNOWN:
        return timedelta(minutes=UNKNOWN_CACHE_MINUTES)
    if status in (SUSPICIOUS, MALICIOUS):
        return timedelta(hours=THREAT_CACHE_HOURS)
    return timedelta(hours=config.REPUTATION_CACHE_HOURS)


def _refuse_url_scope(result):
    if result.get("scope") == "url":
        raise ValueError("a URL-scoped result is about one address only and is never stored in a domain-level table")


def _validity(result, default):
    """The default validity, shortened to the provider's own cache_seconds (Google's cacheDuration) when it gave one."""
    seconds = result.get("cache_seconds")
    if isinstance(seconds, (int, float)) and not isinstance(seconds, bool) and seconds >= 0:
        return min(default, timedelta(seconds=seconds))
    return default


def store(conn, domain, result):
    _refuse_url_scope(result)
    now = _now()
    expires = now + _validity(result, ttl_for(result["status"]))
    conn.execute(
        "INSERT INTO domain_reputation (domain, status, source, reason, checked_at, expires_at, level, alert_severity) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(domain) DO UPDATE SET status = excluded.status, source = excluded.source, "
        "reason = excluded.reason, checked_at = excluded.checked_at, expires_at = excluded.expires_at, "
        "level = excluded.level, alert_severity = excluded.alert_severity",
        (domain, result["status"], result["source"], result["reason"],
         now.strftime(TIME_FORMAT), expires.strftime(TIME_FORMAT), result.get("level"), result.get("alert_severity") if result.get("level") is not None else None),
    )
    conn.commit()


# --------------------------------------------------------------------
# Evidence (what each provider found) - stored per domain and provider
# --------------------------------------------------------------------
def store_evidence(conn, domain, name, result, now):
    """Keep what one provider answered: its verdict, the whitelisted counts, when, until when, and - when it could not
    answer - the short error text. The provider's raw response is never stored."""
    _refuse_url_scope(result)
    state = result.get("state", STATE_CHECKED)
    verdict = result["status"] if state == STATE_CHECKED else None
    raw = result.get("evidence") or {}
    counts = dict((k, int(raw[k])) for k in EVIDENCE_KEYS if k in raw and isinstance(raw[k], int) and not isinstance(raw[k], bool))
    ttl = _validity(result, ttl_for(result["status"])) if state == STATE_CHECKED else timedelta(minutes=UNKNOWN_CACHE_MINUTES)
    details = result.get("details") if state == STATE_CHECKED and isinstance(result.get("details"), dict) else None
    conn.execute(
        "INSERT INTO reputation_evidence (domain, provider, state, provider_verdict, reason, evidence_json, error, checked_at, expires_at, details_json) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(domain, provider) DO UPDATE SET state = excluded.state, provider_verdict = excluded.provider_verdict, "
        "reason = excluded.reason, evidence_json = excluded.evidence_json, error = excluded.error, "
        "checked_at = excluded.checked_at, expires_at = excluded.expires_at, details_json = excluded.details_json",
        (domain, name, state, verdict, result.get("reason"), json.dumps(counts) if counts else None,
         (result.get("error") or None) if state != STATE_CHECKED else None,
         now.strftime(TIME_FORMAT), (now + ttl).strftime(TIME_FORMAT), json.dumps(details) if details else None))
    conn.commit()


def _cached_provider_result(conn, domain, name, now):
    """A still-valid CHECKED answer of this provider for this domain (provider-level cache), or None."""
    row = conn.execute("SELECT provider_verdict, reason, evidence_json, expires_at, details_json FROM reputation_evidence "
                       "WHERE domain = ? AND provider = ? AND state = ?", (domain, name, STATE_CHECKED)).fetchone()
    if row is None or row["expires_at"] < now.strftime(TIME_FORMAT) or row["provider_verdict"] not in STATUSES:
        return None
    result = _result(row["provider_verdict"], name, row["reason"] or "")
    result["evidence"] = json.loads(row["evidence_json"]) if row["evidence_json"] else {}
    result["state"] = STATE_CHECKED
    result["reused"] = True
    result["cache_seconds"] = max(0.0, (datetime.strptime(row["expires_at"], TIME_FORMAT) - now).total_seconds())          # what is left of its own validity
    details = evidence.read_details(row["details_json"]) if "details_json" in row.keys() else None
    if details:
        if details.get("list_based"):
            result["list_based"] = True
        if details.get("coverage_gap"):
            result["coverage_gap"] = True
        if details.get("applied_level") is not None and (config.SEVERITY_POLICY == "evidence" or details.get("list_based")):
            result["level"] = details["applied_level"]
            result["alert_severity"] = details.get("applied_alert_severity")
    return result


SEVERITY_ORDER = {MALICIOUS: 3, SUSPICIOUS: 2, SAFE: 1, UNKNOWN: 0}
_ALERT_RANK = {"HIGH": 2, "MEDIUM": 1}


def decide(results):
    """The ONE overall verdict from the provider results. A single provider's verdict is the overall verdict, unchanged.
    With several, the most serious verdict wins; UNKNOWN (a provider that failed or knows nothing) never outranks a real
    answer and never turns into SAFE."""
    if len(results) == 1:
        only = results[0]
        return _carry_policy(_result(only["status"], only["source"], only["reason"]), only, results)
    # equal verdicts: the one that raises the stronger alert decides, so a weak finding listed first can never hide a credible one (order of providers no longer matters)
    best = max(results, key=lambda r: (SEVERITY_ORDER[r["status"]], _ALERT_RANK.get(alert_severity_for(r), 0)))
    if best["status"] == SAFE and any(r["status"] == UNKNOWN and not r.get("coverage_gap") for r in results) and all(r.get("list_based") for r in results if r["status"] == SAFE):
        # Only list-based sources (Safe Browsing, OTX, urlscan.io) found nothing, and another source could not be asked: absence from a list is not proof of safety, so the overall
        # answer stays "not checked" instead of becoming SAFE.
        unknown = sorted(set(r["source"] for r in results if r["status"] == UNKNOWN))
        return _result(UNKNOWN, ", ".join(unknown), "Not enough information: %s could not check this website, and the sources that did only list known threats." % ", ".join(unknown))
    agreeing = sorted(set(r["source"] for r in results if r["status"] == best["status"]))
    return _carry_policy(_result(best["status"], ", ".join(agreeing), best["reason"]), best, results)


def _carry_policy(result, source, results=()):
    """A provider decided by the evidence policy (or a list-based source, which always decides for itself) hands its assessment (level, alert decision) on to the overall verdict;
    the overall verdict is valid no longer than the shortest validity any provider gave."""
    limits = [r["cache_seconds"] for r in results if isinstance(r.get("cache_seconds"), (int, float))]
    if limits:
        result["cache_seconds"] = min(limits)
    if source.get("level") is not None:
        result["level"] = source["level"]
        result["alert_severity"] = source.get("alert_severity")
    return result


# --------------------------------------------------------------------
# Public entry point
# --------------------------------------------------------------------
def _run_provider(domain, provider, budget, now, source=None):
    """Ask one provider (cooldown and budget respected). Returns its normalised result plus 'state' and, when it was not
    asked, 'attempted': False. Never raises."""
    name = provider.name
    entry = _entry(name)
    if entry.get("breaker_fp") is not None:
        if entry["breaker_fp"] == _provider_fingerprint(provider):          # circuit breaker open: this credential was rejected, so no request is made with it
            result = _result(UNKNOWN, name, UNAVAILABLE_REASON_PREFIX + " (credentials rejected earlier).")
            result.update(state=STATE_ERROR, error="credentials rejected earlier (%s); not retried until the key changes or the server restarts" % entry["last_error"])
            return result
        entry["breaker_fp"], entry["unavailable_until"] = None, None          # a different key: the breaker closes
    if _in_cooldown(name, now):
        error = _entry(name)["last_error"]
        result = _result(UNKNOWN, name, "Reputation service temporarily unavailable (%s)." % error)
        result.update(state=STATE_UNAVAILABLE, error="cooling down after: %s" % error)
        return result
    if budget is not None:
        if not budget.try_acquire(now):
            return dict(_result(UNKNOWN, "none", NOT_CHECKED_YET_REASON), state=STATE_NOT_CHECKED, deferred=True)   # not cached
    shared = shared_budget_for(provider)
    if shared is not None and not shared.acquire(source, now):
        if budget is not None:
            budget.refund(now)                 # the source's own allowance was booked but nothing is sent
        return dict(_result(UNKNOWN, "none", SHARED_LIMIT_REASON), state=STATE_NOT_CHECKED, deferred=True)   # not cached
    try:
        result = provider.lookup(domain)
        if not result or result.get("status") not in STATUSES:
            raise ProviderError("unexpected provider result", COOLDOWN_ERROR_MINUTES)
        _record_success(name, now)
        result = dict(result)
        result["state"] = STATE_CHECKED
    except ProviderError as err:
        # HTTP-level failure the provider understood: back off (no rapid retries on 429/401).
        _record_failure(name, str(err), err.cooldown_minutes, now, err.kind, auth=err.auth, fingerprint=_provider_fingerprint(provider))
        result = _result(UNKNOWN, name, UNAVAILABLE_REASON_PREFIX + " (%s)." % err)
        result.update(state=err.kind, error=str(err))
    except Exception:  # any other bug in a provider must never break ingestion
        result = _result(UNKNOWN, name, UNAVAILABLE_REASON_PREFIX + ".")
        result.update(state=STATE_ERROR, error="unexpected provider failure")
    return result


def check_domain(conn, domain, provider=None, budget=None, providers=None, source=None, deadline=None):
    """Cached verdict if fresh; otherwise ask the provider(s), keep each one's evidence and cache the overall verdict.
    Never raises. Any provider problem -> UNKNOWN (never SAFE).
    `provider` / `providers` override the configured ones (tests); `budget` (a LookupBudget) limits how many provider
    calls the caller's source may start: a cache hit is always free; when the budget is spent the answer is UNKNOWN and
    is not cached. With several providers each keeps its own cache: one whose evidence is still valid is not asked again."""
    cached = get_cached(conn, domain)
    if cached is not None and not _missing_sources(conn, domain, provider, providers):
        return cached
    with _domain_lock(domain):
        cached = get_cached(conn, domain)          # another request may have just asked the provider about this very domain
        if cached is not None:
            missing = _missing_sources(conn, domain, provider, providers)
            if not missing:
                return cached
            for name in missing:                   # the website is re-opened for these sources: not again for MISSING_SOURCE_RETRY_SECONDS
                _missing_probe[(domain, name)] = time.monotonic()
        return _check_uncached(conn, domain, provider, budget, providers, source, deadline)


_missing_probe = {}                     # (domain, source) -> when a cached website was last re-opened because that source had never answered for it
MISSING_SOURCE_RETRY_SECONDS = 600


def _missing_sources(conn, domain, provider, providers):
    """The sources that are configured NOW but never left evidence for a website that has a cached verdict - typically sources switched on after the website was cached ([] if none).
    Then the website is looked at again: the sources that already have valid evidence are reused (no request), only the new one is asked. Retried at most every
    MISSING_SOURCE_RETRY_SECONDS per website and source, so a source that stays over its budget cannot cause a request storm."""
    if provider is not None or providers is not None:
        return []                                   # tests / explicit providers: exactly what was passed
    configured = [p.name for p in configured_providers()]
    if len(configured) < 2:
        return []
    have = set(r[0] for r in conn.execute("SELECT provider FROM reputation_evidence WHERE domain = ?", (domain,)))
    now = time.monotonic()
    return [n for n in configured if n not in have and now - _missing_probe.get((domain, n), -1e9) >= MISSING_SOURCE_RETRY_SECONDS]


def _run_providers(domain, providers, budget, now, source, deadline=None):
    """[result per provider]. One provider: asked in place (exactly the earlier behaviour). Several: asked in parallel threads, each bounded by its own timeout."""
    budgets = [budget] + [None] * (len(providers) - 1)
    if len(providers) <= 1:
        return [_run_provider(domain, p, b, now, source) for p, b in zip(providers, budgets)]
    out = [None] * len(providers)

    def worker(i):
        try:
            out[i] = _run_provider(domain, providers[i], budgets[i], now, source)
        except Exception:               # _run_provider never raises; this is belt and braces so a thread can never leave a hole
            out[i] = dict(_result(UNKNOWN, providers[i].name, UNAVAILABLE_REASON_PREFIX + "."), state=STATE_ERROR, error="unexpected provider failure")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(len(providers))]
    for t in threads:
        t.start()
    for t in threads:
        t.join(min(PROVIDER_TIMEOUT_SECONDS + 4, deadline.host_remaining()) if deadline is not None else PROVIDER_TIMEOUT_SECONDS + 4)
    out = list(out)                      # a snapshot: a thread that finishes after the deadline can no longer change what is returned
    for i, value in enumerate(out):
        if value is None:                # a thread that never came back: treated as an unavailable provider, never as an answer
            out[i] = dict(_result(UNKNOWN, providers[i].name, UNAVAILABLE_REASON_PREFIX + " (timeout)."), state=STATE_UNAVAILABLE, error="timeout")
    return out


def _check_uncached(conn, domain, provider, budget, providers, source, deadline=None):
    now = _now()
    if providers is None:
        providers = [provider] if provider is not None else configured_providers()
    if not providers:
        result = _result(UNKNOWN, "none", "No reputation provider is configured.")
        store(conn, domain, result)
        return result

    results = [None] * len(providers)
    to_run = []
    for index, p in enumerate(providers):
        reused = _cached_provider_result(conn, domain, p.name, now) if len(providers) > 1 else None
        if reused is not None:
            results[index] = reused
        else:
            to_run.append(index)
    # The source's own allowance is charged ONCE per domain (by the first source asked), not once per provider. Several providers are asked at the same time, so a slow one
    # delays the answer by its own timeout, not by the sum of all of them. No database access happens in the lookups themselves.
    fresh = _run_providers(domain, [providers[i] for i in to_run], budget, now, source, deadline)
    for index, result in zip(to_run, fresh):
        results[index] = result
        if not result.get("deferred"):
            store_evidence(conn, domain, providers[index].name, result, now)

    # Phase F3.22: observation-only sources (APIVoid, MetaDefender Cloud, AbuseIPDB) are stored above but NEVER enter the verdict, so they cannot create, change or lower an alert.
    answered = [r for r, p in zip(results, providers) if not r.get("deferred") and getattr(p, "name", "") not in OBSERVED_PROVIDERS]
    if not answered:
        return _result(UNKNOWN, "none", NOT_CHECKED_YET_REASON)           # deliberately not cached
    overall = decide(answered)
    store(conn, domain, overall)
    overall.pop("cache_seconds", None)               # bookkeeping for the cache only; not part of the answer the callers see
    return overall


# --------------------------------------------------------------------
# Address-level (URL-scoped) check of ONE visit - Google Safe Browsing lookup_url (Phase F3.9)
# --------------------------------------------------------------------
URL_SCOPE_COOLDOWN_KEY = "Google Safe Browsing (address check)"          # its own back-off: an address-level failure never cools down the host-level check
SKIP_REASONS = {
    "sensitive": "The address looks like it may carry a private link or a token, so it was not sent to Google (hash prefixes included). Only the site as a whole was checked.",
    "budget": "Google Safe Browsing's request limit was reached (part of it is kept in reserve so that new sites keep being checked), so this address was not checked.",
    "time": "The answer had to be sent quickly, and there was not enough time left to check this address, so it was not checked.",
    "host-listed": "Google already lists the whole site (host-level), so a separate address check was not needed.",
    "cooldown": "Google Safe Browsing was temporarily unavailable, so this address was not checked.",
}


def _url_evidence_write(conn, visit_id, provider, state, now, url_key=None, result=None, skip_reason=None, error=None, expires_at=None, reused=False):
    """The visit's own evidence row (one per visit and provider). Never holds an address, a path or a credential."""
    result = result or {}
    checked = state == STATE_CHECKED
    details = result.get("details") if isinstance(result.get("details"), dict) else None
    conn.execute(
        "INSERT INTO visit_url_evidence (web_visit_id, provider, scope, url_key, state, provider_verdict, level, alert_severity, reason, skip_reason, details_json, error, "
        "checked_at, expires_at, reused) VALUES (?, ?, 'url', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (web_visit_id, provider) DO NOTHING",
        (visit_id, provider, url_key, state, result.get("status") if checked else None, result.get("level") if checked else None,
         result.get("alert_severity") if checked else None, result.get("reason") if checked else None, skip_reason,
         json.dumps(details) if details and checked else None, error, now.strftime(TIME_FORMAT), expires_at, 1 if reused else 0))
    conn.commit()


def _visit_url_row(conn, visit_id, name):
    return conn.execute("SELECT * FROM visit_url_evidence WHERE web_visit_id = ? AND provider = ?", (visit_id, name)).fetchone()


def url_outcome(row):
    """What the route needs from a visit's address evidence row: {"state", "status", "level", "severity", "categories", "reused", "provider"} (severity None when no alert is called for)."""
    if row is None:
        return None
    details = evidence.read_details(row["details_json"]) if row["details_json"] else None
    categories = sorted(set(d.get("result") for d in ((details or {}).get("detections") or []) if d.get("result")))
    return {"state": row["state"], "status": row["provider_verdict"], "level": row["level"], "severity": row["alert_severity"] if row["state"] == STATE_CHECKED else None,
            "categories": categories, "reused": bool(row["reused"]), "provider": row["provider"]}


def check_visit_url(conn, visit_id, domain, sanitized_url, source=None, provider=None, now=None, deadline=None):
    """Check THIS visit's page address at address level and keep the answer WITH THE VISIT (visit_url_evidence). Returns url_outcome(row), or None when nothing applies (Google is
    off or has no key; the visit has no usable address; the address is only the site's root, which the host-level check covers).

      * eligibility: urlcheck.assess - a sensitive-looking path is never sent anywhere (a NOT_CHECKED row; no address and no key are kept);
      * reuse: an answer for the same address (url_lookup_cache, valid until the provider's own cache duration ends) is copied to this visit - from any computer - with no request;
      * a repeat for the same visit (a reload burst) finds its row and neither asks nor writes again;
      * the request is Google's v5 hash-prefix lookup (GoogleSafeBrowsingProvider.lookup_url), counted in the SAME shared budget as the host-level check, with its own cooldown;
      * a failure is stored on the visit as UNAVAILABLE / ERROR (never SAFE) and changes nothing else: the host-level verdict is untouched;
      * the answer is URL-scoped: it is never written to domain_reputation or reputation_evidence, so it can never become the verdict of a whole host."""
    gsb = provider or build_gsb_provider()
    if gsb is None or not sanitized_url:
        return None
    name = gsb.name
    now = now or _now()
    existing = _visit_url_row(conn, visit_id, name)
    if existing is not None:
        return url_outcome(existing)
    verdict = urlcheck.assess(sanitized_url)
    if verdict["skip"] in ("no-path", "not-http"):
        return None
    if verdict["skip"] == "sensitive":
        _url_evidence_write(conn, visit_id, name, STATE_NOT_CHECKED, now, skip_reason="sensitive")
        return url_outcome(_visit_url_row(conn, visit_id, name))
    listed = conn.execute("SELECT 1 FROM reputation_evidence WHERE domain = ? AND provider = ? AND state = ? AND provider_verdict IN (?, ?)",
                          (domain, name, STATE_CHECKED, MALICIOUS, SUSPICIOUS)).fetchone()
    expressions = safebrowsing.url_expressions(sanitized_url)
    if listed is not None or not expressions:
        _url_evidence_write(conn, visit_id, name, STATE_NOT_CHECKED, now, skip_reason="host-listed" if listed is not None else "sensitive")
        return url_outcome(_visit_url_row(conn, visit_id, name))
    key = urlcheck.url_key(expressions[:30])
    lock = _domain_lock("url:" + key)                      # two computers asking about one new address at the same moment make ONE request
    if not lock.acquire(timeout=deadline.remaining() if deadline is not None else -1):          # never wait longer than the request may take
        _url_evidence_write(conn, visit_id, name, STATE_NOT_CHECKED, now, skip_reason="time")
        return url_outcome(_visit_url_row(conn, visit_id, name))
    try:
        existing = _visit_url_row(conn, visit_id, name)
        if existing is not None:
            return url_outcome(existing)
        cached = conn.execute("SELECT * FROM url_lookup_cache WHERE url_key = ? AND provider = ? AND expires_at > ?", (key, name, now.strftime(TIME_FORMAT))).fetchone()
        if cached is not None:
            result = _result(cached["provider_verdict"], name, cached["reason"] or "")
            result.update(level=cached["level"], alert_severity=cached["alert_severity"], details=json.loads(cached["details_json"]) if cached["details_json"] else None)
            _url_evidence_write(conn, visit_id, name, STATE_CHECKED, now, url_key=key, result=result, expires_at=cached["expires_at"], reused=True)
            conn.execute("UPDATE visit_url_evidence SET checked_at = ? WHERE web_visit_id = ? AND provider = ?", (cached["checked_at"], visit_id, name))     # WHEN it was really asked
            conn.commit()
        else:
            _ask_address_provider(conn, visit_id, gsb, sanitized_url, key, source, now, deadline)
    finally:
        lock.release()
    return url_outcome(_visit_url_row(conn, visit_id, name))


def _ask_address_provider(conn, visit_id, gsb, sanitized_url, key, source, now, deadline=None):
    name = gsb.name
    timeout = None
    if deadline is not None:
        left = deadline.remaining()
        if left < ADDRESS_MIN_SECONDS:
            _url_evidence_write(conn, visit_id, name, STATE_NOT_CHECKED, now, skip_reason="time")
            return
        timeout = left
    if _in_cooldown(URL_SCOPE_COOLDOWN_KEY, now):
        error = _entry(URL_SCOPE_COOLDOWN_KEY)["last_error"]
        _url_evidence_write(conn, visit_id, name, STATE_UNAVAILABLE, now, url_key=key, error="cooling down after: %s" % error, skip_reason="cooldown")
        return
    shared = shared_budget_for(gsb)
    if shared is not None and not shared.acquire(source, now, reserve=ADDRESS_BUDGET_SHARE):          # lower priority than a host-level check: only up to its share of the allowance
        _url_evidence_write(conn, visit_id, name, STATE_NOT_CHECKED, now, skip_reason="budget")
        return
    try:
        result = gsb.lookup_url(sanitized_url, timeout=timeout) if timeout is not None else gsb.lookup_url(sanitized_url)
        if not result or result.get("status") not in STATUSES or result.get("scope") != "url":
            raise ProviderError("unexpected provider result", COOLDOWN_ERROR_MINUTES)
        _record_success(URL_SCOPE_COOLDOWN_KEY, now)
    except ProviderError as err:
        _record_failure(URL_SCOPE_COOLDOWN_KEY, str(err), err.cooldown_minutes, now, err.kind)
        _url_evidence_write(conn, visit_id, name, err.kind, now, url_key=key, error=str(err))
        return
    except Exception:                                       # a bug in a provider must never break ingestion
        _url_evidence_write(conn, visit_id, name, STATE_ERROR, now, url_key=key, error="unexpected provider failure")
        return
    expires = now + _validity(result, ttl_for(result["status"]))
    if result["status"] in (SAFE, SUSPICIOUS, MALICIOUS):
        details = result.get("details") if isinstance(result.get("details"), dict) else None
        conn.execute(
            "INSERT INTO url_lookup_cache (url_key, provider, scope, state, provider_verdict, level, alert_severity, reason, details_json, checked_at, expires_at) "
            "VALUES (?, ?, 'url', 'CHECKED', ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (url_key, provider) DO UPDATE SET provider_verdict = excluded.provider_verdict, "
            "level = excluded.level, alert_severity = excluded.alert_severity, reason = excluded.reason, details_json = excluded.details_json, "
            "checked_at = excluded.checked_at, expires_at = excluded.expires_at",
            (key, name, result["status"], result.get("level"), result.get("alert_severity"), result.get("reason"), json.dumps(details) if details else None,
             now.strftime(TIME_FORMAT), expires.strftime(TIME_FORMAT)))
        conn.commit()
    _url_evidence_write(conn, visit_id, name, STATE_CHECKED, now, url_key=key, result=result, expires_at=expires.strftime(TIME_FORMAT))     # UNKNOWN is shown on the visit, never cached


URL_FINDING = "URL-level finding"            # the words an alert event's detail starts with when a PAGE (not the site) was flagged
WHY_IT_MATTERS_PAGE = {
    "HIGH": "Google Safe Browsing identified a specific page that was opened as potentially malicious. This is about that page, not necessarily the rest of the site, "
            "and it does not by itself mean the computer is compromised.",
    "MEDIUM": "Google Safe Browsing reported a warning about a specific page that was opened. This is about that page only and does not mean it is harmful, only that it should be reviewed.",
}
_LEVEL_WORDS = {"CONFIRMED": "Confirmed", "CREDIBLE": "Credible", "WEAK": "Weak", "CLEAN": "No listing found", "UNKNOWN": "Unknown"}


def page_path_of(visit_row):
    """The path of an address that PASSED the sensitivity rules, else None (a sensitive path is never shown anywhere new)."""
    url = visit_row["sanitized_url"] if "sanitized_url" in visit_row.keys() else None
    if url and urlcheck.assess(url)["eligible"]:
        return urlcheck.display_path(url)
    return None


def address_cards(rows):
    """The address-level checks of a visit as display dictionaries for the analysis page: provider, scope, state, verdict, strength, threat categories, times, skip reason, error."""
    cards = []
    for r in rows:
        details = evidence.read_details(r["details_json"]) if r.get("details_json") else None
        categories = sorted(set(d.get("result") for d in ((details or {}).get("detections") or []) if d.get("result")))
        checked = r["state"] == STATE_CHECKED
        cards.append({
            "provider": r["provider"], "scope_label": "Address-level (this page only)", "state": r["state"], "state_label": STATE_LABELS.get(r["state"], r["state"].replace("_", " ").title()),
            "verdict": r["provider_verdict"] if checked else None, "strength": _LEVEL_WORDS.get(r["level"] or "", None) if checked else None,
            "weak": checked and r["level"] == "WEAK", "categories": categories, "checked_at": r["checked_at"], "valid_until": r["expires_at"], "reused": bool(r["reused"]),
            "skip_text": SKIP_REASONS.get(r["skip_reason"] or "", None), "error": r["error"], "reason": r["reason"] if checked else None,
            "raised_verdict": checked and r["provider_verdict"] in (SUSPICIOUS, MALICIOUS) and bool(r["alert_severity"])})
    return cards


def address_summary(rows):
    """One phrase for the visits lists about THIS page's own address check, or '' when there was none. A failed or skipped check is said to be NOT checked, never clean."""
    if not rows:
        return ""
    parts = []
    for r in rows:
        name = r["provider"]
        if r["state"] == STATE_CHECKED:
            details = evidence.read_details(r["details_json"]) if r.get("details_json") else None
            found = sorted(set(d.get("result") for d in ((details or {}).get("detections") or []) if d.get("result")))
            parts.append("%s - this page: %s" % (name, ("listed as " + ", ".join(found)) if found else "no known threat listed"))
        elif r["state"] == STATE_NOT_CHECKED:
            parts.append("%s - this page was not checked" % name)
        else:
            parts.append("%s - this page was not checked (%s)" % (name, _STATE_WORDS.get(r["state"], "failed")))
    return "; ".join(parts)


# --------------------------------------------------------------------
# Reading the analysis back (for the pages)
# --------------------------------------------------------------------
def _short_reason_state(status, reason):
    """The state of a domain that has a cached verdict but no per-provider evidence row."""
    text = reason or ""
    if text == NOT_CHECKED_YET_REASON:
        return STATE_NOT_CHECKED
    if text.startswith("No reputation provider"):
        return STATE_NO_PROVIDER
    if text.startswith(UNAVAILABLE_REASON_PREFIX):
        return STATE_UNAVAILABLE
    return STATE_NO_EVIDENCE


def analysis_bulk(conn, domains):
    """{domain: analysis} for these domains with two queries. analysis = {"overall": {...} or None, "providers": [cards],
    "not_configured": [names]}. Never raises for a domain without evidence (older rows): the card says so."""
    domains = sorted(set(d for d in domains if d))
    out = {}
    if not domains:
        return out
    marks = ",".join("?" for _ in domains)
    overall_rows = dict((r["domain"], r) for r in conn.execute(
        "SELECT domain, status, source, reason, checked_at, expires_at FROM domain_reputation WHERE domain IN (%s)" % marks, domains))
    evidence_rows = {}
    for r in conn.execute("SELECT * FROM reputation_evidence WHERE domain IN (%s) ORDER BY provider" % marks, domains):
        if r["provider"] in LEGACY_EVIDENCE_PROVIDERS:
            continue                 # kept in the database, never shown or used
        evidence_rows.setdefault(r["domain"], []).append(r)
    configured = bool(config.VT_API_KEY)
    for domain in domains:
        overall = overall_rows.get(domain)
        cards = []
        for r in evidence_rows.get(domain, []):
            counts = json.loads(r["evidence_json"]) if r["evidence_json"] else None
            details = evidence.read_details(r["details_json"]) if "details_json" in r.keys() else None          # None for rows stored before Phase F2
            cards.append({"details": details, "provider": r["provider"], "state": r["state"], "state_label": STATE_LABELS.get(r["state"], r["state"]),
                          "verdict": r["provider_verdict"], "reason": r["reason"], "counts": counts,
                          "total": sum(counts.values()) if counts else None, "error": r["error"],
                          "checked_at": r["checked_at"], "valid_until": r["expires_at"]})
        if not cards and overall is not None:
            state = _short_reason_state(overall["status"], overall["reason"])
            if state == STATE_NO_EVIDENCE and overall["source"] in (None, "", "none"):
                state = STATE_NO_PROVIDER
            cards.append({"details": None, "provider": overall["source"] if overall["source"] not in (None, "", "none") else VirusTotalProvider.name,
                          "state": state, "state_label": STATE_LABELS[state],
                          "verdict": overall["status"] if state == STATE_NO_EVIDENCE else None, "reason": overall["reason"],
                          "counts": None, "total": None, "error": None, "checked_at": overall["checked_at"], "valid_until": overall["expires_at"]})
        if not cards:
            state = STATE_NO_PROVIDER if not configured else STATE_NOT_CHECKED
            cards.append({"details": None, "provider": VirusTotalProvider.name, "state": state, "state_label": STATE_LABELS[state], "verdict": None,
                          "reason": None, "counts": None, "total": None, "error": None, "checked_at": None, "valid_until": None})
        out[domain] = {"overall": dict(overall) if overall is not None else None, "providers": cards,
                       "not_configured": [n for n in FUTURE_PROVIDERS if n not in [c["provider"] for c in cards]]}
    return out


_STATE_WORDS = {STATE_UNAVAILABLE: "unavailable", STATE_ERROR: "error", STATE_NOT_CHECKED: "not checked yet"}


def _facts_of(card):
    """What ONE provider found, in that provider's own terms - never another provider's: VirusTotal counts security vendors, Google Safe Browsing names threat categories.
    None when the card carries nothing to say."""
    details = card.get("details") or {}
    if "pulse_count" in details:                          # AlienVault OTX (community pulses)
        if not details["pulse_count"]:
            return "no community report mentions this site"
        return "%d community report(s) mention this site (%d recent), context only" % (details["pulse_count"], details.get("recent_pulses") or 0)
    if "total_scans" in details:                          # urlscan.io (existing public scans)
        if details.get("verdicts_readable") is False and details["total_scans"]:
            return "%d existing scan(s) of this site, verdicts not readable at this access level (a gap, not a clean result)" % details["total_scans"]
        if details.get("coverage_gap") or not details["total_scans"]:
            return "no scan of this site exists (a gap, not a clean result)"
        return "%d existing scan(s) of this site, %d with a malicious verdict" % (details["total_scans"], details.get("malicious_scans") or 0)
    if details.get("list_based"):                         # Google Safe Browsing
        found = sorted(set(d.get("result") for d in (details.get("detections") or []) if d.get("result")))
        return ("listed as " + ", ".join(found)) if found else "no known threat listed"
    counts = card.get("counts")
    if counts:                                            # VirusTotal: security vendor counts
        return "%d malicious, %d suspicious" % (counts.get("malicious", 0), counts.get("suspicious", 0))
    return None


def summarize(analysis):
    """One short line for the table: who checked it and what each source found IN ITS OWN TERMS - or why nobody did. Never says 'checked' for a provider that did not answer; a
    provider that failed is named as not checked next to the ones that answered."""
    if not analysis:
        return "No analysis recorded."
    visible = [c for c in analysis["providers"] if c["provider"] not in OBSERVED_PROVIDERS] or analysis["providers"]          # the observation-only sources are shown on the analysis page
    checked = [c for c in visible if c["state"] == STATE_CHECKED]
    failed = [c for c in visible if c["state"] in _STATE_WORDS]
    if checked:
        names = ", ".join(c["provider"] for c in checked)
        facts = [(c["provider"], _facts_of(c)) for c in checked]
        if len(checked) == 1:
            text = "Checked by %s: %s" % (names, facts[0][1] or "no vendor results available")
        elif any(f for _, f in facts):
            text = "Checked by %s: %s" % (names, "; ".join("%s - %s" % (n, f or "no details") for n, f in facts))
        else:
            text = "Checked by %s: no vendor results available" % names
        if failed:
            text += " (not checked: %s)" % ", ".join("%s %s" % (c["provider"], _STATE_WORDS[c["state"]]) for c in failed)
        return text
    first = analysis["providers"][0]
    state = first["state"]
    if state == STATE_NO_EVIDENCE:
        who = first["provider"]
        return "Checked by %s (details were not recorded)" % who if first["verdict"] in (SAFE, SUSPICIOUS, MALICIOUS) else "Not checked: no details recorded"
    return {STATE_UNAVAILABLE: "Not checked: provider unavailable", STATE_ERROR: "Not checked: provider error",
            STATE_NOT_CHECKED: "Not checked yet", STATE_NO_PROVIDER: "Not checked: no provider configured"}.get(state, "Not checked")


WEAK_HINT_DEFAULT = "One or very few security vendors flagged this website. That is not enough evidence to raise an alert; see the analysis for who flagged it."
WEAK_HINTS = {
    "VirusTotal": WEAK_HINT_DEFAULT,
    "Google Safe Browsing": "Google Safe Browsing reported a weak signal about this website. That is not enough evidence to raise an alert; see the analysis.",
}


def weak_hint(analysis):
    """The tooltip of a 'Weak finding', worded for the source(s) that produced it (a vendor count is not a URL list)."""
    names = sorted(set(c["provider"] for c in (analysis or {}).get("providers", [])
                       if c["state"] == STATE_CHECKED and (c.get("details") or {}).get("classification") == "WEAK"))
    hints = [WEAK_HINTS[n] for n in names if n in WEAK_HINTS]
    return " ".join(hints) if hints else WEAK_HINT_DEFAULT


# Plain-language alert text for the dashboard audience.
ALERT_SEVERITY = {MALICIOUS: "HIGH", SUSPICIOUS: "MEDIUM"}
# Deterministic wording. A visit to a bad website does not prove the computer is
# compromised, and the product neither blocks sites nor remediates, so the text
# never claims either.
RECOMMENDED_ACTION = {
    "HIGH": "Ask the user to close the website and avoid reopening it. If the visit was unexpected, "
            "contact your IT administrator for further review.",
    "MEDIUM": "Review whether this website was expected. If not, ask the user to avoid reopening it "
              "and contact your IT administrator.",
}
WHY_IT_MATTERS = {
    "HIGH": "The reputation service identified this website as potentially malicious. "
            "Visiting it does not by itself mean the computer is compromised.",
    "MEDIUM": "The reputation service reported suspicious signals about this website. "
              "This does not mean it is harmful, only that it should be reviewed.",
}

# Wording for alerts raised by the Windows network agent. It only knows that a program on the
# computer looked a domain up, so these never say that anybody "visited" or opened a website.
WHY_IT_MATTERS_AGENT = {
    "HIGH": "A program on this computer looked up a domain that the reputation service identified as "
            "potentially malicious. This shows a lookup, not necessarily that a person opened a website, "
            "and it does not by itself mean the computer is compromised.",
    "MEDIUM": "A program on this computer looked up a domain that the reputation service reported suspicious "
              "signals about. This does not mean it is harmful, only that it should be reviewed.",
}
RECOMMENDED_ACTION_AGENT = {
    "HIGH": "Find out which program or website on that computer used this domain. If it was unexpected, "
            "contact your IT administrator for further review.",
    "MEDIUM": "Review whether this domain was expected on that computer. If not, contact your IT administrator.",
}
