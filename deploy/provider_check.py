"""Isolated diagnostic for the optional reputation sources: Google Safe Browsing (v5 hashes.search), AlienVault OTX (domain indicator) and urlscan.io (search of
EXISTING scans - nothing is ever submitted). --provider all asks the three of them; VirusTotal is not covered here (its integration is older and has its own checks).

    python deploy/provider_check.py                                  # DRY RUN: shows exactly what would be sent. Sends nothing.
    python deploy/provider_check.py --provider google --vector       # dry run of Google's documented test vector
    python deploy/provider_check.py --live --provider google --domain example.com       # LIVE: asks you to type SEND first
    python deploy/provider_check.py --live --provider otx --domain example.com          # needs OTX_API_KEY in the environment
    python deploy/provider_check.py --live --provider urlscan --domain example.com      # URLSCAN_API_KEY is optional

What it is: a thin command-line wrapper around the SAME adapters the application uses (services/reputation.py). What it is NOT: it does not import or start the Flask application, never
opens or creates a SQLite database (the configuration module is loaded in its no-database test mode with a throw-away path that is never opened, which also keeps it from reading the
production .env), writes no file, and creates no visit, alert or cached verdict. Nothing is stored anywhere; it only prints.

Credentials come ONLY from environment variables (GSB_API_KEY, OTX_API_KEY, URLSCAN_API_KEY - the last one optional): never from the command line, never from a file. They are never printed (every line of output is passed
through a redaction filter as a second safeguard) and never written.

Safety: no request is sent unless you pass --live AND type SEND at the prompt that lists every request first. Only lookups are made - no URL is submitted for scanning and no page is
fetched. Google receives only 4-byte hash prefixes; the others receive the host name you typed and your key. At most 6 lookups per run. Exit code 0 = every lookup answered, 1 = some
lookup failed or was skipped, 2 = refused / usage.

Inputs: --domain NAME (repeatable; default example.com, a harmless known-clean name), --url ADDRESS (Google only; the query and fragment are dropped, only the path is used),
--vector (Google's documented test page testsafebrowsing.appspot.com/s/malware.html: the page is never visited, only its hash prefix is sent).
Python 3.8 compatible; standard library plus requests.
"""
import argparse
import json
import os
import re
import sys
import tempfile
import time

# No database, no .env: the application's configuration module, imported in its test mode, skips the production .env and demands a throw-away database path (never opened here).
os.environ["WEBSITE_MONITOR_TEST_MODE"] = "1"
os.environ["DATABASE_PATH"] = os.path.join(tempfile.gettempdir(), "provider_check_never_opened.db")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import requests  # noqa: E402
from services import reputation, safebrowsing  # noqa: E402

MAX_LOOKUPS = 6
DEFAULT_DOMAIN = "example.com"
VECTOR_URL = "http://testsafebrowsing.appspot.com/s/malware.html"          # Google's documented Safe Browsing test page (never fetched)
CREDENTIALS = {"google": "GSB_API_KEY", "otx": "OTX_API_KEY", "urlscan": "URLSCAN_API_KEY"}
OPTIONAL_KEY = ("urlscan",)                     # urlscan.io searches work without a key (small quotas)
LABELS = {"google": "Google Safe Browsing", "otx": "AlienVault OTX", "urlscan": "urlscan.io"}
HOSTS = {"google": "safebrowsing.googleapis.com", "otx": "otx.alienvault.com", "urlscan": "urlscan.io"}
_HOSTNAME = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)(\.[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)*\.?$")


class Refused(Exception):
    """A usage problem or a refusal; the message is safe to print."""


class RecordingSession(object):
    """Wraps a requests session and notes, for each call, only what is safe to show: method, host and path (never the query, the headers or the credentials), HTTP status, duration,
    the size of the answer and the names of its top-level fields."""

    def __init__(self, real=None):
        self.real = real if real is not None else requests.Session()
        self.records = []

    def _do(self, method, url, **kwargs):
        started = time.time()
        record = {"method": method.upper(), "endpoint": url.split("?", 1)[0], "http_status": None, "ms": None, "answer_bytes": None, "answer_fields": None, "retry_after": None, "error": None,
                  "content_type": None, "starts_with": None, "json_kind": None, "format": None}
        self.records.append(record)
        try:
            response = getattr(self.real, method)(url, **kwargs)
        except Exception as error:                                     # only the class name is kept: the text of a network error can contain the address
            record["ms"] = int((time.time() - started) * 1000)
            record["error"] = type(error).__name__
            raise
        record["ms"] = int((time.time() - started) * 1000)
        record["http_status"] = getattr(response, "status_code", None)
        headers = getattr(response, "headers", None) or {}
        record["retry_after"] = headers.get("Retry-After") if hasattr(headers, "get") else None
        kind = headers.get("Content-Type") if hasattr(headers, "get") else None
        record["content_type"] = str(kind)[:60] if kind else None
        try:
            content = bytes(response.content)
            record["answer_bytes"] = len(content)
            head = content.lstrip()[:1]
            media = (record["content_type"] or "").split(";", 1)[0].strip().lower()
            if media in reputation.PROTOBUF_TYPES:
                record["starts_with"] = "binary data (not shown)"                 # the bytes of a binary answer are never printed
            else:
                record["starts_with"] = ("nothing (empty body)" if not content.strip() else
                                         {b"{": "an opening brace", b"[": "an opening bracket", b"<": "a markup tag"}.get(head, "a digit" if head.isdigit() else ("a letter" if head.isalpha() else "another character")))
        except Exception:
            pass
        media = (record["content_type"] or "").split(";", 1)[0].strip().lower()
        record["format"] = "Protobuf" if media in reputation.PROTOBUF_TYPES else ("JSON" if media == "application/json" or media.endswith("+json") else "other (%s)" % (media or "no content type"))
        if record["format"] == "JSON":
            try:
                body = response.json()
                record["json_kind"] = {dict: "object", list: "array", str: "string", int: "number", float: "number", bool: "boolean", type(None): "null"}.get(type(body), "other")
                if isinstance(body, dict):
                    record["answer_fields"] = sorted(str(k) for k in body.keys())[:12]
            except Exception:
                record["json_kind"] = "not JSON"
        return response

    def get(self, url, **kwargs):
        return self._do("get", url, **kwargs)

    def post(self, url, **kwargs):
        return self._do("post", url, **kwargs)


def valid_domain(text):
    text = (text or "").strip()
    if not text or "/" in text or ":" in text or "@" in text or not _HOSTNAME.match(text):
        raise Refused("'%s' is not a plain host name (no scheme, path, port or credentials)" % text[:80])
    return text.lower().rstrip(".")


def valid_url(text):
    text = (text or "").strip()
    if not re.match(r"^https?://[^/@\s]+(/[^?#\s]*)?([?#].*)?$", text):
        raise Refused("'%s' is not an http(s) address without credentials" % text[:80])
    return re.split(r"[?#]", text, 1)[0]                              # only host and path are ever used: the query and fragment are dropped here


def build_checks(args):
    """[(provider, kind, label, argument)] in the order they will run; kind is 'domain' or 'url'."""
    providers = {"all": ["google", "otx", "urlscan"]}.get(args.provider, [args.provider])
    domains = [valid_domain(d) for d in (args.domain or [])]
    urls = [valid_url(u) for u in (args.url or [])]
    if args.vector and "google" not in providers:
        raise Refused("--vector is Google's documented test page (use a known-clean --domain for the other sources)")
    if urls and "google" not in providers:
        raise Refused("--url is for Google only: the other sources are asked for the host name alone")
    if not domains and not urls and not args.vector:
        domains = [DEFAULT_DOMAIN]
    checks = []
    for provider in providers:
        for domain in domains:
            checks.append((provider, "domain", domain, domain))
        if provider == "google":
            for address in urls:
                checks.append((provider, "url", address, address))
            if args.vector:
                checks.append((provider, "url", "documented test vector", VECTOR_URL))
    if len(checks) > MAX_LOOKUPS:
        raise Refused("at most %d lookups per run (this run would make %d)" % (MAX_LOOKUPS, len(checks)))
    return checks


def describe(provider, kind, argument, env):
    """What a lookup would send, as lines of text. Nothing here touches the network."""
    key_name = CREDENTIALS[provider]
    present = bool(env.get(key_name, "").strip()) or provider in OPTIONAL_KEY
    lines = []
    if provider == "google":
        expressions = safebrowsing.url_expressions(argument) if kind == "url" else safebrowsing.host_level_expressions(argument)
        prefixes = sorted(set(safebrowsing.prefix_b64(e) for e in expressions))
        lines.append("GET %s  (key from %s: %s)" % (reputation.GoogleSafeBrowsingProvider.url, key_name, "set" if present else "NOT SET"))
        lines.append("sends %d hash prefix(es) of 4 bytes: %s - never the name or the address" % (len(prefixes), ", ".join(prefixes)))
        lines.append("scope: %s" % ("this address only (path prefixes included)" if kind == "url" else "the whole host (root path only)"))
    elif provider == "otx":
        lines.append("GET %s  (X-OTX-API-KEY from %s: %s)" % (reputation.OtxProvider.url.format(domain=argument), key_name, "set" if env.get(key_name, "").strip() else "NOT SET"))
        lines.append("sends only the host name %s (in the address) and the key; the answer lists community pulses that mention it" % argument)
        lines.append("scope: the whole host")
    else:
        keyed = bool(env.get(key_name, "").strip())
        lines.append("GET %s  (api-key from %s: %s)" % (reputation.UrlscanProvider.url, key_name, "set" if keyed else "not set - optional, smaller quotas"))
        lines.append("sends a search for EXISTING scans: page.domain:\"%s\" (with a key whose plan allows it, a second one adds AND verdicts.malicious:true); nothing is submitted for scanning" % argument)
        lines.append("scope: the whole host")
    return lines, present


def provider_state(error=None, result=None):
    if error is not None:
        text = str(error).lower()
        if "429" in text or "rate limit" in text:
            return "RATE_LIMITED"
        return "ERROR" if getattr(error, "kind", None) == reputation.STATE_ERROR else "UNAVAILABLE"
    return "OK"


def _failure_outcome(report):
    state, error = report.get("state"), (report.get("error") or "").lower()
    if state == "NOT_CONFIGURED":
        return "NOT_CONFIGURED"
    if state == "RATE_LIMITED":
        return "RATE_LIMITED"
    if "rejected" in error or "key missing" in error:
        return "AUTHENTICATION_FAILURE"
    if "malformed" in error:
        return "MALFORMED_RESPONSE"
    return "UNAVAILABLE"


def otx_outcome(report):
    """What an OTX lookup found, in one word. Failures are never 'no records'."""
    if report.get("state") != "OK":
        return _failure_outcome(report)
    facts = report.get("facts") or {}
    if not facts.get("pulse_count"):
        return "NO_RECORDS"
    if report.get("level") == "CREDIBLE":
        return "CORROBORATED_RECENT_PULSES"
    return "CONTEXT_ONLY_PULSE_MENTIONS"


def urlscan_outcome(report):
    """What a urlscan.io lookup found, in one word. 'No scan' is a gap in coverage, never a clean result."""
    if report.get("state") != "OK":
        return _failure_outcome(report)
    facts = report.get("facts") or {}
    if not facts.get("total_scans"):
        return "NO_SCAN_AVAILABLE"
    if facts.get("malicious_scans") is None:
        return "SCANS_EXIST_VERDICTS_UNREADABLE"
    if not facts.get("malicious_scans"):
        return "SCANS_EXIST_NONE_MALICIOUS"
    return "FRESH_MALICIOUS_SCAN" if report.get("level") == "CREDIBLE" else "STALE_MALICIOUS_SCANS"


def run_check(provider, kind, label, argument, env, session_factory):
    """Run one lookup with the real adapter. Returns the report (a dict of safe fields)."""
    key_name = CREDENTIALS[provider]
    secret = env.get(key_name, "").strip()
    report = {"provider": LABELS[provider], "input": label, "kind": kind, "state": None, "http_status": None, "duration_ms": None}
    if not secret and provider not in OPTIONAL_KEY:
        report["state"] = "NOT_CONFIGURED"
        report["note"] = "%s is not set in the environment: nothing was sent" % key_name
        return report
    session = RecordingSession(session_factory())
    adapter = {"google": reputation.GoogleSafeBrowsingProvider, "otx": reputation.OtxProvider, "urlscan": reputation.UrlscanProvider}[provider](secret, session=session)
    started = time.time()
    try:
        if provider == "google":
            result = adapter.lookup_url(argument) if kind == "url" else adapter.lookup(argument)
        else:
            result = adapter.lookup(argument)
        report["state"] = "OK"
    except reputation.ProviderError as error:
        result = None
        report["state"] = provider_state(error)
        report["error"] = str(error)
        report["retry_in_minutes"] = error.cooldown_minutes
    report["duration_ms"] = int((time.time() - started) * 1000)
    if session.records:
        last = session.records[-1]
        report.update(http_status=last["http_status"], answer_bytes=last["answer_bytes"], answer_fields=last["answer_fields"], retry_after_header=last["retry_after"],
                      content_type=last["content_type"], answer_starts_with=last["starts_with"], answer_json=last["json_kind"], response_format=last["format"])
        if last["error"]:
            report["network_error"] = last["error"]
    if result is not None:
        details = result.get("details") or {}
        report.update(
            verdict=result["status"], level=result.get("level"), alert_decision=result.get("alert_severity"), reason=result.get("reason"), scope=details.get("scope") or result.get("scope"),
            classification=details.get("classification"), strength=details.get("strength"), cache_seconds=result.get("cache_seconds"), evidence_kind=details.get("evidence_kind"),
            detections=details.get("detections"), list_based=bool(result.get("list_based")),
            facts=dict((k, details[k]) for k in ("url_count", "urls_seen", "online_urls", "offline_urls", "firstseen", "latest_url_added", "spamhaus_dbl", "surbl", "threat_types", "prefixes_sent",
                                                 "expressions_checked", "answer_entries", "cache_duration_given", "answer_format", "pulse_count", "recent_pulses", "recent_authors",
                                                 "attributed_recent", "whitelisted", "derived_from", "total_scans", "malicious_scans", "newest_malicious_age_days",
                                                 "newest_scan_age_days", "search_authenticated") if k in details))
        report["note"] = "a list-based source: 'no match' is not proof of safety" if result["status"] == "SAFE" else None
    if provider == "otx":
        report["outcome"] = otx_outcome(report)
    elif provider == "urlscan":
        report["outcome"] = urlscan_outcome(report)
    return report


def redact(text, env):
    for name in CREDENTIALS.values():
        secret = env.get(name, "").strip()
        if len(secret) >= 4:
            text = text.replace(secret, "<hidden>")
    return text


def main(argv=None, env=None, ask=None, session_factory=None, out=None, interactive=None):
    env = os.environ if env is None else env
    session_factory = session_factory or requests.Session
    emit_raw = out or print
    emit = lambda text="": emit_raw(redact(str(text), env))
    parser = argparse.ArgumentParser(prog="provider_check.py", description="Isolated diagnostic for Google Safe Browsing, AlienVault OTX and urlscan.io (dry run unless --live).")
    parser.add_argument("--provider", choices=("google", "otx", "urlscan", "all"), default="google", help="one source, or 'all' = google, otx, urlscan (default google)")
    parser.add_argument("--domain", action="append", help="host name to look up (repeatable); default example.com")
    parser.add_argument("--url", action="append", help="address for Google's path-level lookup (query and fragment are dropped)")
    parser.add_argument("--vector", action="store_true", help="Google's documented test page (never visited; only its hash prefix is sent)")
    parser.add_argument("--live", action="store_true", help="really send the requests (you are asked to type SEND first)")
    parser.add_argument("--json", action="store_true", help="print the reports as one JSON document")
    try:
        args = parser.parse_args(argv)
        checks = build_checks(args)
    except Refused as refusal:
        emit("REFUSED: %s" % refusal)
        return 2
    except SystemExit as exit_:
        return 2 if exit_.code else 0

    emit("Isolated provider diagnostic - no application, no database, nothing stored.")
    emit("Mode: %s" % ("LIVE (after confirmation)" if args.live else "DRY RUN (nothing is sent; add --live to send)"))
    planned = []
    for number, (provider, kind, label, argument) in enumerate(checks, 1):
        lines, present = describe(provider, kind, argument, env)
        emit("")
        emit("[%d] %s - %s '%s'" % (number, LABELS[provider], "address" if kind == "url" else "host", label))
        for line in lines:
            emit("    " + line)
        planned.append(present)

    if not args.live:
        emit("")
        emit("Nothing was sent. To send these requests: add --live (you will be asked to type SEND).")
        return 0 if all(planned) else 1
    sendable = [c for c, present in zip(checks, planned) if present]
    if not sendable:
        emit("")
        emit("REFUSED: no credential is set (%s), so there is nothing to send." % ", ".join(sorted(set(CREDENTIALS[c[0]] for c in checks))))
        return 2
    emit("")
    emit("LIVE: %d request(s) will be sent to: %s" % (len(sendable), ", ".join(sorted(set(HOSTS[c[0]] for c in sendable)))))
    if ask is None:
        if interactive is None:
            interactive = sys.stdin.isatty()
        if not interactive:
            emit("REFUSED: live requests need a person at the keyboard (type SEND at the prompt); this input is not interactive.")
            return 2
        ask = input
    if ask("Type SEND to make these requests, anything else to cancel: ").strip() != "SEND":
        emit("Cancelled: nothing was sent.")
        return 2

    reports = [run_check(provider, kind, label, argument, env, session_factory) for (provider, kind, label, argument) in checks]
    if args.json:
        emit(json.dumps(reports, indent=2, default=str))
    else:
        for number, r in enumerate(reports, 1):
            emit("")
            emit("[%d] %s - %s" % (number, r["provider"], r["input"]))
            emit("    provider state : %s" % r["state"])
            emit("    HTTP status    : %s    duration: %s ms" % (r.get("http_status"), r.get("duration_ms")))
            if r.get("outcome"):
                emit("    outcome        : %s" % r["outcome"])
            if r.get("error"):
                emit("    error          : %s (back off %s min)" % (r["error"], r.get("retry_in_minutes")))
            if r.get("network_error"):
                emit("    network error  : %s" % r["network_error"])
            if r.get("verdict"):
                emit("    verdict        : %s   level: %s   alert decision: %s   strength: %s" % (r["verdict"], r.get("level"), r.get("alert_decision"), r.get("strength")))
                emit("    scope          : %s   cache validity: %s s" % (r.get("scope"), r.get("cache_seconds")))
                emit("    reason         : %s" % r.get("reason"))
                if r.get("evidence_kind"):
                    emit("    evidence kind  : %s" % r["evidence_kind"])
                for d in r.get("detections") or []:
                    emit("    detection      : %s / %s / %s" % (d.get("engine"), d.get("category"), d.get("result")))
                if r.get("facts"):
                    emit("    facts          : %s" % json.dumps(r["facts"], sort_keys=True))
            if r.get("http_status") is not None:
                decoded = "succeeded" if r["state"] == "OK" else ("FAILED" if r.get("error", "").startswith("malformed") else "not reached")
                emit("    response format: %s    decoding: %s" % (r.get("response_format") or "?", decoded))
                shape = "%s bytes, %s, content type %s" % (r.get("answer_bytes"), r.get("answer_starts_with") or "?", r.get("content_type") or "none")
                if r.get("answer_json") == "not JSON":
                    shape += ", the body is not JSON"
                elif r.get("answer_json"):
                    shape += ", JSON %s with top-level fields %s" % (r.get("answer_json"), r.get("answer_fields"))
                emit("    answer shape   : %s" % shape)
            if r.get("note"):
                emit("    note           : %s" % r["note"])
    failed = [r for r in reports if r["state"] != "OK"]
    emit("")
    emit("%d lookup(s): %d answered, %d not." % (len(reports), len(reports) - len(failed), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
