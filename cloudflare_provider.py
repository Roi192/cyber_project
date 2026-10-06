# ==================================================
# PHASE 12B.5B: CLOUDFLARE THREAT INTELLIGENCE (MANUAL, ON-DEMAND)
# ==================================================
#
# MANUAL / ON-DEMAND / CACHE-FIRST / QUOTA-FIRST / CONTEXT-ONLY.
#
#  * Only an explicit analyst/admin POST (see app.cloudflare_investigate)
#    may cause a live request. Nothing here runs on page load, from the
#    async worker, or from the event-analysis path. The registry marks
#    Cloudflare manual_only, and the worker structurally skips such
#    providers.
#  * Adds ZERO Threat Risk points and never touches severity,
#    Investigation Priority, Alerts, Incidents or Response Commands.
#  * Endpoints (Cloudflare Threat Intelligence, account-scoped):
#       GET /accounts/{account_id}/intel/ip?ipv4=<ip>
#       GET /accounts/{account_id}/intel/domain?domain=<domain>
#    Auth: Authorization: Bearer <API token> (Account > Intel > Read is
#    enough). The Account Settings API is NOT used or required: the
#    pre-flight proved GET /accounts/<id> can return 403 for this
#    least-privilege token while /intel/... succeeds.
#  * NOT implemented (out of scope): Domain History, Passive DNS, WHOIS,
#    URL/ASN Intelligence, Indicator Feeds, Sinkholes, Threat Events, Radar.
#
# REAL-PAYLOAD RULE (live pre-flight): a successful IP Intelligence answer
# returned risk_types as absent/null. Missing, null and [] are treated
# identically as "no direct threat category" - never as an error, and
# never worded safe/clean/benign.
#
# NEVER STORED: Cloudflare's numeric risk_score, popularity_rank, the raw
# response body, the token, or any header. Only bounded counts, bounded
# category names and short attributed prose are kept.
#
# --------------------------------------------------
# APPLICATION BUDGET (not Cloudflare's own quota)
# --------------------------------------------------
# CLOUDFLARE_TI_MONTHLY_BUDGET (default 80 of the 100-call Free/Pro/
# Business quota) is enforced over a ROLLING 30 DAYS, because Cloudflare's
# reset boundary is undocumented (a rolling window can never over-spend
# under any reset alignment). It counts only requests that actually
# reached Cloudflare, recorded in threat_intel_call_log (provider=
# 'cloudflare'). The application cannot see calls made by Cloudflare's
# dashboard/Brand Protection/client-side products, so it reports
# "application budget X / N used" - never the account's remaining quota.
#
# LEDGER ACCOUNTING: cache hit, local rejection, not-configured, back-off
# and budget refusal -> NO row. A request that never reached Cloudflare
# (connect timeout, DNS, TLS, refused) -> NO row (no quota can have been
# spent) and nothing is cached, so it may be retried. Any HTTP response,
# and a READ timeout (the request was sent), -> one row, recorded AFTER the
# response so a request that never left the machine is never counted.
# ==================================================

import ipaddress
import json
import os
import re
import sqlite3
from datetime import datetime, timedelta

import requests

from dotenv import load_dotenv

import threat_intel_framework as framework

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))


PROVIDER_NAME = "cloudflare"

CF_BASE_URL = "https://api.cloudflare.com/client/v4"

CF_HTTP_TIMEOUT_SECONDS = 15

ACCOUNT_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")
TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_\-]{20,120}$")

DEFAULT_MONTHLY_BUDGET = 80
BUDGET_WINDOW_DAYS = 30

BACKOFF_STATE_KEY = "cloudflare_backoff_until"
DEFAULT_429_BACKOFF_SECONDS = 3600
MAX_RETRY_AFTER_SECONDS = 3600

INFLIGHT_KEY_PREFIX = "cloudflare_inflight:"
INFLIGHT_STALE_SECONDS = 60

_TS_FORMAT = "%Y-%m-%d %H:%M:%S"
_MAX_NAME = 64
_MAX_TAGS = 10
_MAX_SUMMARY = 600
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")

# Outcomes of manual_lookup() (all safe, fixed messages - provider bodies
# are never surfaced to the UI).
OUTCOME_LIVE = "LIVE"
OUTCOME_CACHE = "CACHE"
OUTCOME_NOT_ELIGIBLE = "NOT_ELIGIBLE"
OUTCOME_NOT_CONFIGURED = "NOT_CONFIGURED"
OUTCOME_BACKOFF = "BACKOFF"
OUTCOME_BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
OUTCOME_IN_PROGRESS = "IN_PROGRESS"
OUTCOME_UNREACHABLE = "UNREACHABLE"

OUTCOME_MESSAGES = {
    OUTCOME_LIVE: "Cloudflare lookup completed.",
    OUTCOME_CACHE: "Fresh Cloudflare evidence already exists - no new request was made.",
    OUTCOME_NOT_ELIGIBLE: "This indicator is not eligible for an external Cloudflare lookup.",
    OUTCOME_NOT_CONFIGURED: "Cloudflare is not configured.",
    OUTCOME_BACKOFF: "Cloudflare lookups are paused after a rate-limit response. Try again later.",
    OUTCOME_BUDGET_EXHAUSTED: "The application's Cloudflare budget is exhausted. No request was sent.",
    OUTCOME_IN_PROGRESS: "A Cloudflare lookup for this indicator is already in progress.",
    OUTCOME_UNREACHABLE: "Cloudflare could not be reached. No request was counted; try again.",
}


def _log_error(indicator_type, exc):

    framework.log_provider_lookup_error(PROVIDER_NAME, indicator_type, exc)


# --------------------------------------------------
# CONFIGURATION (values are never logged or rendered)
# --------------------------------------------------

def _token():
    return os.getenv("CLOUDFLARE_API_TOKEN", "").strip()


def _account_id():
    return os.getenv("CLOUDFLARE_ACCOUNT_ID", "").strip()


def is_configured():

    # BOTH the token and a well-formed Account ID are required. Account
    # Settings API access is deliberately NOT a prerequisite.
    return bool(TOKEN_PATTERN.match(_token())) and bool(ACCOUNT_ID_PATTERN.match(_account_id()))


def monthly_budget():

    try:
        value = int(os.getenv("CLOUDFLARE_TI_MONTHLY_BUDGET", "").strip())
    except ValueError:
        return DEFAULT_MONTHLY_BUDGET

    return value if value >= 1 else DEFAULT_MONTHLY_BUDGET


# --------------------------------------------------
# LEDGER / BACK-OFF / IN-FLIGHT CLAIM (non-secret, additive)
# --------------------------------------------------

def ensure_call_log_schema(conn):

    conn.execute("""
        CREATE TABLE IF NOT EXISTS threat_intel_call_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider TEXT NOT NULL,
            called_at TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_threat_intel_call_log_lookup
        ON threat_intel_call_log(provider, called_at)
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS threat_intel_worker_state (
            config_key TEXT PRIMARY KEY,
            config_value TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()


def record_live_call(conn, now=None):

    now = now or datetime.now()

    conn.execute(
        "INSERT INTO threat_intel_call_log (provider, called_at) VALUES (?, ?)",
        (PROVIDER_NAME, now.strftime(_TS_FORMAT))
    )
    conn.commit()


def used_in_window(conn, now=None):

    now = now or datetime.now()

    try:
        return conn.execute(
            "SELECT COUNT(*) FROM threat_intel_call_log WHERE provider = ? AND called_at >= ?",
            (PROVIDER_NAME, (now - timedelta(days=BUDGET_WINDOW_DAYS)).strftime(_TS_FORMAT))
        ).fetchone()[0]
    except sqlite3.OperationalError:
        return 0


def get_budget_state(conn, now=None):

    used = used_in_window(conn, now)
    budget = monthly_budget()

    return {"used": used, "budget": budget, "exhausted": used >= budget}


def _get_backoff_until(conn):

    try:
        row = conn.execute(
            "SELECT config_value FROM threat_intel_worker_state WHERE config_key = ?",
            (BACKOFF_STATE_KEY,)
        ).fetchone()
    except sqlite3.OperationalError:
        return None

    if row is None:
        return None

    try:
        return datetime.strptime(row[0], _TS_FORMAT)
    except (TypeError, ValueError):
        return None


def _set_backoff(conn, seconds, now=None):

    now = now or datetime.now()

    conn.execute("""
        INSERT INTO threat_intel_worker_state (config_key, config_value, created_at)
        VALUES (?, ?, ?)
        ON CONFLICT(config_key) DO UPDATE SET config_value = excluded.config_value
    """, (
        BACKOFF_STATE_KEY,
        (now + timedelta(seconds=seconds)).strftime(_TS_FORMAT),
        now.strftime(_TS_FORMAT)
    ))
    conn.commit()


def _retry_after_seconds(response):

    headers = getattr(response, "headers", None) or {}

    try:
        value = int(str(headers.get("retry-after", headers.get("Retry-After", ""))).strip())
    except ValueError:
        return DEFAULT_429_BACKOFF_SECONDS

    return value if 1 <= value <= MAX_RETRY_AFTER_SECONDS else DEFAULT_429_BACKOFF_SECONDS


def _claim(conn, key, now=None):

    # Atomic in-flight claim (double-click / concurrent-request guard):
    # succeeds only if no live claim exists. A claim older than
    # INFLIGHT_STALE_SECONDS is considered abandoned and may be taken over.
    now = now or datetime.now()
    stamp = now.strftime(_TS_FORMAT)
    stale = (now - timedelta(seconds=INFLIGHT_STALE_SECONDS)).strftime(_TS_FORMAT)

    cursor = conn.execute("""
        INSERT INTO threat_intel_worker_state (config_key, config_value, created_at)
        VALUES (?, ?, ?)
        ON CONFLICT(config_key) DO UPDATE SET config_value = excluded.config_value
        WHERE threat_intel_worker_state.config_value < ?
    """, (key, stamp, stamp, stale))
    conn.commit()

    return cursor.rowcount == 1


def _release(conn, key):

    # Narrow: removes only this indicator's own claim row.
    conn.execute("DELETE FROM threat_intel_worker_state WHERE config_key = ?", (key,))
    conn.commit()


# --------------------------------------------------
# ELIGIBILITY (reuses the hardened Phase 12B.2B guards)
# --------------------------------------------------

def is_eligible_indicator(indicator_type, indicator_value):

    # The exact value must already be in canonical normalized form and the
    # provider must support the type (IPv4 public IPs and strict public
    # domains only).
    if not isinstance(indicator_value, str):
        return False

    if not framework.provider_supports_indicator(PROVIDER_NAME, indicator_type, indicator_value):
        return False

    if indicator_type == "IP":
        if framework.normalize_ip_candidate(indicator_value) != indicator_value:
            return False
        # Quota is scarce: additionally never spend it on multicast /
        # reserved space, which the shared guard (is_global) can let through.
        ip_obj = ipaddress.ip_address(indicator_value)
        return not (ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified)

    if indicator_type == "DOMAIN":
        return framework.normalize_domain_candidate(indicator_value) == indicator_value

    return False


# --------------------------------------------------
# RESPONSE PARSING (null-safe: every optional structure may be missing,
# null or the wrong type)
# --------------------------------------------------

def _clean(value, limit=_MAX_NAME):

    if not isinstance(value, str):
        return None

    cleaned = _CONTROL_CHARS.sub(" ", value).strip()

    return cleaned[:limit] if cleaned else None


def _named_items(value):

    # risk_types / inherited_risk_types / content_categories: a list of
    # {"id", "name", "super_category_id"} objects. Anything that is not a
    # list (missing, null, a string, an object...) yields []. Only items
    # with a usable name count.
    if not isinstance(value, list):
        return []

    names = []

    for item in value:
        if isinstance(item, dict):
            name = _clean(item.get("name"))
            if name:
                names.append(name)

    return names


def _build_summary(direct, inherited, content_categories, network_context, family):

    if direct:
        head = "Cloudflare reports threat category information for this indicator: " + ", ".join(direct[:_MAX_TAGS]) + "."
    elif inherited:
        head = "Cloudflare returned inherited threat category information for this domain: " + ", ".join(inherited[:_MAX_TAGS]) + "."
    else:
        head = "Cloudflare returned intelligence for this indicator with no direct threat category in the current response."

    parts = [head]

    if network_context:
        parts.append("Network context: " + network_context + ".")

    if content_categories:
        parts.append("Content categories: " + ", ".join(content_categories[:_MAX_TAGS]) + ".")

    if family:
        parts.append("Suspected malware family (per Cloudflare): " + family + ".")

    return " ".join(parts)[:_MAX_SUMMARY]


def _match_result(direct, inherited, content, network_context, family):

    return {
        "lookup_status": "MATCH",
        "threat_type": None,
        "malware_family": family,
        "confidence_level": None,
        "tags": json.dumps(direct[:_MAX_TAGS]) if direct else None,
        "first_seen": None,
        "last_seen": None,
        "summary": _build_summary(direct, inherited, content, network_context, family),
        "analysis_stats": {
            "risk_types": len(direct),
            "inherited_risk_types": len(inherited),
            "content_categories": len(content),
        },
    }


def _first_object(result):

    # `result` may be a list of objects (IP) or an object (Domain).
    if isinstance(result, dict):
        return result if result else None

    if isinstance(result, list):
        for item in result:
            if isinstance(item, dict) and item:
                return item

    return None


def _is_empty_result(result):

    return result is None or result == [] or result == {}


def parse_ip_result(result):

    # Returns a normalized MATCH dict, a NO_MATCH dict (genuinely empty
    # result) or an ERROR dict (unusable shape).
    if _is_empty_result(result):
        return {"lookup_status": "NO_MATCH", "summary": "No Cloudflare intelligence was returned for this indicator.", "analysis_stats": None}

    item = _first_object(result)

    if item is None:
        return _error("Cloudflare returned an unexpected response.")

    direct = _named_items(item.get("risk_types"))       # missing / null / [] -> []

    belongs = item.get("belongs_to_ref")
    context = None
    if isinstance(belongs, dict):
        kind = _clean(belongs.get("type"), 40)
        country = _clean(belongs.get("country"), 40)
        context = ", ".join(x for x in (kind, country) if x) or None

    return _match_result(direct, [], [], context, None)


def parse_domain_result(result):

    if _is_empty_result(result):
        return {"lookup_status": "NO_MATCH", "summary": "No Cloudflare intelligence was returned for this indicator.", "analysis_stats": None}

    item = _first_object(result)

    if item is None:
        return _error("Cloudflare returned an unexpected response.")

    direct = _named_items(item.get("risk_types"))
    inherited = _named_items(item.get("inherited_risk_types"))
    content = _named_items(item.get("content_categories"))

    family = None
    extra = item.get("additional_information")
    if isinstance(extra, dict):
        family = _clean(extra.get("suspected_malware_family"), 120)

    # risk_score and popularity_rank are deliberately never read.
    return _match_result(direct, inherited, content, None, family)


def _error(summary):

    return {"lookup_status": "ERROR", "summary": summary, "analysis_stats": None}


# --------------------------------------------------
# LIVE CLIENT (called ONLY from manual_lookup)
# --------------------------------------------------

def query_cloudflare_live(indicator_type, indicator_value):

    # Returns (result_dict, reached_provider). reached_provider is True only
    # if the request actually reached Cloudflare (any HTTP response, or a
    # read timeout) - it decides whether a ledger row is written.
    if not is_eligible_indicator(indicator_type, indicator_value):
        return {"lookup_status": "NOT_SUPPORTED"}, False

    if not is_configured():
        return {"lookup_status": "NOT_CONFIGURED"}, False

    account_id = _account_id()

    if indicator_type == "IP":
        url = f"{CF_BASE_URL}/accounts/{account_id}/intel/ip"
        params = {"ipv4": indicator_value}
    else:
        url = f"{CF_BASE_URL}/accounts/{account_id}/intel/domain"
        params = {"domain": indicator_value}

    try:

        response = requests.get(
            url,
            headers={"Authorization": "Bearer " + _token(), "Accept": "application/json"},
            params=params,
            timeout=CF_HTTP_TIMEOUT_SECONDS
        )

    except requests.ConnectTimeout:
        return _error("Cloudflare connection timed out."), False

    except requests.Timeout:
        return _error("Cloudflare request timed out."), True

    except requests.RequestException:
        return _error("Cloudflare connection error."), False

    status = response.status_code

    if status == 429:
        result = {
            "lookup_status": "RATE_LIMITED",
            "summary": "Cloudflare rate limit or quota response received.",
            "analysis_stats": None,
            "retry_after_seconds": _retry_after_seconds(response),
        }
        return result, True

    if status in (401, 403):
        return _error(
            "Cloudflare rejected the request (authentication or API token "
            "permission). Check that the token has Account > Intel > Read."
        ), True

    if status != 200:
        return _error(f"Cloudflare returned HTTP {status}."), True

    try:
        body = response.json()
    except ValueError:
        return _error("Cloudflare returned invalid JSON."), True

    if not isinstance(body, dict) or body.get("success") is not True:
        return _error("Cloudflare returned an unexpected response."), True

    result = body.get("result")

    if indicator_type == "IP":
        return parse_ip_result(result), True

    return parse_domain_result(result), True


# --------------------------------------------------
# BUTTON STATE (read-only - never performs a request)
# --------------------------------------------------

def get_action_state(conn, indicator_type, indicator_value, budget_state=None, now=None):

    # For the UI. Pure DB reads; NEVER an HTTP request.
    if not is_eligible_indicator(indicator_type, indicator_value):
        return "NOT_ELIGIBLE"

    if framework.get_cached_evidence(
        conn, PROVIDER_NAME, indicator_type, indicator_value, count_as_lookup=False
    ) is not None:
        return "CACHED"

    if not is_configured():
        return "NOT_CONFIGURED"

    backoff = _get_backoff_until(conn)
    if backoff is not None and (now or datetime.now()) < backoff:
        return "BACKOFF"

    state = budget_state or get_budget_state(conn, now)
    if state["exhausted"]:
        return "BUDGET_EXHAUSTED"

    return "READY"


# --------------------------------------------------
# THE MANUAL LOOKUP (the only entry point that can cause a request)
# --------------------------------------------------

def manual_lookup(indicator_type, indicator_value, conn=None):

    # Order (as required): eligibility -> fresh cache -> configuration ->
    # back-off -> monthly application budget -> in-flight claim -> (re-check
    # cache/budget) -> ONE GET -> ledger (only if it reached Cloudflare) ->
    # persist normalized evidence. Returns {"outcome", "message",
    # "evidence", "budget"}; never raises to the caller.
    def result(outcome, evidence=None, budget=None):
        return {
            "outcome": outcome,
            "message": OUTCOME_MESSAGES[outcome],
            "evidence": evidence,
            "budget": budget,
        }

    if not is_eligible_indicator(indicator_type, indicator_value):
        return result(OUTCOME_NOT_ELIGIBLE)

    owns_conn = conn is None
    conn = conn or framework.get_db_connection()

    claim_key = f"{INFLIGHT_KEY_PREFIX}{indicator_type}:{indicator_value}"
    claimed = False

    try:

        framework.ensure_evidence_schema(conn)
        ensure_call_log_schema(conn)

        # 1. CACHE FIRST - before any configuration/quota check.
        cached = framework.get_cached_evidence(conn, PROVIDER_NAME, indicator_type, indicator_value)
        if cached is not None:
            return result(OUTCOME_CACHE, cached, get_budget_state(conn))

        # 2. configuration
        if not is_configured():
            return result(OUTCOME_NOT_CONFIGURED, None, get_budget_state(conn))

        # 3. back-off after a 429
        backoff = _get_backoff_until(conn)
        if backoff is not None and datetime.now() < backoff:
            return result(OUTCOME_BACKOFF, None, get_budget_state(conn))

        # 4. application budget (rolling 30 days)
        budget = get_budget_state(conn)
        if budget["exhausted"]:
            return result(OUTCOME_BUDGET_EXHAUSTED, None, budget)

        # 5. double-click / concurrency guard
        claimed = _claim(conn, claim_key)
        if not claimed:
            return result(OUTCOME_IN_PROGRESS, None, budget)

        # 6. re-check after the claim: a concurrent request may have just
        #    finished (its evidence is now fresh) or spent the last budget.
        cached = framework.get_cached_evidence(conn, PROVIDER_NAME, indicator_type, indicator_value)
        if cached is not None:
            return result(OUTCOME_CACHE, cached, get_budget_state(conn))

        budget = get_budget_state(conn)
        if budget["exhausted"]:
            return result(OUTCOME_BUDGET_EXHAUSTED, None, budget)

        # 7. the single provider request
        try:
            live_result, reached = query_cloudflare_live(indicator_type, indicator_value)
        except Exception as exc:
            _log_error(indicator_type, exc)
            live_result, reached = _error("Unexpected Cloudflare integration error."), False

        if live_result.get("lookup_status") not in framework.PERSISTABLE_LOOKUP_STATUSES:
            return result(OUTCOME_NOT_ELIGIBLE if live_result.get("lookup_status") == "NOT_SUPPORTED" else OUTCOME_NOT_CONFIGURED, None, budget)

        if not reached:
            # never left the machine / never reached Cloudflare: no ledger
            # row, nothing cached (may be retried immediately).
            return result(OUTCOME_UNREACHABLE, None, budget)

        # 8. it reached Cloudflare: count it, THEN persist.
        record_live_call(conn)

        if live_result["lookup_status"] == "RATE_LIMITED":
            _set_backoff(conn, live_result.get("retry_after_seconds", DEFAULT_429_BACKOFF_SECONDS))

        stored = framework.store_evidence(conn, PROVIDER_NAME, indicator_type, indicator_value, live_result)

        return result(OUTCOME_LIVE, stored, get_budget_state(conn))

    finally:
        if claimed:
            try:
                _release(conn, claim_key)
            except Exception as exc:
                _log_error(indicator_type, exc)
        if owns_conn:
            conn.close()
