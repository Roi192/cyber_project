"""Domain reputation: check_domain(conn, domain) -> {"status", "source", "reason"}.

Statuses: SAFE, SUSPICIOUS, MALICIOUS, UNKNOWN.

Flow:  cache (domain_reputation table, not expired)  ->  provider  ->  cache
       provider missing / cooling down / failing     ->  UNKNOWN (never raises,
                                                          never SAFE on error)

Only one provider exists (VirusTotal, active only when VT_API_KEY is set).

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
from datetime import datetime, timedelta

import requests

import config

SAFE = "SAFE"
SUSPICIOUS = "SUSPICIOUS"
MALICIOUS = "MALICIOUS"
UNKNOWN = "UNKNOWN"
STATUSES = (SAFE, SUSPICIOUS, MALICIOUS, UNKNOWN)

TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
PROVIDER_TIMEOUT_SECONDS = 8

UNKNOWN_CACHE_MINUTES = 30
THREAT_CACHE_HOURS = 6

MALICIOUS_MIN_VENDORS = 3
SUSPICIOUS_MIN_SUSPICIOUS_VENDORS = 2

COOLDOWN_RATE_LIMIT_MINUTES = 15
COOLDOWN_AUTH_MINUTES = 60
COOLDOWN_ERROR_MINUTES = 5

# Provider status for the dashboard (ACTIVE / NOT_CONFIGURED / TEMPORARILY_UNAVAILABLE)
STATUS_ACTIVE = "ACTIVE"
STATUS_NOT_CONFIGURED = "NOT_CONFIGURED"
STATUS_UNAVAILABLE = "TEMPORARILY_UNAVAILABLE"

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
class ProviderError(Exception):
    """Raised by a provider for any non-verdict outcome; carries the cooldown."""

    def __init__(self, message, cooldown_minutes):
        Exception.__init__(self, message)
        self.cooldown_minutes = cooldown_minutes


class VirusTotalProvider(object):
    name = "VirusTotal"
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
        except requests.RequestException:
            raise ProviderError("connection error", COOLDOWN_ERROR_MINUTES)

        code = response.status_code
        if code == 404:
            return _result(UNKNOWN, self.name, "This website is not known to VirusTotal yet.")
        if code in (401, 403):
            raise ProviderError("HTTP %d (API key rejected)" % code, COOLDOWN_AUTH_MINUTES)
        if code == 429:
            raise ProviderError("HTTP 429 (rate limited)", COOLDOWN_RATE_LIMIT_MINUTES)
        if code >= 500:
            raise ProviderError("HTTP %d (provider error)" % code, COOLDOWN_ERROR_MINUTES)
        if code != 200:
            raise ProviderError("HTTP %d" % code, COOLDOWN_ERROR_MINUTES)

        try:
            stats = response.json()["data"]["attributes"]["last_analysis_stats"]
            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            engines = sum(int(stats.get(k, 0)) for k in ("harmless", "malicious", "suspicious", "undetected", "timeout"))
        except (ValueError, KeyError, TypeError, AttributeError):
            raise ProviderError("malformed response", COOLDOWN_ERROR_MINUTES)

        return interpret_stats(malicious, suspicious, engines, self.name)


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


def _record_failure(name, message, cooldown_minutes, now):
    entry = _entry(name)
    entry["unavailable_until"] = now + timedelta(minutes=cooldown_minutes)
    entry["last_error"] = message


def _record_success(name, now):
    entry = _entry(name)
    entry["unavailable_until"] = None
    entry["last_error"] = None
    entry["last_success_at"] = now


def reset_state():
    _state.clear()
    _provider_cache["key"] = None
    _provider_cache["provider"] = None


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
        "SELECT status, source, reason, expires_at FROM domain_reputation WHERE domain = ?", (domain,)
    ).fetchone()
    if row is None or row["expires_at"] < _now().strftime(TIME_FORMAT):
        return None
    return _result(row["status"], row["source"], row["reason"])


def ttl_for(status):
    if status == UNKNOWN:
        return timedelta(minutes=UNKNOWN_CACHE_MINUTES)
    if status in (SUSPICIOUS, MALICIOUS):
        return timedelta(hours=THREAT_CACHE_HOURS)
    return timedelta(hours=config.REPUTATION_CACHE_HOURS)


def store(conn, domain, result):
    now = _now()
    expires = now + ttl_for(result["status"])
    conn.execute(
        "INSERT INTO domain_reputation (domain, status, source, reason, checked_at, expires_at) "
        "VALUES (?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(domain) DO UPDATE SET status = excluded.status, source = excluded.source, "
        "reason = excluded.reason, checked_at = excluded.checked_at, expires_at = excluded.expires_at",
        (domain, result["status"], result["source"], result["reason"],
         now.strftime(TIME_FORMAT), expires.strftime(TIME_FORMAT)),
    )
    conn.commit()


# --------------------------------------------------------------------
# Public entry point
# --------------------------------------------------------------------
def check_domain(conn, domain, provider=None):
    """Cached verdict if fresh; otherwise ask the provider and cache.
    Never raises. Any provider problem -> UNKNOWN (never SAFE)."""
    cached = get_cached(conn, domain)
    if cached is not None:
        return cached

    now = _now()
    provider = provider if provider is not None else build_provider()
    if provider is None:
        result = _result(UNKNOWN, "none", "No reputation provider is configured.")
    elif _in_cooldown(provider.name, now):
        result = _result(UNKNOWN, provider.name, "Reputation service temporarily unavailable (%s)."
                         % _entry(provider.name)["last_error"])
    else:
        try:
            result = provider.lookup(domain)
            if not result or result.get("status") not in STATUSES:
                raise ProviderError("unexpected provider result", COOLDOWN_ERROR_MINUTES)
            _record_success(provider.name, now)
        except ProviderError as err:
            # HTTP-level failure the provider understood: back off (no rapid retries on 429/401).
            _record_failure(provider.name, str(err), err.cooldown_minutes, now)
            result = _result(UNKNOWN, provider.name, UNAVAILABLE_REASON_PREFIX + " (%s)." % err)
        except Exception:  # any other bug in a provider must never break ingestion
            result = _result(UNKNOWN, provider.name, UNAVAILABLE_REASON_PREFIX + ".")

    store(conn, domain, result)
    return result


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
