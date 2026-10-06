# ==================================================
# PHASE 12B.1: MULTI-PROVIDER THREAT INTELLIGENCE FRAMEWORK
# ==================================================
#
# Provider-neutral foundation the ThreatFox adapter (threat_intel_providers.py)
# is built on top of. This module intentionally contains NO provider-specific
# HTTP logic - it only holds shared, reusable primitives:
#   - the lookup-status vocabulary (infrastructure state, never a verdict)
#   - the provider registry (metadata only - only "threatfox" is implemented)
#   - centralized indicator normalization (IPv4/IPv6/DOMAIN/SHA256/MD5)
#   - a centralized private/local-address eligibility guard
#   - a (provider, indicator_type, indicator_value)-parameterized cache layer
#     built on the EXISTING threat_intel_evidence table (no schema change)
#   - a provider-keyed TTL registry
#   - provider-routing / eligibility helpers (NOT_SUPPORTED / NOT_CONFIGURED)
#   - a pure, non-persisted classification helper
#   - a pure corroboration-summarization helper (descriptive counts only,
#     never a probability/percentage, never a Threat Risk contribution)
#   - a generalized safe-logging helper (provider-parameterized, secrets-free)
#
# As of Phase 12B.2, ThreatFox and URLhaus may actually execute a live
# lookup (via their own adapter modules: threat_intel_providers.py and
# urlhaus_provider.py). virustotal / abuseipdb / cloudflare exist ONLY as
# registry metadata (implemented=False) - no HTTP code, no fake results.
#
# This module never reads/writes web_events.risk_score/severity/decision,
# security_alerts, security_events, response_commands, or any Behavioral
# Baseline table - exactly like the provider adapters it supports.
# ==================================================

import bisect
import ipaddress
import json
import logging
import os
import re
import db_config
import sqlite3
from datetime import datetime, timedelta


# --------------------------------------------------
# LOOKUP STATUS (infrastructure/transport state - NEVER a security verdict)
# --------------------------------------------------
# NOT_CONFIGURED / NO_MATCH do NOT mean "safe".
# ERROR / RATE_LIMITED do NOT mean "malicious".

LOOKUP_STATUS_MATCH = "MATCH"
LOOKUP_STATUS_NO_MATCH = "NO_MATCH"
LOOKUP_STATUS_ERROR = "ERROR"
LOOKUP_STATUS_RATE_LIMITED = "RATE_LIMITED"
LOOKUP_STATUS_NOT_SUPPORTED = "NOT_SUPPORTED"
LOOKUP_STATUS_NOT_CONFIGURED = "NOT_CONFIGURED"

VALID_LOOKUP_STATUSES = {
    LOOKUP_STATUS_MATCH,
    LOOKUP_STATUS_NO_MATCH,
    LOOKUP_STATUS_ERROR,
    LOOKUP_STATUS_RATE_LIMITED,
    LOOKUP_STATUS_NOT_SUPPORTED,
    LOOKUP_STATUS_NOT_CONFIGURED,
}

# A lookup_status that reflects a REAL provider response being stored/cached
# (as opposed to a routing-level short-circuit before any provider call).
PERSISTABLE_LOOKUP_STATUSES = {
    LOOKUP_STATUS_MATCH,
    LOOKUP_STATUS_NO_MATCH,
    LOOKUP_STATUS_ERROR,
    LOOKUP_STATUS_RATE_LIMITED,
}

# --------------------------------------------------
# CONFIGURATION STATE (provider readiness - distinct concept from a single
# lookup's outcome). Reserved for future provider-management UI; only
# AVAILABLE / NOT_CONFIGURED are actually computed in this phase.
# --------------------------------------------------

CONFIG_STATE_AVAILABLE = "AVAILABLE"
CONFIG_STATE_NOT_CONFIGURED = "NOT_CONFIGURED"
CONFIG_STATE_AUTH_ERROR = "AUTH_ERROR"
CONFIG_STATE_RATE_LIMITED = "RATE_LIMITED"
CONFIG_STATE_DISABLED = "DISABLED"


# --------------------------------------------------
# PROVIDER REGISTRY (metadata only). As of Phase 12B.2, "threatfox" and
# "urlhaus" are implemented (real HTTP adapters exist: threat_intel_
# providers.py and urlhaus_provider.py). "virustotal"/"abuseipdb"/
# "cloudflare" remain NOT_IMPLEMENTED placeholders - no HTTP code exists
# for them anywhere. "virustotal"/"abuseipdb" here are DISTINCT from the
# legacy per-IP reputation engine in threat_intelligence.py/
# reputation_routes.py, which is untouched and keeps operating
# independently (never merged or rewritten by this framework).
# --------------------------------------------------

# --------------------------------------------------
# RISK-SCORING POLICY FIELDS (added for the limited, corroboration-based
# Risk Scoring integration - see threat_intel_risk.py). These are POLICY
# metadata only (never API specifics) and are purely ADDITIVE: no existing
# code reads them, so nothing here changes current behavior.
#   evidence_class:
#     "malicious_evidence" - this provider's MATCH/flagged-type
#       classification is itself a direct signal that the indicator was
#       observed doing something malicious (e.g. a confirmed C2 IOC, a
#       verified phishing URL). Eligible to contribute to risk scoring.
#     "context_only"       - this provider supplies technical/contextual
#       information (open ports, hosting/ASN data, scan metadata) that is
#       NEVER independent evidence of malicious activity on its own (per
#       the project's explicit instruction for Shodan/Censys, and applied
#       the same way to urlscan.io). Never contributes to risk scoring,
#       regardless of what it reports.
#   reliability_weight (0.0-1.0): how much ONE signal from this provider
#     should count toward a corroboration-weighted contribution. A
#     reasoned default, not a measured statistic - documented per
#     provider below and reviewable/overridable.
#   decisive_indicator_types: indicator types for which a MATCH from this
#     provider is unambiguous enough to contribute to risk scoring on its
#     own, without needing a second independent source (Decision, Oct
#     2026: "a decisive match from a trusted source may affect the risk
#     score even without corroboration"). Empty tuple = never decisive
#     alone - this provider only ever contributes as part of corroboration
#     with at least one other independent signal.
# --------------------------------------------------

PROVIDER_REGISTRY = {
    "threatfox": {
        "supported_indicator_types": ("IP", "DOMAIN", "SHA256"),
        "ip_versions": (4, 6),
        "automatic_eligible": True,
        "manual_eligible": True,
        "implemented": True,
        # Curated, actively-maintained community IOC feed; already the
        # most-trusted source in this system (Phase 11D.1/12B.1).
        "evidence_class": "malicious_evidence",
        "reliability_weight": 0.9,
        "decisive_indicator_types": ("IP", "DOMAIN", "SHA256"),
    },
    # Phase 12B.2B: URLhaus /host/ accepts an IPv4 address or a hostname
    # only - live-verified in Phase 12B.2A, it answers IPv6 with
    # query_status=invalid_host. IPv6 is therefore NOT a supported
    # indicator for URLhaus (decided here, at the capability layer, so no
    # HTTP request is ever made and no ERROR row/retry cycle is created).
    "urlhaus": {
        "supported_indicator_types": ("IP", "DOMAIN", "SHA256", "MD5"),
        "ip_versions": (4,),
        "automatic_eligible": True,
        "manual_eligible": True,
        "implemented": True,
        "evidence_class": "malicious_evidence",
        "reliability_weight": 0.85,
        # A payload/hash MATCH identifies one exact known-malware sample -
        # decisive alone. A HOST (IP/DOMAIN) MATCH only means "at least one
        # URL on this host was reported" (classify_evidence() already calls
        # this "listed", not "malicious" - shared/legitimate hosts can be
        # listed too) - NOT decisive alone, needs corroboration.
        "decisive_indicator_types": ("SHA256", "MD5"),
    },
    # Phase 12B.3: VirusTotal (API v3 report lookups only). Evidence is
    # context/corroboration ONLY. "live_lookup_types" are the indicator
    # types the async worker may fetch over HTTP; IP is deliberately NOT
    # one of them - IP evidence is derived from the result the legacy
    # reputation path (threat_intelligence.check_virustotal) already
    # fetched, so the same IP is never requested from VirusTotal twice.
    "virustotal": {
        "supported_indicator_types": ("IP", "DOMAIN", "SHA256", "MD5"),
        "live_lookup_types": ("DOMAIN", "SHA256", "MD5"),
        "ip_versions": (4, 6),
        "automatic_eligible": True,
        "manual_eligible": True,
        "implemented": True,
        "evidence_class": "malicious_evidence",
        # "flagged" already requires >=1 engine out of ~70+ to call it
        # malicious/suspicious - a single engine out of many is a weak
        # signal on its own (false positives happen), so never decisive
        # alone; a reasonable corroboration weight.
        "reliability_weight": 0.75,
        "decisive_indicator_types": (),
    },
    # Phase 12B.4: AbuseIPDB (public IP evidence only). Context/
    # corroboration ONLY. "live_lookup_types" is EMPTY on purpose: this
    # provider has NO HTTP client of its own - normalized evidence is
    # derived from the result the legacy reputation path
    # (threat_intelligence.check_abuseipdb) already fetched, so an IP is
    # never requested from AbuseIPDB twice. AbuseIPDB's v2 /check endpoint
    # accepts IPv4 and IPv6 (live-verified: real answers for both).
    "abuseipdb": {
        "supported_indicator_types": ("IP",),
        "live_lookup_types": (),
        "ip_versions": (4, 6),
        "automatic_eligible": True,
        "manual_eligible": True,
        "implemented": True,
        "evidence_class": "malicious_evidence",
        # "reported" already requires abuseConfidenceScore > 0; still
        # community-submitted and unverified, so weighted lower than
        # curated feeds and never decisive alone.
        "reliability_weight": 0.6,
        "decisive_indicator_types": (),
    },
    # Phase 12B.5B: Cloudflare Threat Intelligence (IP Overview + Domain
    # Details ONLY). MANUAL, ON-DEMAND, CACHE-FIRST, QUOTA-FIRST,
    # CONTEXT-ONLY. "manual_only" is a STRUCTURAL guarantee: the automatic
    # async worker skips any manual_only provider even if a developer
    # accidentally adds it to its provider list, and the provider is not
    # automatic_eligible. The monthly quota (100 calls on Free/Pro/
    # Business) is shared with Cloudflare's own dashboard features, so
    # automatic enrichment (600-1,400 distinct indicators/day locally) is
    # impossible. IPv4 only for now: the API documents an ipv6 parameter,
    # but it has not been verified against a real response, and an
    # unverified path must not spend scarce quota.
    "cloudflare": {
        "supported_indicator_types": ("IP", "DOMAIN"),
        "live_lookup_types": ("IP", "DOMAIN"),
        "ip_versions": (4,),
        "manual_only": True,
        "automatic_eligible": False,
        "manual_eligible": True,
        "implemented": True,
        "evidence_class": "malicious_evidence",
        # A DIRECT risk_types match (classify_evidence() -> "threat_
        # category_present") is a real Cloudflare-assigned threat category,
        # not inherited/content-category noise. Manual/on-demand only, so
        # it is weighted as solid corroboration but never decisive alone.
        "reliability_weight": 0.65,
        "decisive_indicator_types": (),
    },

    # --------------------------------------------------
    # NOT YET IMPLEMENTED (Oct 2026 request): registry/policy placeholders
    # only. No HTTP code exists for any of these - "implemented": False
    # means they are never dispatched by any routing helper above
    # (providers_for_indicator / resolve_provider_lookup_eligibility both
    # already gate on "implemented"). evidence_class/reliability_weight/
    # decisive_indicator_types are filled in now (policy decisions, not API
    # specifics) so the risk-scoring engine's rules can be written and
    # tested today; TTLs are deliberately NOT added here (see
    # PROVIDER_TTL_CONFIG's own comment) until each provider's real,
    # doc-verified cache-appropriate values are known at implementation
    # time. "requires_api_key" / signup info feeds the "services that still
    # need a key" report requested for project close-out.
    # --------------------------------------------------
    "alienvault_otx": {
        "supported_indicator_types": ("IP", "DOMAIN", "SHA256", "MD5"),
        "live_lookup_types": ("IP", "DOMAIN", "SHA256", "MD5"),
        "ip_versions": (4, 6),
        # Doc-verified (otx.alienvault.com/assets/static/external_api.html,
        # corroborated via search): general-indicator lookups work WITHOUT
        # an API key, at 1,000 requests/hour (shared, global) vs 10,000/
        # hour with a key. The adapter applies its own conservative
        # per-process guard well under that ceiling either way, so
        # automatic dispatch is reasonable even keyless.
        "automatic_eligible": True,
        "manual_eligible": True,
        "implemented": True,
        # Community-curated "Pulse" IOC matches - same family as ThreatFox/
        # URLhaus, but pulses vary widely in curation quality by author.
        "evidence_class": "malicious_evidence",
        "reliability_weight": 0.6,
        "decisive_indicator_types": (),
        "requires_api_key": False,  # works keyless; a key only raises the hourly ceiling
    },
    "greynoise": {
        "supported_indicator_types": ("IP",),
        "live_lookup_types": ("IP",),
        "ip_versions": (4,),
        # Doc-verified (docs.greynoise.io): keyless access is real but VERY
        # tight (10 lookups/day unauthenticated; 50 searches/week even with
        # a free Community key) - too tight for automatic per-event
        # dispatch, so this is manual/analyst-triggered only, protecting
        # the shared quota from being silently exhausted by routine
        # enrichment.
        "automatic_eligible": False,
        "manual_eligible": True,
        "implemented": True,
        # GreyNoise's own purpose is mostly to explain away internet
        # background noise (benign/common scanners) - its "benign"/
        # "unknown" classifications must NEVER lower risk (rule: missing/
        # negative info never reduces a score). Only its "malicious"
        # classification tag is evidence_class malicious_evidence.
        "evidence_class": "malicious_evidence",
        "reliability_weight": 0.5,
        "decisive_indicator_types": (),
        "requires_api_key": False,  # works keyless (10/day); a key raises it to 50/week
    },
    "google_safe_browsing": {
        "supported_indicator_types": ("URL",),
        "live_lookup_types": ("URL",),
        "ip_versions": (),
        # URL-only, and this project currently has NO automatic candidate-
        # indicator pipeline for URLs at all (only IP/DOMAIN/SHA256/MD5 are
        # derived from web_events - see all_candidate_indicators_for_event)
        # - so automatic dispatch could never fire regardless of this flag.
        # Set False for honesty; becomes usable once a manual URL-lookup UI
        # exists (planned for the Reputation page upgrade, not yet built).
        "automatic_eligible": False,
        "manual_eligible": True,
        "implemented": True,
        # A direct phishing/malware verdict from Google's own maintained
        # list - among the most authoritative, low-false-positive sources
        # available; an industry-standard safe-browsing signal.
        "evidence_class": "malicious_evidence",
        "reliability_weight": 0.95,
        "decisive_indicator_types": ("URL",),
        "requires_api_key": True,
    },
    "phishtank": {
        "supported_indicator_types": ("URL",),
        "live_lookup_types": ("URL",),
        "ip_versions": (),
        # Same URL-pipeline limitation as Google Safe Browsing above, PLUS
        # a doc-confirmed but numerically-undocumented keyless rate limit
        # ("much more limited") - manual-only for both reasons.
        "automatic_eligible": False,
        "manual_eligible": True,
        "implemented": True,
        # Community-verified (voting) confirmed-phishing reports - solid
        # but can lag newly-registered phishing URLs.
        "evidence_class": "malicious_evidence",
        "reliability_weight": 0.7,
        "decisive_indicator_types": ("URL",),
        "requires_api_key": False,  # doc-confirmed optional; a key only raises the rate limit
    },
    "urlscan": {
        "supported_indicator_types": ("URL", "DOMAIN"),
        "live_lookup_types": ("URL", "DOMAIN"),
        "ip_versions": (),
        "automatic_eligible": False,  # never auto-submits a scan (ToS/privacy); search-only, manual
        "manual_eligible": True,
        "implemented": True,
        # Investigation/enrichment tool (scan results, redirects, resources,
        # a report link) - descriptive, never a verdict on its own.
        "evidence_class": "context_only",
        "reliability_weight": 0.0,
        "decisive_indicator_types": (),
        "requires_api_key": False,  # doc-confirmed: search works keyless at reduced quota
    },
    "ipqualityscore": {
        "supported_indicator_types": ("IP", "URL"),
        "live_lookup_types": ("IP",),  # URL support exists in the adapter but has no candidate pipeline yet
        "ip_versions": (4, 6),
        "automatic_eligible": True,
        "manual_eligible": True,
        "implemented": True,
        # A commercial fraud/risk score with proxy/VPN detection - useful
        # corroboration, but proxy/VPN usage alone is common and legitimate,
        # so never decisive alone.
        "evidence_class": "malicious_evidence",
        "reliability_weight": 0.55,
        "decisive_indicator_types": (),
        "requires_api_key": True,
    },
    "shodan": {
        "supported_indicator_types": ("IP",),
        "live_lookup_types": ("IP",),
        "ip_versions": (4, 6),
        "automatic_eligible": False,  # technical enrichment, not a verdict feed
        "manual_eligible": True,
        "implemented": True,
        # Explicit project instruction: an open port/exposed service is
        # NEVER independent evidence the server is malicious.
        "evidence_class": "context_only",
        "reliability_weight": 0.0,
        "decisive_indicator_types": (),
        "requires_api_key": True,
    },
    "censys": {
        "supported_indicator_types": ("IP",),
        "live_lookup_types": ("IP",),
        "ip_versions": (4, 6),
        "automatic_eligible": False,
        "manual_eligible": True,
        # LOWER CONFIDENCE (see censys_provider.py module header): Censys's
        # own primary docs could not be fetched directly at implementation
        # time (403/522) - this adapter is built from corroborated
        # secondary sources only. implemented=True so the registry/cache/
        # manual-lookup plumbing is exercised and testable, but the live
        # endpoint/response shape should be re-verified before relying on
        # real results.
        "implemented": True,
        "evidence_class": "context_only",
        "reliability_weight": 0.0,
        "decisive_indicator_types": (),
        "requires_api_key": True,
    },
}

# Env var name each provider's configuration presence is checked against.
# Only used by get_provider_configuration_state() below - never logged.
PROVIDER_ENV_KEY_NAMES = {
    "threatfox": "THREATFOX_API_KEY",
    "urlhaus": "URLHAUS_API_KEY",
    "virustotal": "VT_API_KEY",
    "abuseipdb": "ABUSEIPDB_API_KEY",
    "cloudflare": "CLOUDFLARE_API_TOKEN",
    "alienvault_otx": "OTX_API_KEY",
    "greynoise": "GREYNOISE_API_KEY",
    "google_safe_browsing": "GSB_API_KEY",
    "phishtank": "PHISHTANK_API_KEY",
    "urlscan": "URLSCAN_API_KEY",
    "ipqualityscore": "IPQS_API_KEY",
    "shodan": "SHODAN_API_KEY",
    "censys": "CENSYS_API_ID",
}

# Official signup/API-key page for every provider that needs one - used only
# to render the "still needs an API key" report at project close-out; never
# used in any request and never logged. PhishTank is listed even though it
# has a key-less public mode (requires_api_key above reflects that) because
# registering still raises its rate limit.
PROVIDER_SIGNUP_URLS = {
    "threatfox": "https://auth.abuse.ch/",
    "urlhaus": "https://auth.abuse.ch/",
    "virustotal": "https://www.virustotal.com/gui/my-apikey",
    "abuseipdb": "https://www.abuseipdb.com/account/api",
    "cloudflare": "https://dash.cloudflare.com/profile/api-tokens",
    "alienvault_otx": "https://otx.alienvault.com/api",
    "greynoise": "https://viz.greynoise.io/account/api-key",
    "google_safe_browsing": "https://developers.google.com/safe-browsing/v4/get-started",
    "phishtank": "https://phishtank.org/api_register.php",
    "urlscan": "https://urlscan.io/user/signup",
    "ipqualityscore": "https://www.ipqualityscore.com/create-account",
    "shodan": "https://account.shodan.io/register",
    "censys": "https://search.censys.io/register",
}


# Additional variables that must ALSO be present for a provider to count as
# configured (Phase 12B.5B: Cloudflare's Intel endpoints are account-scoped,
# so BOTH the API token and the Account ID are required). Presence only -
# values are never read into logs or the UI.
PROVIDER_EXTRA_REQUIRED_ENV = {
    "cloudflare": ("CLOUDFLARE_ACCOUNT_ID",),
    # Censys v2 authenticates with an API ID + API Secret pair (HTTP Basic),
    # same two-variable-required pattern as Cloudflare above.
    "censys": ("CENSYS_API_SECRET",),
}


def provider_is_manual_only(provider):

    # Structural flag: a manual_only provider is never fetched by any
    # automatic path (worker, page load, background job).
    return bool((PROVIDER_REGISTRY.get(provider) or {}).get("manual_only"))


def get_provider_configuration_state(provider):

    meta = PROVIDER_REGISTRY.get(provider)

    if meta is None or not meta.get("implemented"):
        # Not a real, implemented provider - nothing to configure.
        return CONFIG_STATE_NOT_CONFIGURED

    env_name = PROVIDER_ENV_KEY_NAMES.get(provider, "")
    value = os.getenv(env_name, "").strip() if env_name else ""

    if not value:
        return CONFIG_STATE_NOT_CONFIGURED

    for extra in PROVIDER_EXTRA_REQUIRED_ENV.get(provider, ()):
        if not os.getenv(extra, "").strip():
            return CONFIG_STATE_NOT_CONFIGURED

    return CONFIG_STATE_AVAILABLE


# --------------------------------------------------
# PROVIDER-KEYED TTL REGISTRY
# ThreatFox values are byte-equivalent to the original Phase 11D.1
# constants - this is the ONLY place they live now.
# --------------------------------------------------

PROVIDER_TTL_CONFIG = {
    "threatfox": {
        LOOKUP_STATUS_MATCH: timedelta(hours=24),
        LOOKUP_STATUS_NO_MATCH: timedelta(hours=12),
        LOOKUP_STATUS_ERROR: timedelta(minutes=15),
        LOOKUP_STATUS_RATE_LIMITED: timedelta(minutes=30),
    },
    # Phase 12B.2: URLhaus TTLs chosen independently, NOT copied from
    # ThreatFox, based on provider semantics:
    #   MATCH (12h, shorter than ThreatFox's 24h) - URLhaus host/payload
    #   records churn faster than ThreatFox's botnet C2 IOC feed (URLs
    #   get taken down, url_count changes) so a match is refreshed sooner.
    #   NO_MATCH (6h, shorter than ThreatFox's 12h) - URLhaus ingests new
    #   URLs continuously throughout the day; a "clean" host/hash today
    #   can appear in the feed within hours, so a negative result should
    #   not be trusted as long as ThreatFox's slower-moving feed.
    #   ERROR (15min) / RATE_LIMITED (30min) - generic transient-failure
    #   retry cadence, not a provider-data-freshness judgment, so reusing
    #   the same operational backoff interval as ThreatFox here is a
    #   deliberate infra convention, not a copied data-freshness guess.
    "urlhaus": {
        LOOKUP_STATUS_MATCH: timedelta(hours=12),
        LOOKUP_STATUS_NO_MATCH: timedelta(hours=6),
        LOOKUP_STATUS_ERROR: timedelta(minutes=15),
        LOOKUP_STATUS_RATE_LIMITED: timedelta(minutes=30),
    },
    # Phase 12B.3: VirusTotal. Normalized-evidence TTLs only - entirely
    # separate from the legacy threat_reputation cache (60 minutes,
    # unchanged). RATE_LIMITED is 60 min (the Public API allows only
    # 4 requests/minute and 500/day), longer than the other providers.
    "virustotal": {
        LOOKUP_STATUS_MATCH: timedelta(hours=12),
        LOOKUP_STATUS_NO_MATCH: timedelta(hours=6),
        LOOKUP_STATUS_ERROR: timedelta(minutes=15),
        LOOKUP_STATUS_RATE_LIMITED: timedelta(minutes=60),
    },
    # Phase 12B.4: AbuseIPDB. Only MATCH is ever written (a real answer
    # for a public IP is always an object, even at score 0); the other
    # states are defined for framework completeness. 6h (not 12h): reports
    # accumulate continuously and the row is refreshed whenever the legacy
    # path (60-minute cache) looks the IP up again.
    "abuseipdb": {
        LOOKUP_STATUS_MATCH: timedelta(hours=6),
        LOOKUP_STATUS_NO_MATCH: timedelta(hours=6),
        LOOKUP_STATUS_ERROR: timedelta(minutes=15),
        LOOKUP_STATUS_RATE_LIMITED: timedelta(minutes=60),
    },
    # Phase 12B.5B: Cloudflare. The 7-day successful/empty TTLs are
    # APPLICATION QUOTA-CONSERVATION values, NOT claims about Cloudflare's
    # data freshness (Cloudflare documents none). Failures cache briefly so
    # a manual retry is possible but repeated clicking cannot burn quota;
    # RATE_LIMITED (a 429 or an exhausted account quota) waits an hour.
    "cloudflare": {
        LOOKUP_STATUS_MATCH: timedelta(days=7),
        LOOKUP_STATUS_NO_MATCH: timedelta(days=7),
        LOOKUP_STATUS_ERROR: timedelta(minutes=15),
        LOOKUP_STATUS_RATE_LIMITED: timedelta(minutes=60),
    },
    # Oct 2026 additions - reasoned, documented per provider (never a
    # blanket copy); see each adapter module's own TTL comment for the
    # provider-specific freshness reasoning.
    "alienvault_otx": {
        LOOKUP_STATUS_MATCH: timedelta(hours=12),
        LOOKUP_STATUS_NO_MATCH: timedelta(hours=6),
        LOOKUP_STATUS_ERROR: timedelta(minutes=15),
        LOOKUP_STATUS_RATE_LIMITED: timedelta(minutes=30),
    },
    "greynoise": {
        LOOKUP_STATUS_MATCH: timedelta(hours=12),
        LOOKUP_STATUS_NO_MATCH: timedelta(hours=24),
        LOOKUP_STATUS_ERROR: timedelta(minutes=15),
        LOOKUP_STATUS_RATE_LIMITED: timedelta(minutes=60),  # very tight quota - back off longer
    },
    "google_safe_browsing": {
        LOOKUP_STATUS_MATCH: timedelta(hours=1),
        LOOKUP_STATUS_NO_MATCH: timedelta(minutes=30),
        LOOKUP_STATUS_ERROR: timedelta(minutes=15),
        LOOKUP_STATUS_RATE_LIMITED: timedelta(minutes=30),
    },
    "phishtank": {
        LOOKUP_STATUS_MATCH: timedelta(hours=12),
        LOOKUP_STATUS_NO_MATCH: timedelta(hours=6),
        LOOKUP_STATUS_ERROR: timedelta(minutes=15),
        LOOKUP_STATUS_RATE_LIMITED: timedelta(minutes=60),  # undocumented keyless limit - back off longer
    },
    "urlscan": {
        LOOKUP_STATUS_MATCH: timedelta(hours=24),
        LOOKUP_STATUS_NO_MATCH: timedelta(hours=6),
        LOOKUP_STATUS_ERROR: timedelta(minutes=15),
        LOOKUP_STATUS_RATE_LIMITED: timedelta(minutes=30),
    },
    "ipqualityscore": {
        LOOKUP_STATUS_MATCH: timedelta(hours=6),
        LOOKUP_STATUS_NO_MATCH: timedelta(hours=6),
        LOOKUP_STATUS_ERROR: timedelta(minutes=15),
        LOOKUP_STATUS_RATE_LIMITED: timedelta(minutes=60),
    },
    "shodan": {
        LOOKUP_STATUS_MATCH: timedelta(hours=24),
        LOOKUP_STATUS_NO_MATCH: timedelta(hours=24),
        LOOKUP_STATUS_ERROR: timedelta(minutes=15),
        LOOKUP_STATUS_RATE_LIMITED: timedelta(minutes=30),
    },
    "censys": {
        LOOKUP_STATUS_MATCH: timedelta(hours=24),
        LOOKUP_STATUS_NO_MATCH: timedelta(hours=24),
        LOOKUP_STATUS_ERROR: timedelta(minutes=15),
        LOOKUP_STATUS_RATE_LIMITED: timedelta(minutes=30),
    },

    # Future providers: TTLs added only when that provider is actually
    # implemented, using its own real documented values - never guessed.
}

# Safety-net only (never used by ThreatFox - it always has a full,
# explicit entry above). Applied only if some future provider is wired
# in without a TTL entry, so a lookup can never cache forever by accident.
_FALLBACK_TTL = timedelta(minutes=15)


def get_ttl(provider, lookup_status):

    provider_ttls = PROVIDER_TTL_CONFIG.get(provider, {})
    return provider_ttls.get(lookup_status, _FALLBACK_TTL)


# --------------------------------------------------
# PROVIDER ROUTING / ELIGIBILITY
# --------------------------------------------------

def provider_supports_indicator(provider, indicator_type, indicator_value=None):

    # Capability check that is provider-specific and, when a value is
    # supplied, value-aware: for IP indicators the address family must be
    # one the provider accepts (registry "ip_versions"). Pure - no I/O.
    meta = PROVIDER_REGISTRY.get(provider)

    if meta is None or not meta.get("implemented"):
        return False

    if indicator_type not in meta.get("supported_indicator_types", ()):
        return False

    if indicator_type == "IP" and indicator_value is not None:

        try:
            version = ipaddress.ip_address(indicator_value).version
        except ValueError:
            return False

        if version not in meta.get("ip_versions", (4, 6)):
            return False

    return True


def provider_live_lookup_allowed(provider, indicator_type):

    # Whether the async worker may make an HTTP request for this type.
    # Defaults to every supported type; a provider narrows it with
    # "live_lookup_types" (VirusTotal: IP evidence is derived, not fetched).
    meta = PROVIDER_REGISTRY.get(provider) or {}
    allowed = meta.get("live_lookup_types", meta.get("supported_indicator_types", ()))
    return indicator_type in allowed


def providers_for_indicator(indicator_type, mode="automatic", indicator_value=None):

    eligible = []

    for name, meta in PROVIDER_REGISTRY.items():

        if not meta.get("implemented"):
            continue

        if not provider_supports_indicator(name, indicator_type, indicator_value):
            continue

        if mode == "automatic" and not meta.get("automatic_eligible"):
            continue

        if mode == "manual" and not meta.get("manual_eligible"):
            continue

        eligible.append(name)

    return eligible


def resolve_provider_lookup_eligibility(provider, indicator_type, indicator_value=None):

    # Pure, read-only, no HTTP: can this (provider, indicator) ever be
    # queried right now? Returns ELIGIBLE / NOT_SUPPORTED / NOT_CONFIGURED.
    # Support (incl. IP family) is decided BEFORE anything else, so a
    # previously cached ERROR row for an unsupported indicator can never
    # cause - or even influence - a new dispatch.
    if not provider_supports_indicator(provider, indicator_type, indicator_value):
        return LOOKUP_STATUS_NOT_SUPPORTED

    # Oct 2026 Step 8 fix: a provider doc-confirmed to work WITHOUT an API
    # key (GreyNoise/PhishTank/urlscan.io/AlienVault OTX -
    # requires_api_key=False in PROVIDER_REGISTRY) must not be blocked here
    # just because no key env var happens to be set - that would silently
    # make every "automatic_eligible" keyless provider permanently
    # undispatchable by threat_intel_worker.py's own automatic cycle, while
    # still working from the UI's manual re-check (threat_intel_display.
    # force_recheck already carries this exact same exception - this makes
    # the automatic path consistent with it, not a new, separate rule).
    meta = PROVIDER_REGISTRY.get(provider) or {}
    requires_key = bool(meta.get("requires_api_key", True))

    if requires_key and get_provider_configuration_state(provider) == CONFIG_STATE_NOT_CONFIGURED:
        return LOOKUP_STATUS_NOT_CONFIGURED

    return "ELIGIBLE"


# --------------------------------------------------
# INDICATOR NORMALIZATION / VALIDATION (centralized)
# --------------------------------------------------

SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
MD5_PATTERN = re.compile(r"^[a-f0-9]{32}$")


def is_externally_eligible_ip(ip_str):

    # Centralized private/local-address guard: rejects private IPv4,
    # loopback, link-local, unspecified, multicast, private/local IPv6,
    # and localhost. Uses Python's ipaddress.is_global, which already
    # correctly excludes all of the above (verified empirically in
    # Phase 11D.1/11E-era testing) - never re-implemented ad hoc.
    if not ip_str:
        return False

    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    return bool(ip_obj.is_global)


def normalize_ip_candidate(resolved_ip):

    if not resolved_ip:
        return None

    try:
        ip_obj = ipaddress.ip_address(resolved_ip)
    except ValueError:
        return None

    if not ip_obj.is_global:
        return None

    return str(ip_obj)


# --------------------------------------------------
# DOMAIN PRIVACY / VALIDATION (Phase 12B.2B)
# Only a plausible, externally routable DNS name may become a DOMAIN
# candidate. This is a SYNTAX + NAMESPACE-PRIVACY check only: no DNS
# resolution, and deliberately NO allowlist of public TLDs (brittle and
# always stale) - only well-known private/special-use namespaces are
# denied.
# --------------------------------------------------

_MAX_DOMAIN_LENGTH = 253
_MAX_LABEL_LENGTH = 63

# One DNS label: ASCII letters/digits/hyphen, not starting or ending with
# a hyphen (rejects empty labels, underscores, whitespace, non-ASCII).
# Internationalized names are accepted only in their ASCII punycode
# ("xn--") form.
_DNS_LABEL_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")

# Final-label (TLD) namespaces that can never be a public destination.
#  localhost / local   - RFC 6761 loopback name / RFC 6762 mDNS
#  internal            - ICANN-reserved private-use TLD
#  intranet, lan, home, corp, private, localdomain
#                      - de-facto private/internal namespaces (never
#                        delegated; ICANN name-collision risk) - these
#                        would leak internal host naming
#  test, example, invalid - RFC 6761 reserved (never publicly resolvable;
#                        note "example.com" is unaffected - only the
#                        "example" TLD itself is reserved)
#  onion               - RFC 7686 Tor name, not DNS-resolvable
_BLOCKED_TLDS = frozenset({
    "localhost", "local", "internal", "intranet", "lan", "home", "corp",
    "private", "localdomain", "test", "example", "invalid", "onion",
})

# Multi-label special-use suffixes:
#  home.arpa           - RFC 8375 home-network namespace
#  in-addr.arpa / ip6.arpa - reverse-DNS names: an IP in disguise, never
#                        a destination hostname
_BLOCKED_SUFFIXES = ("home.arpa", "in-addr.arpa", "ip6.arpa")


def normalize_domain_candidate(domain):

    if not domain or not isinstance(domain, str):
        return None

    # Any whitespace (leading, trailing or embedded) marks a malformed
    # value - rejected, never silently repaired.
    if any(ch.isspace() for ch in domain):
        return None

    candidate = domain.lower()

    # A single optional trailing DNS root dot is normalized away.
    if candidate.endswith("."):
        candidate = candidate[:-1]

    if not candidate or len(candidate) > _MAX_DOMAIN_LENGTH:
        return None

    # An IP-shaped value must never become a DOMAIN candidate (Phase
    # 11D.1 fix, preserved exactly). web_monitoring.normalize_destination()
    # sometimes sets web_events.domain equal to web_events.resolved_ip.
    try:
        ipaddress.ip_address(candidate)
        return None
    except ValueError:
        pass

    labels = candidate.split(".")

    # Single-label hostnames (printer, dc01, intranet) are internal.
    if len(labels) < 2:
        return None

    for label in labels:
        if len(label) > _MAX_LABEL_LENGTH or not _DNS_LABEL_PATTERN.match(label):
            return None

    tld = labels[-1]

    # An all-numeric final label is never a valid TLD (also catches
    # malformed dotted-numeric strings such as "999.1.1.1").
    if tld.isdigit():
        return None

    if tld in _BLOCKED_TLDS:
        return None

    for suffix in _BLOCKED_SUFFIXES:
        if candidate == suffix or candidate.endswith("." + suffix):
            return None

    return candidate


_MAX_URL_LENGTH = 2048


def normalize_url_candidate(url):
    """
    Step 24B.1: validates (never transforms/redacts) a URL candidate for
    threat-intel lookups. Redaction (stripping query string/fragment)
    already happened upstream, at collection time (browser_events.py,
    enforced server-side independently of the extension - see Step
    24A.3), and is NOT this function's job to re-perform; this only
    rejects a value that is not even shape-valid as a URL candidate,
    matching every other normalize_*_candidate function's contract
    (validate and pass through, or return None - never repair).
    """

    if not url or not isinstance(url, str):
        return None

    if any(ch.isspace() for ch in url):
        return None

    if len(url) > _MAX_URL_LENGTH:
        return None

    if not (url.startswith("http://") or url.startswith("https://")):
        return None

    # Defense in depth - a query string or fragment should never reach
    # this point at all (enforced at write time), but a candidate
    # carrying one is refused here too rather than silently accepted.
    if "?" in url or "#" in url:
        return None

    return url


def normalize_sha256_candidate(sha256):

    if not sha256:
        return None

    candidate = sha256.strip().lower()

    if not SHA256_PATTERN.match(candidate):
        return None

    return candidate


def normalize_md5_candidate(md5):

    # Built for future-provider readiness (URLhaus/VirusTotal may use
    # MD5). Deliberately NOT wired into ThreatFox's own candidate
    # routing - ThreatFox stays SHA-256-only, matching its original
    # Phase 11D.1 design. providers_for_indicator("MD5") currently
    # returns [] since no implemented provider supports MD5 yet.
    if not md5:
        return None

    candidate = md5.strip().lower()

    if not MD5_PATTERN.match(candidate):
        return None

    return candidate


# --------------------------------------------------
# ADDITIVE SCHEMA (Phase 12B.3): analysis_stats
# VirusTotal's evidence classification ("flagged" vs "no_detection") and
# its corroboration signal depend on structured per-engine counts, which
# no existing column can hold without overloading its meaning. One
# nullable TEXT column (JSON) is added the project's usual way
# (PRAGMA table_info -> ALTER TABLE ADD COLUMN). Additive only: existing
# rows/providers are untouched and simply have NULL there.
# --------------------------------------------------

def ensure_evidence_schema(conn):

    columns = {row[1] for row in conn.execute("PRAGMA table_info(threat_intel_evidence)")}

    if columns and "analysis_stats" not in columns:
        conn.execute("ALTER TABLE threat_intel_evidence ADD COLUMN analysis_stats TEXT")
        conn.commit()


ANALYSIS_STAT_KEYS = ("malicious", "suspicious", "harmless", "undetected", "timeout")


def parse_analysis_stats(value):

    # Accepts the stored JSON string (or an already-decoded dict) and
    # returns a dict of non-negative ints for ANALYSIS_STAT_KEYS, or None
    # if absent/invalid. Never raises.
    if value is None:
        return None

    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (ValueError, TypeError):
            return None

    if not isinstance(value, dict):
        return None

    try:
        return {key: max(0, int(value.get(key) or 0)) for key in ANALYSIS_STAT_KEYS}
    except (TypeError, ValueError):
        return None


ABUSE_STAT_KEYS = ("abuse_confidence_score", "total_reports", "distinct_users")


def parse_abuse_stats(value):

    # AbuseIPDB's structured evidence lives in the same additive JSON
    # column as VirusTotal's counts (analysis_stats), keyed differently:
    #   {"abuse_confidence_score": 0-100, "total_reports": n,
    #    "distinct_users": n}
    # Returns a dict of ints (score clamped to 0-100) or None if absent/
    # invalid/missing the score. Never raises.
    if value is None:
        return None

    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (ValueError, TypeError):
            return None

    if not isinstance(value, dict) or "abuse_confidence_score" not in value:
        return None

    try:
        stats = {key: max(0, int(value.get(key) or 0)) for key in ABUSE_STAT_KEYS}
    except (TypeError, ValueError):
        return None

    stats["abuse_confidence_score"] = min(stats["abuse_confidence_score"], 100)

    return stats


CLOUDFLARE_STAT_KEYS = ("risk_types", "inherited_risk_types", "content_categories")


def parse_cloudflare_stats(value):

    # Cloudflare's structured evidence (bounded COUNTS only) lives in the
    # same additive JSON column as VirusTotal/AbuseIPDB's, keyed:
    #   {"risk_types": n, "inherited_risk_types": n, "content_categories": n}
    # Returns a dict of non-negative ints, or None if absent/invalid/missing
    # the "risk_types" key. Never raises. NOTE: a real Cloudflare IP answer
    # may omit or null risk_types - the PROVIDER normalizes that to 0 when
    # storing, so a stored MATCH always carries all three counts.
    if value is None:
        return None

    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (ValueError, TypeError):
            return None

    if not isinstance(value, dict) or "risk_types" not in value:
        return None

    try:
        return {key: max(0, int(value.get(key) or 0)) for key in CLOUDFLARE_STAT_KEYS}
    except (TypeError, ValueError):
        return None


IPQS_STAT_KEYS = ("fraud_score", "recent_abuse", "proxy_or_vpn_or_tor")


def parse_ipqs_stats(value):

    # IPQualityScore's structured evidence (Oct 2026) lives in the same
    # additive JSON column, keyed:
    #   {"fraud_score": 0-100, "recent_abuse": 0|1, "proxy_or_vpn_or_tor": 0|1}
    # Returns a dict of non-negative ints (fraud_score clamped to 0-100),
    # or None if absent/invalid/missing fraud_score. Never raises.
    if value is None:
        return None

    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (ValueError, TypeError):
            return None

    if not isinstance(value, dict) or "fraud_score" not in value:
        return None

    try:
        stats = {key: max(0, int(value.get(key) or 0)) for key in IPQS_STAT_KEYS}
    except (TypeError, ValueError):
        return None

    stats["fraud_score"] = min(stats["fraud_score"], 100)

    return stats


# --------------------------------------------------
# GENERALIZED CACHE LAYER
# Built on the EXISTING threat_intel_evidence table - no schema change.
# Parameterized by (provider, indicator_type, indicator_value), preserving
# negative/ERROR/RATE_LIMITED caching exactly as ThreatFox already does.
# --------------------------------------------------

def get_cached_evidence(conn, provider, indicator_type, indicator_value, count_as_lookup=True):

    # count_as_lookup=False is for PURE DISPLAY callers (e.g.
    # threat_intel_display.py rendering already-stored evidence on a
    # page a human happens to open) - those are not an orchestration
    # decision of "do we need a live call", so they must NEVER inflate
    # Stage 25D's cache_hits_today counter (which specifically means
    # "the orchestration layer avoided a live call because of a fresh
    # cache entry"). Every real provider adapter's get_X_evidence()
    # (the actual cache-vs-live decision point) keeps the default True.
    row = conn.execute("""
        SELECT * FROM threat_intel_evidence
        WHERE provider = ? AND indicator_type = ? AND indicator_value = ?
    """, (provider, indicator_type, indicator_value)).fetchone()

    if row is None:
        return None

    expires_at = datetime.strptime(row["expires_at"], "%Y-%m-%d %H:%M:%S")

    if datetime.now() < expires_at:
        result = dict(row)
        result["source"] = "CACHE"

        # Stage 25D: central cache-hit counter (section 5) - every
        # provider module's real cache-vs-live decision routes through
        # this exact function, so this is the single choke point for
        # "served from cache, no live call needed" across all 11
        # providers. A counter failure must never break the real
        # lookup it is only observing.
        if count_as_lookup:
            try:
                import provider_health
                provider_health.record_cache_hit(provider)
            except Exception:
                pass

        return result

    return None


def store_evidence(conn, provider, indicator_type, indicator_value, live_result, now=None):

    # live_result: dict with at least "lookup_status", optionally
    # threat_type/malware_family/confidence_level/tags/first_seen/
    # last_seen/summary - the exact same shape ThreatFox's
    # query_threatfox_live() already returns. Upserts into the
    # unmodified threat_intel_evidence table and returns the stored row.
    now = now or datetime.now()

    lookup_status = live_result.get("lookup_status", LOOKUP_STATUS_ERROR)

    retrieved_at = now.strftime("%Y-%m-%d %H:%M:%S")
    expires_at_str = (now + get_ttl(provider, lookup_status)).strftime("%Y-%m-%d %H:%M:%S")

    if "analysis_stats" in live_result:

        # Extended path (VirusTotal): also writes/resets analysis_stats.
        # Results without that key (ThreatFox, URLhaus) take the original
        # statement below, byte-for-byte unchanged.
        ensure_evidence_schema(conn)

        stats = live_result.get("analysis_stats")
        stats_json = json.dumps(stats) if isinstance(stats, dict) else None

        conn.execute("""
            INSERT INTO threat_intel_evidence (
                provider, indicator_type, indicator_value, lookup_status,
                threat_type, malware_family, confidence_level, tags,
                first_seen, last_seen, summary, retrieved_at, expires_at,
                analysis_stats
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(provider, indicator_type, indicator_value) DO UPDATE SET
                lookup_status = excluded.lookup_status,
                threat_type = excluded.threat_type,
                malware_family = excluded.malware_family,
                confidence_level = excluded.confidence_level,
                tags = excluded.tags,
                first_seen = excluded.first_seen,
                last_seen = excluded.last_seen,
                summary = excluded.summary,
                retrieved_at = excluded.retrieved_at,
                expires_at = excluded.expires_at,
                analysis_stats = excluded.analysis_stats
        """, (
            provider, indicator_type, indicator_value, lookup_status,
            live_result.get("threat_type"), live_result.get("malware_family"),
            live_result.get("confidence_level"), live_result.get("tags"),
            live_result.get("first_seen"), live_result.get("last_seen"),
            live_result.get("summary"), retrieved_at, expires_at_str,
            stats_json
        ))

    else:

        conn.execute("""
            INSERT INTO threat_intel_evidence (
                provider, indicator_type, indicator_value, lookup_status,
                threat_type, malware_family, confidence_level, tags,
                first_seen, last_seen, summary, retrieved_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(provider, indicator_type, indicator_value) DO UPDATE SET
                lookup_status = excluded.lookup_status,
                threat_type = excluded.threat_type,
                malware_family = excluded.malware_family,
                confidence_level = excluded.confidence_level,
                tags = excluded.tags,
                first_seen = excluded.first_seen,
                last_seen = excluded.last_seen,
                summary = excluded.summary,
                retrieved_at = excluded.retrieved_at,
                expires_at = excluded.expires_at
        """, (
            provider, indicator_type, indicator_value, lookup_status,
            live_result.get("threat_type"), live_result.get("malware_family"),
            live_result.get("confidence_level"), live_result.get("tags"),
            live_result.get("first_seen"), live_result.get("last_seen"),
            live_result.get("summary"), retrieved_at, expires_at_str
        ))


    conn.commit()

    # Stage 25D: central "a live call was attempted" counter (section
    # 5) - store_evidence() is only ever called after an actual live
    # fetch attempt (whatever its outcome: MATCH/NO_MATCH/ERROR/
    # RATE_LIMITED), so this is the single choke point for
    # requests_today across all 11 providers. A counter failure must
    # never break the real lookup it is only observing.
    try:
        import provider_health
        provider_health.record_request(provider)
    except Exception:
        pass

    result = conn.execute("""
        SELECT * FROM threat_intel_evidence
        WHERE provider = ? AND indicator_type = ? AND indicator_value = ?
    """, (provider, indicator_type, indicator_value)).fetchone()

    result = dict(result)
    result["source"] = "LIVE"
    return result


# --------------------------------------------------
# CLASSIFICATION (pure, derived, NEVER persisted - satisfies the
# "raw_signal_summary/classification" normalized fields without any
# threat_intel_evidence schema change: raw_signal_summary maps directly
# onto the existing "summary" column; classification is computed here).
# --------------------------------------------------

def classify_evidence(provider, lookup_status, indicator_type=None, analysis_stats=None, threat_type=None):

    # Provider-specific security-signal interpretation - deliberately NOT
    # a shared "MATCH == malicious" assumption for every future provider.
    # For Phase 12B.1 only ThreatFox is implemented, and its existing
    # semantics (a MATCH is a known-bad-IOC signal) are preserved exactly.
    if provider == "threatfox":
        if lookup_status == LOOKUP_STATUS_MATCH:
            return "malicious"
        if lookup_status == LOOKUP_STATUS_NO_MATCH:
            return "unknown"
        if lookup_status in (LOOKUP_STATUS_NOT_SUPPORTED, LOOKUP_STATUS_NOT_CONFIGURED):
            return lookup_status.lower()
        return "unavailable"  # ERROR / RATE_LIMITED

    if provider == "urlhaus":
        # Phase 12B.2B. A URLhaus MATCH means only "this indicator is
        # represented in URLhaus intelligence" - never "endpoint
        # infected", "the whole domain is malicious" or "this connection
        # is malicious".
        #  HOST match (IP / DOMAIN): URLhaus lists a host when at least
        #    one URL on it was reported. Shared, legitimate hosts (e.g.
        #    www.googleapis.com, which URLhaus lists for one historical
        #    abuse) get listed too, so the neutral word "listed" is used.
        #    This is also the conservative default when the indicator type
        #    is not supplied.
        #  PAYLOAD match (SHA256 / MD5): URLhaus keeps this database of
        #    malware samples it collected from distribution URLs. A hash
        #    identifies one exact file, so there is no shared-host
        #    ambiguity - the existing "malicious" wording is retained for
        #    payload matches (label only; it never becomes a score).
        if lookup_status == LOOKUP_STATUS_MATCH:
            if indicator_type in ("SHA256", "MD5"):
                return "malicious"
            return "listed"
        if lookup_status == LOOKUP_STATUS_NO_MATCH:
            return "unknown"
        if lookup_status in (LOOKUP_STATUS_NOT_SUPPORTED, LOOKUP_STATUS_NOT_CONFIGURED):
            return lookup_status.lower()
        return "unavailable"  # ERROR / RATE_LIMITED

    if provider == "virustotal":
        # Phase 12B.3. lookup_status only says whether the report lookup
        # worked; the classification describes what the returned report
        # says, and stays deliberately cautious:
        #   flagged      - report found AND >=1 engine malicious/suspicious
        #   no_detection - report found, 0 malicious and 0 suspicious in the
        #                  latest analysis. This is NOT "safe"/"clean"/
        #                  "benign": engines can miss things and analyses age.
        #   unknown      - VirusTotal has no report (404), or a report
        #                  without usable statistics
        # VirusTotal's own numeric "reputation" field is never used, and no
        # cross-provider score/percentage is ever derived from these counts.
        if lookup_status == LOOKUP_STATUS_MATCH:
            stats = parse_analysis_stats(analysis_stats)
            if stats is None:
                return "unknown"
            if stats["malicious"] > 0 or stats["suspicious"] > 0:
                return "flagged"
            return "no_detection"
        if lookup_status == LOOKUP_STATUS_NO_MATCH:
            return "unknown"
        if lookup_status in (LOOKUP_STATUS_NOT_SUPPORTED, LOOKUP_STATUS_NOT_CONFIGURED):
            return lookup_status.lower()
        return "unavailable"  # ERROR / RATE_LIMITED

    if provider == "abuseipdb":
        # Phase 12B.4. lookup_status only says a report was obtained; the
        # classification describes what the report says. AbuseIPDB's
        # abuseConfidenceScore is a 0-100 provider-defined weighting of
        # reports - NOT a probability of maliciousness - and a score of
        # 0 is NOT "safe". Live data shows score 0 frequently COEXISTS with
        # reports on record (92 of 583 real historical answers, e.g. score
        # 0 with 114 reports), so "score 0" cannot honestly be worded "no
        # reported abuse". Hence three MATCH classifications:
        #   reported              - abuseConfidenceScore > 0
        #   reports_zero_confidence - score 0 but totalReports > 0
        #   no_reported_abuse     - score 0 AND totalReports == 0
        #   unknown               - a MATCH without usable statistics
        # A failed lookup never becomes evidence at all (the legacy result
        # must prove availability) - "unavailable" is defined for ERROR/
        # RATE_LIMITED rows only for framework completeness.
        if lookup_status == LOOKUP_STATUS_MATCH:
            stats = parse_abuse_stats(analysis_stats)
            if stats is None:
                return "unknown"
            if stats["abuse_confidence_score"] > 0:
                return "reported"
            if stats["total_reports"] > 0:
                return "reports_zero_confidence"
            return "no_reported_abuse"
        if lookup_status == LOOKUP_STATUS_NO_MATCH:
            return "unknown"
        if lookup_status in (LOOKUP_STATUS_NOT_SUPPORTED, LOOKUP_STATUS_NOT_CONFIGURED):
            return lookup_status.lower()
        return "unavailable"  # ERROR / RATE_LIMITED

    if provider == "cloudflare":
        # Phase 12B.5B. lookup_status only says whether an answer was
        # obtained; the classification describes what it says, cautiously:
        #   threat_category_present   - >=1 DIRECT risk type on this indicator
        #   threat_category_inherited - none direct, but risk types inherited
        #                               from a parent domain (weaker
        #                               attribution - shared parents get
        #                               listed too, so it is descriptive
        #                               only and never a signal)
        #   no_threat_category        - an answer with no direct risk type
        #                               (risk_types missing, null OR empty are
        #                               equivalent). NOT "safe"/"clean".
        #   unknown                   - no result / no usable statistics
        # Network ownership, country, hosting type, content categories,
        # popularity and Cloudflare's own numeric risk score are never used.
        if lookup_status == LOOKUP_STATUS_MATCH:
            stats = parse_cloudflare_stats(analysis_stats)
            if stats is None:
                return "unknown"
            if stats["risk_types"] > 0:
                return "threat_category_present"
            if stats["inherited_risk_types"] > 0:
                return "threat_category_inherited"
            return "no_threat_category"
        if lookup_status == LOOKUP_STATUS_NO_MATCH:
            return "unknown"
        if lookup_status in (LOOKUP_STATUS_NOT_SUPPORTED, LOOKUP_STATUS_NOT_CONFIGURED):
            return lookup_status.lower()
        return "unavailable"  # ERROR / RATE_LIMITED

    if provider == "alienvault_otx":
        # Oct 2026. A pulse match means only "referenced by a community-
        # authored OTX Pulse" - curation quality varies widely by author,
        # hence the lower reliability_weight and never-decisive-alone
        # policy (see PROVIDER_REGISTRY), independent of this label.
        if lookup_status == LOOKUP_STATUS_MATCH:
            return "pulse_match"
        if lookup_status == LOOKUP_STATUS_NO_MATCH:
            return "unknown"
        if lookup_status in (LOOKUP_STATUS_NOT_SUPPORTED, LOOKUP_STATUS_NOT_CONFIGURED):
            return lookup_status.lower()
        return "unavailable"

    if provider == "greynoise":
        # Oct 2026. GreyNoise's OWN classification field (stored verbatim
        # in the "threat_type" column: "malicious"/"benign"/"unknown")
        # distinguishes malicious scanning activity from benign/common
        # business services (RIOT) and unclassified noise - only
        # "malicious" is ever treated as a signal (_is_security_signal
        # below). "benign"/"unknown" must NEVER lower risk and are NOT
        # "safe" - they simply are not evidence of maliciousness.
        if lookup_status == LOOKUP_STATUS_MATCH:
            return threat_type if threat_type in ("malicious", "benign", "unknown") else "unknown"
        if lookup_status == LOOKUP_STATUS_NO_MATCH:
            return "unknown"
        if lookup_status in (LOOKUP_STATUS_NOT_SUPPORTED, LOOKUP_STATUS_NOT_CONFIGURED):
            return lookup_status.lower()
        return "unavailable"

    if provider == "google_safe_browsing":
        # Oct 2026. A MATCH is always a real Google-confirmed threat-type
        # listing (the parser never returns MATCH for an empty result) -
        # among the most authoritative sources available, hence decisive-
        # eligible in the registry.
        if lookup_status == LOOKUP_STATUS_MATCH:
            return "verified_threat"
        if lookup_status == LOOKUP_STATUS_NO_MATCH:
            return "unknown"
        if lookup_status in (LOOKUP_STATUS_NOT_SUPPORTED, LOOKUP_STATUS_NOT_CONFIGURED):
            return lookup_status.lower()
        return "unavailable"

    if provider == "phishtank":
        # Oct 2026. Distinguishes a community-VERIFIED phishing URL (a
        # real signal, decisive-eligible) from a merely unverified
        # submission (NOT a signal - an unconfirmed report proves nothing
        # on its own). The adapter stores which case applies verbatim in
        # the "threat_type" column ("verified_phishing"/"unverified_report").
        if lookup_status == LOOKUP_STATUS_MATCH:
            return threat_type if threat_type in ("verified_phishing", "unverified_report") else "unknown"
        if lookup_status == LOOKUP_STATUS_NO_MATCH:
            return "unknown"
        if lookup_status in (LOOKUP_STATUS_NOT_SUPPORTED, LOOKUP_STATUS_NOT_CONFIGURED):
            return lookup_status.lower()
        return "unavailable"

    if provider == "ipqualityscore":
        # Oct 2026. "reported" requires recent_abuse OR a high fraud_score;
        # a bare proxy/vpn/tor flag alone ("flagged_anonymizer") is NOT a
        # signal - legitimate privacy-tool usage is extremely common and
        # must never be treated as malicious-activity evidence on its own.
        if lookup_status == LOOKUP_STATUS_MATCH:
            stats = parse_ipqs_stats(analysis_stats)
            if stats is None:
                return "unknown"
            if stats["recent_abuse"] or stats["fraud_score"] >= 85:
                return "reported"
            if stats["proxy_or_vpn_or_tor"]:
                return "flagged_anonymizer"
            return "no_reported_abuse"
        if lookup_status == LOOKUP_STATUS_NO_MATCH:
            return "unknown"
        if lookup_status in (LOOKUP_STATUS_NOT_SUPPORTED, LOOKUP_STATUS_NOT_CONFIGURED):
            return lookup_status.lower()
        return "unavailable"

    if provider in ("urlscan", "shodan", "censys"):
        # Oct 2026. All three are context_only (see PROVIDER_REGISTRY):
        # descriptive technical/investigation enrichment, NEVER
        # independent evidence of malicious activity, regardless of label.
        if lookup_status == LOOKUP_STATUS_MATCH:
            return "technical_context_found"
        if lookup_status == LOOKUP_STATUS_NO_MATCH:
            return "no_technical_context"
        if lookup_status in (LOOKUP_STATUS_NOT_SUPPORTED, LOOKUP_STATUS_NOT_CONFIGURED):
            return lookup_status.lower()
        return "unavailable"

    # No other provider is implemented yet - a future provider defines
    # its own rule here when it is actually built.
    return "unavailable"


# --------------------------------------------------
# CORROBORATION SUMMARIZATION (pure, descriptive counts only - never a
# probability/percentage, never a Threat Risk contribution). Operates on
# a list of already-fetched evidence rows (e.g. from
# get_stored_evidence_for_event) - may see 0 or 1 provider today, must
# work unmodified once more providers exist.
# --------------------------------------------------

def _is_security_signal(row):

    # Provider-specific (never a blanket MATCH == signal). ThreatFox and
    # URLhaus: a MATCH is a provider listing. VirusTotal: a returned
    # report counts only when at least one engine flagged it - a report
    # with 0 malicious / 0 suspicious, or a 404, is NOT a signal.
    if row.get("provider") == "virustotal":
        return classify_evidence(
            "virustotal", LOOKUP_STATUS_MATCH, row.get("indicator_type"),
            row.get("analysis_stats")
        ) == "flagged"

    # AbuseIPDB: a signal requires an abuse confidence score > 0. A
    # successful answer with score 0 - even one with reports on record
    # ("reports_zero_confidence") - is NOT a positive signal, mirroring the
    # legacy risk engine, which likewise ignores reports below 25.
    if row.get("provider") == "abuseipdb":
        return classify_evidence(
            "abuseipdb", LOOKUP_STATUS_MATCH, row.get("indicator_type"),
            row.get("analysis_stats")
        ) == "reported"

    # Cloudflare: a signal requires a DIRECT, non-empty risk_types list.
    # Missing/null/empty risk_types, inherited-only categories, content
    # categories and network context (ASN/country/hosting) are NOT signals.
    if row.get("provider") == "cloudflare":
        return classify_evidence(
            "cloudflare", LOOKUP_STATUS_MATCH, row.get("indicator_type"),
            row.get("analysis_stats")
        ) == "threat_category_present"

    # Oct 2026 additions.

    if row.get("provider") == "greynoise":
        # Only GreyNoise's own "malicious" classification counts - "benign"
        # (including RIOT-listed common business services) and "unknown"
        # are NOT signals and must never lower risk either.
        return classify_evidence(
            "greynoise", LOOKUP_STATUS_MATCH, row.get("indicator_type"),
            row.get("analysis_stats"), row.get("threat_type")
        ) == "malicious"

    if row.get("provider") == "phishtank":
        # Only a community-VERIFIED phishing URL counts - an unverified
        # submission is not treated as evidence of anything.
        return classify_evidence(
            "phishtank", LOOKUP_STATUS_MATCH, row.get("indicator_type"),
            row.get("analysis_stats"), row.get("threat_type")
        ) == "verified_phishing"

    if row.get("provider") == "ipqualityscore":
        # A signal requires recent_abuse or a high fraud_score; a bare
        # proxy/vpn/tor flag alone is NOT a signal (common, legitimate).
        return classify_evidence(
            "ipqualityscore", LOOKUP_STATUS_MATCH, row.get("indicator_type"),
            row.get("analysis_stats")
        ) == "reported"

    if row.get("provider") in ("urlscan", "shodan", "censys"):
        # context_only: never a security signal, regardless of findings.
        # (threat_intel_risk.py already excludes these providers upstream
        # via evidence_class before this function is even reached - this
        # branch is defense in depth / correctness for any other caller.)
        return False

    return True


def is_security_signal(row):

    # Public name for _is_security_signal, added for threat_intel_risk.py
    # (and any future caller) so it does not need to reach into a
    # single-underscore "private" name. Behavior is identical - this is a
    # thin wrapper, not a reimplementation.
    return _is_security_signal(row)


def summarize_provider_evidence(evidence_rows):

    configured_providers = set()
    responding_providers = set()
    security_signal_providers = set()
    no_match_providers = set()
    unavailable_providers = set()

    for row in evidence_rows:

        lookup_status = row.get("lookup_status")

        # A synthetic "no stored evidence yet" placeholder (used by
        # get_stored_evidence_for_event for un-queried candidates) is not
        # a real provider response - excluded from every count.
        if lookup_status not in PERSISTABLE_LOOKUP_STATUSES:
            continue

        provider = row.get("provider")
        configured_providers.add(provider)

        if lookup_status == LOOKUP_STATUS_MATCH:
            responding_providers.add(provider)
            if _is_security_signal(row):
                security_signal_providers.add(provider)
        elif lookup_status == LOOKUP_STATUS_NO_MATCH:
            responding_providers.add(provider)
            no_match_providers.add(provider)
        else:
            # ERROR / RATE_LIMITED
            unavailable_providers.add(provider)

    return {
        "configured_providers": len(configured_providers),
        "responding_providers": len(responding_providers),
        "security_signal_providers": len(security_signal_providers),
        "no_match_providers": len(no_match_providers),
        "unavailable_providers": len(unavailable_providers),
    }


# --------------------------------------------------
# SAFE LOGGING (generalized, provider-parameterized; extends the exact
# suppression behavior ThreatFox already relies on). Never logs API keys,
# Authorization/Auth-Key headers, full request headers, or response bodies
# - only provider name, indicator_type, and the exception's class name.
# --------------------------------------------------

_logger = logging.getLogger("threat_intel")

_LOG_SUPPRESS_SECONDS = 300
_last_logged_failure = {}


def log_provider_lookup_error(provider, indicator_type, exc):

    key = (provider, indicator_type, type(exc).__name__)

    now = datetime.now().timestamp()

    if now - _last_logged_failure.get(key, 0) < _LOG_SUPPRESS_SECONDS:
        return

    _last_logged_failure[key] = now

    _logger.warning(
        "THREAT_INTEL_LOOKUP_ERROR provider=%s indicator_type=%s "
        "exception_class=%s",
        provider,
        indicator_type,
        type(exc).__name__
    )


# --------------------------------------------------
# PHASE 12B.2: MULTI-PROVIDER READ HELPERS
# Generalized, registry-aware versions of ThreatFox's original
# candidate_indicators_for_event()/get_stored_evidence_for_event() -
# these span EVERY implemented+automatic-eligible provider for each
# candidate indicator type (now including MD5, which only URLhaus
# supports). Read-only: never performs a live lookup, never writes.
# Used by rendering code (Web Monitoring / Alert Details display) and by
# threat_intel_worker.py's freshness/claim check. Investigation Priority
# is DELIBERATELY NOT wired to these - it keeps using ThreatFox's own
# get_stored_evidence_for_event() from threat_intel_providers.py,
# unchanged, per the Phase 12B.2 instruction not to touch
# compute_investigation_priority() or its ThreatFox-only input.
# --------------------------------------------------

_soc_db_path_override = os.getenv("SOC_DB_PATH", "").strip()

if _soc_db_path_override:
    if os.path.isabs(_soc_db_path_override):
        _DB_NAME = _soc_db_path_override
    else:
        _DB_NAME = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            _soc_db_path_override
        )
else:
    _DB_NAME = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cybersec.db")


def get_db_connection():

    # Phase 12B.6C.1: central policy (WAL, busy timeout, synchronous=FULL,
    # tracked so a request/iteration can always release it).
    return db_config.open_connection(_DB_NAME)


def all_candidate_indicators_for_event(resolved_ip, domain, sha256, md5, url=None):

    # Step 24B.1: `url` is a NEW, trailing, OPTIONAL parameter - every
    # existing call site (there are several across this project) keeps
    # working completely unchanged, since omitting it is identical to
    # passing url=None, which contributes no candidate at all (matching
    # the existing behavior of every other None-valued field above).
    candidates = []

    normalized_ip = normalize_ip_candidate(resolved_ip)
    if normalized_ip:
        candidates.append(("IP", normalized_ip))

    normalized_domain = normalize_domain_candidate(domain)
    if normalized_domain:
        candidates.append(("DOMAIN", normalized_domain))

    normalized_sha256 = normalize_sha256_candidate(sha256)
    if normalized_sha256:
        candidates.append(("SHA256", normalized_sha256))

    normalized_md5 = normalize_md5_candidate(md5)
    if normalized_md5:
        candidates.append(("MD5", normalized_md5))

    normalized_url = normalize_url_candidate(url)
    if normalized_url:
        candidates.append(("URL", normalized_url))

    return candidates


def get_all_provider_evidence_for_event_with_conn(conn, resolved_ip, domain, sha256, md5):

    # For every candidate indicator, for every implemented+automatic-
    # eligible provider that supports that indicator type, return the
    # stored evidence row if one exists, else an honest
    # NO_STORED_EVIDENCE placeholder for that specific (provider,
    # indicator) pair - never fabricated as NO_MATCH. This is what
    # powers the combined Provider|Indicator|Status|... display table.
    evidence = []

    for indicator_type, indicator_value in all_candidate_indicators_for_event(
        resolved_ip, domain, sha256, md5
    ):

        automatic_providers = providers_for_indicator(indicator_type, mode="automatic", indicator_value=indicator_value)

        # Phase 12B.5B: MANUAL-ONLY providers (Cloudflare) are listed only
        # when an analyst has already looked the indicator up and evidence
        # is stored - never as a "No stored evidence yet / enrichment may
        # not have run" placeholder (nothing will ever enrich them
        # automatically), and displaying them never causes a lookup.
        for provider in providers_for_indicator(indicator_type, mode="manual", indicator_value=indicator_value):

            if provider in automatic_providers:
                continue

            manual_row = conn.execute("""
                SELECT * FROM threat_intel_evidence
                WHERE provider = ? AND indicator_type = ? AND indicator_value = ?
            """, (provider, indicator_type, indicator_value)).fetchone()

            if manual_row is not None:
                manual_dict = dict(manual_row)
                manual_dict["classification"] = classify_evidence(
                    provider, manual_dict.get("lookup_status"), indicator_type,
                    manual_dict.get("analysis_stats"), manual_dict.get("threat_type")
                )
                evidence.append(manual_dict)

        for provider in automatic_providers:

            row = conn.execute("""
                SELECT * FROM threat_intel_evidence
                WHERE provider = ? AND indicator_type = ? AND indicator_value = ?
            """, (provider, indicator_type, indicator_value)).fetchone()

            if row is not None:
                row_dict = dict(row)
                row_dict["classification"] = classify_evidence(
                    provider, row_dict.get("lookup_status"), indicator_type,
                    row_dict.get("analysis_stats"), row_dict.get("threat_type")
                )
                evidence.append(row_dict)
            else:
                # Distinguish "genuinely never looked up yet" from
                # "this provider is not configured/not supported for
                # this indicator type" (section 23) - the latter is
                # discoverable without a stored row via the same
                # eligibility check the worker itself uses, so a
                # NOT_CONFIGURED provider never gets mislabeled as
                # "pending enrichment".
                eligibility = resolve_provider_lookup_eligibility(provider, indicator_type, indicator_value)
                placeholder_status = eligibility if eligibility != "ELIGIBLE" else "NO_STORED_EVIDENCE"
                evidence.append({
                    "provider": provider,
                    "indicator_type": indicator_type,
                    "indicator_value": indicator_value,
                    "lookup_status": placeholder_status,
                    "classification": placeholder_status.lower()
                })

    return evidence


def get_all_provider_evidence_for_event(resolved_ip, domain, sha256, md5):

    conn = get_db_connection()

    try:
        return get_all_provider_evidence_for_event_with_conn(
            conn, resolved_ip, domain, sha256, md5
        )
    finally:
        conn.close()


# ==================================================
# OCT 2026 STEP 15: SHARED, IMPORT-SAFE MIRROR OF threat_intel_worker.py's
# OWN "RECENT ENRICHMENT WINDOW" BOUNDING LOGIC
# ==================================================
#
# threat_intel_worker.py's find_enrichment_work() only ever offers work
# for an indicator belonging to one of the most recent ENRICHMENT_
# BATCH_EVENT_LIMIT endpoint-agent events at/after the stored
# activation_cutoff (see its own _recent_candidate_events()). A display
# helper that wants to honestly say "this WILL be picked up soon" (not
# just "eligible by static criteria") needs the SAME bounding check -
# but threat_intel_worker.py itself cannot safely be imported from
# inside the live Flask process (it registers SIGINT/SIGTERM handlers at
# module level, meant for its own standalone process - a real side
# effect to avoid taking on). This is the single source of truth for
# that bounding logic instead; threat_intel_worker.py's own
# BATCH_EVENT_LIMIT is a separate constant kept equal to this one by
# design (cross-checked directly, in an isolated subprocess that CAN
# safely import both modules, by test_threat_intel_step15_status_
# precision.py's own mirror test) rather than merged into one import,
# to avoid adding threat_intel_framework.py as a new dependency of
# threat_intel_worker.py's own module-load order.
ENRICHMENT_BATCH_EVENT_LIMIT = 300


def get_enrichment_activation_cutoff(conn):

    row = conn.execute("""
        SELECT config_value FROM threat_intel_worker_state
        WHERE config_key = 'activation_cutoff'
    """).fetchone()

    return row["config_value"] if row is not None else None


def build_enrichment_window_snapshot(conn):
    """
    Step 24A.4 Task 1 (display-layer-only optimization): a batch-computed,
    read-only snapshot of exactly the data is_event_within_enrichment_
    window() would otherwise re-query from scratch on EVERY SINGLE CALL.
    Profiling the Web Monitoring page (160k-row isolated DB) found this
    one function responsible for ~90% of page render time - ~2 calls per
    displayed event, each re-running a COUNT(*) JOIN query that is
    IDENTICAL across every call within one page load (the WHERE clause
    depends only on `cutoff`, a value that cannot change mid-request).

    Computing the qualifying event_time list ONCE per page load (one
    query) and reusing it via is_event_within_enrichment_window(...,
    snapshot=...) for every displayed event turns ~100 SQL round-trips
    into exactly 1, with a provably IDENTICAL per-event answer (see
    test_enrichment_window_equivalence_step24a4.py) - this changes
    nothing about WHAT is reported, worker dispatch, risk scoring, or
    any analysis/alert/response logic; it is purely a read-query
    restructuring local to this display helper.

    Returns {"cutoff": str_or_None, "times": sorted_list_of_str}. Pass
    the result to is_event_within_enrichment_window()'s `snapshot`
    parameter; omitting it preserves the exact original per-call
    behavior (always correct, just one query per call) for any other
    caller.
    """
    try:
        cutoff = get_enrichment_activation_cutoff(conn)
    except sqlite3.OperationalError:
        return {"cutoff": None, "times": []}

    if cutoff is None:
        return {"cutoff": None, "times": []}

    rows = conn.execute("""
        SELECT web_events.event_time AS t
        FROM web_events
        JOIN endpoints ON endpoints.ip_address = web_events.endpoint_ip
        WHERE endpoints.source = 'endpoint-agent'
          AND web_events.source = 'endpoint-agent'
          AND web_events.analysis_status = 'ANALYZED'
          AND web_events.event_time >= ?
        ORDER BY t
    """, (cutoff,)).fetchall()

    return {"cutoff": cutoff, "times": [row["t"] for row in rows]}


def is_event_within_enrichment_window(conn, event_time, snapshot=None):

    # Read-only; never performs a live call; never writes anything.
    # Returns False (the honest, non-overpromising answer) whenever this
    # cannot be positively confirmed - including when the
    # threat_intel_worker_state table does not exist yet at all (the
    # Threat Intel Worker has never started), which a bare SELECT would
    # otherwise raise on.
    #
    # `snapshot` (from build_enrichment_window_snapshot(), Step 24A.4):
    # when given, answers from the precomputed data below instead of
    # issuing a fresh COUNT(*) query - the exact same comparison, just
    # fed from a batch read. Omit it to keep the original, always-fresh,
    # one-query-per-call behavior unchanged.
    if snapshot is not None:

        cutoff = snapshot["cutoff"]

        if cutoff is None or not event_time or event_time < cutoff:
            return False

        times = snapshot["times"]
        # times is sorted ascending and every entry already satisfies
        # event_time >= cutoff (enforced at snapshot build time) - the
        # count of entries strictly greater than this event's own time
        # is exactly what the original query's "AND event_time > ?"
        # computed, restricted to the same >= cutoff population.
        newer_count = len(times) - bisect.bisect_right(times, event_time)

        return newer_count < ENRICHMENT_BATCH_EVENT_LIMIT

    try:
        cutoff = get_enrichment_activation_cutoff(conn)
    except sqlite3.OperationalError:
        return False

    if cutoff is None or not event_time or event_time < cutoff:
        return False

    newer_count = conn.execute("""
        SELECT COUNT(*) AS c
        FROM web_events
        JOIN endpoints ON endpoints.ip_address = web_events.endpoint_ip
        WHERE endpoints.source = 'endpoint-agent'
          AND web_events.source = 'endpoint-agent'
          AND web_events.analysis_status = 'ANALYZED'
          AND web_events.event_time >= ?
          AND web_events.event_time > ?
    """, (cutoff, event_time)).fetchone()["c"]

    return newer_count < ENRICHMENT_BATCH_EVENT_LIMIT
