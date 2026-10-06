# ==================================================
# THREAT INTEL -> RISK SCORING: CORROBORATION ENGINE (Oct 2026 request)
# ==================================================
#
# Approved policy (see the decision this module implements):
#   1. The EXISTING Risk Scoring mechanism and its VirusTotal/AbuseIPDB
#      compatibility are UNCHANGED. This module is an ADDITIONAL,
#      independent, additive contributor - never a replacement.
#   2. New (and existing) intelligence sources feed risk scoring with
#      weight for source reliability, finding severity/classification and
#      information freshness.
#   3. A corroboration mechanism counts how many INDEPENDENT sources
#      report a signal on the SAME event's candidate indicators.
#      "Independent" means distinct PROVIDERS (never the same provider's
#      report counted twice because it also matched a second indicator of
#      the same event - see summarize_signal_providers()).
#   4. A decisive, unambiguous finding from a trusted source may affect
#      the score even WITHOUT a second corroborating source, per the
#      provider_decisive() rule below (registry-driven, not ad hoc).
#   5. Only providers whose evidence_class is "malicious_evidence" (see
#      threat_intel_framework.PROVIDER_REGISTRY) are ever eligible to
#      contribute. "context_only" providers (Shodan, Censys, urlscan.io)
#      NEVER contribute to risk scoring, however they classify.
#   6. Missing data, NOT_CONFIGURED, NOT_SUPPORTED, ERROR and
#      RATE_LIMITED rows NEVER lower the score - they simply contribute 0
#      and are excluded from the signal set. A negative/no-match result
#      from one provider is never treated as proof the target is safe.
#   7. Every contribution carries a human-readable reason string, in the
#      same style as threat_intelligence.py's existing IOC-match reasons,
#      so an analyst can see exactly why a score was computed.
#   8. First stage: this module's output is a risk-score/reasons
#      contribution ONLY. It must not be used to drive automatic
#      block/isolate (response_commands) policy without separate,
#      explicit approval - no code here creates or touches any
#      response_commands/security_alerts/security_events row.
#
# This module is READ-ONLY with respect to threat_intel_evidence: it only
# ever reads rows already written by the existing provider adapters
# (get_all_provider_evidence_for_event_with_conn() et al. in
# threat_intel_framework.py). It performs no HTTP requests of its own and
# writes nothing. It is NOT YET wired into web_event_worker.py's actual
# Threat Risk calculation - that is a separate, explicit next step (see
# the project report), done only once the new provider adapters exist and
# a live dry run has shown it does not unexpectedly reclassify existing
# events (Decision point 9).
# ==================================================

from datetime import datetime

import threat_intel_framework as framework

# Reuses the EXACT same severity vocabulary/thresholds as the existing
# engine (threat_intelligence.severity_from_score) - this module produces
# points on the identical 0-100 scale, never a second parallel scale.
MAX_CONTRIBUTION_POINTS = 40  # same ceiling as a single IOC_SEVERITY_SCORE hit

# Freshness tiers (rule 2): a signal retrieved very recently is trusted at
# full weight; an older-but-still-unexpired cached signal is discounted a
# little, since the provider's own TTL (not this module) is what decides
# whether a row is usable/stale at all - this is an ADDITIONAL, gentler
# recency preference on top of that, not a second expiry mechanism.
_FRESH_FULL_WEIGHT_HOURS = 6
_FRESH_PARTIAL_WEIGHT_HOURS = 24
_FRESHNESS_FULL = 1.0
_FRESHNESS_PARTIAL = 0.85
_FRESHNESS_STALE = 0.7

# Corroboration base points by number of INDEPENDENT non-decisive signal
# providers (rule 3/4): one non-decisive signal alone is not enough to
# move the score (needs a second source); each additional independent
# signal adds confidence. These are reasoned defaults on the existing
# INFO/LOW/MEDIUM/HIGH point scale (threat_intelligence.IOC_SEVERITY_SCORE),
# not a measured statistic - documented here, reviewable, overridable.
_CORROBORATION_BASE_POINTS = {
    0: 0,
    1: 0,
    2: 15,   # two independent non-decisive signals: LOW-ish confirmation
    3: 25,   # three: closer to HIGH
}
_CORROBORATION_BASE_POINTS_MAX = 30  # 4+ independent signals: capped here


def _corroboration_base_points(signal_count):

    if signal_count in _CORROBORATION_BASE_POINTS:
        return _CORROBORATION_BASE_POINTS[signal_count]

    return _CORROBORATION_BASE_POINTS_MAX


# Fixed contribution for a single decisive signal (rule 4). Chosen to sit
# at the existing engine's own HIGH tier (IOC_SEVERITY_SCORE["HIGH"] == 30)
# - serious on its own, but does not alone reach CRITICAL (>=80 total) or
# even MEDIUM-plus-extra without some other factor also contributing,
# leaving room for genuinely corroborated or IOC-matched events to still
# rank higher.
_DECISIVE_BASE_POINTS = 30


def provider_evidence_class(provider):

    return (framework.PROVIDER_REGISTRY.get(provider) or {}).get("evidence_class", "context_only")


def provider_reliability_weight(provider):

    return float((framework.PROVIDER_REGISTRY.get(provider) or {}).get("reliability_weight", 0.0))


def provider_decisive(provider, indicator_type):

    # Registry-driven, per rule 4 and per the provider's own documented
    # decisive_indicator_types (e.g. URLhaus: payload/hash matches only,
    # not host "listed" matches - see the registry comments).
    decisive_types = (framework.PROVIDER_REGISTRY.get(provider) or {}).get("decisive_indicator_types", ())
    return indicator_type in decisive_types


def _parse_retrieved_at(value):

    if not value:
        return None

    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        return None


def freshness_factor(row, now=None):

    now = now or datetime.now()

    retrieved = _parse_retrieved_at(row.get("retrieved_at"))

    if retrieved is None:
        # Can't determine age - treat conservatively (not full weight, but
        # never excluded outright: an unparseable timestamp is an
        # infrastructure quirk, not evidence of anything).
        return _FRESHNESS_PARTIAL

    age_hours = (now - retrieved).total_seconds() / 3600.0

    if age_hours < 0:
        return _FRESHNESS_FULL  # clock skew guard - never penalize

    if age_hours <= _FRESH_FULL_WEIGHT_HOURS:
        return _FRESHNESS_FULL

    if age_hours <= _FRESH_PARTIAL_WEIGHT_HOURS:
        return _FRESHNESS_PARTIAL

    return _FRESHNESS_STALE


def eligible_malicious_signal(row):

    # A row is eligible to contribute to risk scoring only if ALL of:
    #  - its lookup_status is a real, persisted MATCH specifically - NOT
    #    merely "persistable" (NO_MATCH/ERROR/RATE_LIMITED are persistable
    #    too, but are never evidence of anything - rule 6). This mirrors
    #    the exact precondition framework.is_security_signal()'s own
    #    caller (summarize_provider_evidence) always applies before using
    #    it: that function is only ever meaningful for a MATCH row, and
    #    its fallthrough `return True` for providers with no special-cased
    #    stats logic (threatfox, urlhaus) is only safe under that
    #    precondition - WITHOUT it, a threatfox/urlhaus NO_MATCH row would
    #    be misread as a signal (caught by this module's own test suite
    #    and a live read-only dry run, which is exactly why that
    #    precondition is enforced explicitly here rather than assumed);
    #  - the provider's evidence_class is "malicious_evidence" (rule 5);
    #  - framework.is_security_signal(row) says this SPECIFIC MATCH is a
    #    real positive signal (reuses the exact same provider-specific,
    #    already-tested logic the existing corroboration-SUMMARY display
    #    uses - never a blanket "MATCH == malicious" assumption).
    if row.get("lookup_status") != framework.LOOKUP_STATUS_MATCH:
        return False

    if provider_evidence_class(row.get("provider")) != "malicious_evidence":
        return False

    return framework.is_security_signal(row)


def compute_threat_intel_contribution(evidence_rows, now=None, exclude_providers=None):

    # Pure, read-only, deterministic. `evidence_rows` is any list of real
    # threat_intel_evidence rows (dicts) for one event's candidate
    # indicators - e.g. framework.get_all_provider_evidence_for_event_with_
    # conn()'s output, or a direct DB read. Returns:
    #   {"points": int (0..MAX_CONTRIBUTION_POINTS),
    #    "signal_providers": sorted list of provider names that counted,
    #    "decisive": bool,
    #    "reasons": [str, ...]}
    # NEVER negative, NEVER raises, NEVER reads/writes anything itself.
    #
    # exclude_providers (Oct 2026, Step 5 pre-check fix): an optional set of
    # provider names to leave out of this computation entirely. This exists
    # specifically so a CALLER that is about to ADD this result on top of a
    # score that ALREADY incorporates certain providers' evidence (the
    # legacy engine's risk_score already fully incorporates VirusTotal and
    # AbuseIPDB - their threat_intel_evidence rows are a DERIVED TRANSCRIPT
    # of the exact same check, not a second opinion) can avoid counting
    # that same evidence twice. This function itself has no opinion on
    # which providers to exclude - the caller decides (see
    # threat_intel_shadow.py, which passes {"virustotal","abuseipdb"}).
    now = now or datetime.now()
    exclude_providers = exclude_providers or frozenset()

    decisive_hits = []    # (provider, indicator_type, weight, row)
    corroborating = {}    # provider -> best (weight, row) for that provider

    for row in evidence_rows:

        if row.get("provider") in exclude_providers:
            continue

        if not eligible_malicious_signal(row):
            continue

        provider = row.get("provider")
        indicator_type = row.get("indicator_type")
        weight = provider_reliability_weight(provider) * freshness_factor(row, now)

        if provider_decisive(provider, indicator_type):
            decisive_hits.append((provider, indicator_type, weight, row))

        existing = corroborating.get(provider)
        if existing is None or weight > existing[0]:
            corroborating[provider] = (weight, row)

    reasons = []
    points = 0
    decisive = False

    if decisive_hits:

        decisive = True
        # Most-reliable-weighted decisive hit sets the base; this avoids
        # double-escalating when the same event has several decisive hits.
        best_provider, best_type, best_weight, best_row = max(decisive_hits, key=lambda h: h[2])
        decisive_points = round(_DECISIVE_BASE_POINTS * min(best_weight, 1.0))
        points = max(points, decisive_points)

        classification = framework.classify_evidence(
            best_provider, best_row.get("lookup_status"), best_type, best_row.get("analysis_stats")
        )
        reasons.append(
            f"Decisive threat-intelligence match: {best_provider} classified this "
            f"{best_type} indicator as '{classification}' (no corroboration required; "
            f"source reliability {provider_reliability_weight(best_provider):.2f})."
        )

    signal_count = len(corroborating)

    if signal_count >= 2:

        avg_weight = sum(w for w, _ in corroborating.values()) / signal_count
        base = _corroboration_base_points(signal_count)
        corroboration_points = round(base * min(avg_weight, 1.0))

        if corroboration_points > points:
            points = corroboration_points

        provider_list = ", ".join(sorted(corroborating.keys()))
        reasons.append(
            f"Threat-intelligence corroboration: {signal_count} independent sources "
            f"({provider_list}) each reported a malicious-activity signal for this event."
        )

    elif signal_count == 1 and not decisive:

        provider_name = next(iter(corroborating))
        reasons.append(
            f"Threat-intelligence note: {provider_name} reported a malicious-activity "
            "signal, but this is a single, non-decisive source with no corroboration - "
            "not used to raise the risk score on its own."
        )

    points = max(0, min(points, MAX_CONTRIBUTION_POINTS))

    return {
        "points": points,
        "signal_providers": sorted(corroborating.keys()),
        "decisive": decisive,
        "reasons": reasons,
    }
