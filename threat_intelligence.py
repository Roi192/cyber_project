import os
import ipaddress
import requests

from urllib.parse import urlparse

from dotenv import load_dotenv


load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))


VT_API_KEY = os.getenv(
    "VT_API_KEY",
    ""
).strip()

ABUSEIPDB_API_KEY = os.getenv(
    "ABUSEIPDB_API_KEY",
    ""
).strip()


# ==================================================
# IP VALIDATION
# ==================================================

def validate_public_ip(ip_address):

    try:

        ip = ipaddress.ip_address(
            ip_address
        )

    except ValueError:

        return {
            "valid": False,
            "public": False,
            "error": "Invalid IP address."
        }

    if not ip.is_global:

        return {
            "valid": True,
            "public": False,
            "error": (
                "External reputation checks are only "
                "available for public IP addresses."
            )
        }

    return {
        "valid": True,
        "public": True,
        "error": None
    }


# ==================================================
# VIRUSTOTAL
# ==================================================

def check_virustotal(ip_address):

    result = {
        "source": "VirusTotal",
        "available": False,
        "configured": bool(VT_API_KEY),
        "error": None,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "timeout": 0
    }

    if not VT_API_KEY:

        result["error"] = (
            "VirusTotal API key is not configured."
        )

        return result

    validation = validate_public_ip(
        ip_address
    )

    if not validation["public"]:

        result["error"] = validation["error"]

        return result

    url = (
        "https://www.virustotal.com/"
        "api/v3/ip_addresses/"
        f"{ip_address}"
    )

    headers = {
        "x-apikey": VT_API_KEY
    }

    try:

        response = requests.get(
            url,
            headers=headers,
            timeout=10
        )

        if response.status_code == 401:

            result["error"] = (
                "VirusTotal authentication failed."
            )

            return result

        if response.status_code == 403:

            result["error"] = (
                "VirusTotal request was denied."
            )

            return result

        if response.status_code == 429:

            result["error"] = (
                "VirusTotal rate limit reached."
            )

            return result

        if response.status_code != 200:

            result["error"] = (
                "VirusTotal returned "
                f"HTTP {response.status_code}."
            )

            return result

        payload = response.json()

        attributes = (
            payload
            .get("data", {})
            .get("attributes", {})
        )

        stats = attributes.get(
            "last_analysis_stats",
            {}
        )

        result["available"] = True

        result["malicious"] = int(
            stats.get(
                "malicious",
                0
            ) or 0
        )

        result["suspicious"] = int(
            stats.get(
                "suspicious",
                0
            ) or 0
        )

        result["harmless"] = int(
            stats.get(
                "harmless",
                0
            ) or 0
        )

        result["undetected"] = int(
            stats.get(
                "undetected",
                0
            ) or 0
        )

        result["timeout"] = int(
            stats.get(
                "timeout",
                0
            ) or 0
        )

        return result

    except requests.Timeout:

        result["error"] = (
            "VirusTotal request timed out."
        )

        return result

    except requests.RequestException as error:

        result["error"] = (
            "VirusTotal connection error: "
            f"{error}"
        )

        return result

    except ValueError:

        result["error"] = (
            "VirusTotal returned invalid JSON."
        )

        return result


# ==================================================
# ABUSEIPDB
# ==================================================

def check_abuseipdb(ip_address):

    result = {
        "source": "AbuseIPDB",
        "available": False,
        "configured": bool(
            ABUSEIPDB_API_KEY
        ),
        "error": None,
        "abuse_confidence": 0,
        "total_reports": 0,
        "distinct_users": 0,
        "country_code": None,
        "isp": None,
        "domain": None,
        "usage_type": None,
        "last_reported_at": None
    }

    if not ABUSEIPDB_API_KEY:

        result["error"] = (
            "AbuseIPDB API key is not configured."
        )

        return result

    validation = validate_public_ip(
        ip_address
    )

    if not validation["public"]:

        result["error"] = validation["error"]

        return result

    url = (
        "https://api.abuseipdb.com/"
        "api/v2/check"
    )

    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY
    }

    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90
    }

    try:

        response = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=10
        )

        if response.status_code == 401:

            result["error"] = (
                "AbuseIPDB authentication failed."
            )

            return result

        if response.status_code == 429:

            result["error"] = (
                "AbuseIPDB rate limit reached."
            )

            return result

        if response.status_code != 200:

            result["error"] = (
                "AbuseIPDB returned "
                f"HTTP {response.status_code}."
            )

            return result

        payload = response.json()

        data = payload.get(
            "data",
            {}
        )

        result["available"] = True

        result["abuse_confidence"] = int(
            data.get(
                "abuseConfidenceScore",
                0
            ) or 0
        )

        result["total_reports"] = int(
            data.get(
                "totalReports",
                0
            ) or 0
        )

        result["distinct_users"] = int(
            data.get(
                "numDistinctUsers",
                0
            ) or 0
        )

        result["country_code"] = data.get(
            "countryCode"
        )

        result["isp"] = data.get(
            "isp"
        )

        result["domain"] = data.get(
            "domain"
        )

        result["usage_type"] = data.get(
            "usageType"
        )

        result["last_reported_at"] = data.get(
            "lastReportedAt"
        )

        return result

    except requests.Timeout:

        result["error"] = (
            "AbuseIPDB request timed out."
        )

        return result

    except requests.RequestException as error:

        result["error"] = (
            "AbuseIPDB connection error: "
            f"{error}"
        )

        return result

    except ValueError:

        result["error"] = (
            "AbuseIPDB returned invalid JSON."
        )

        return result


# ==================================================
# DOMAIN NORMALIZATION (Phase 4)
# ==================================================
# One clear normalization rule, shared by DOMAIN IOC comparison
# (reputation_routes.check_domain_ioc) and, optionally, by IOC
# creation (app.py add_indicator). Never touches existing DB
# rows - only used at comparison/creation time.
#
# Examples:
#   HTTPS://Example.COM/login  -> example.com
#   example.com.                -> example.com
#   example.com:443             -> example.com

def normalize_domain(value):

    if not value:
        return ""

    value = value.strip()

    if not value:
        return ""

    parse_value = value

    if "://" not in parse_value:
        parse_value = "https://" + parse_value

    # urlparse().hostname already lowercases the host and
    # strips the port - it does not strip a trailing dot.
    host = urlparse(parse_value).hostname or ""

    return host.strip(".")


def domain_matches_ioc(
    observed_domain,
    ioc_domain
):
    """
    Domain-boundary-safe comparison. Both arguments MUST already
    be normalized via normalize_domain() before calling this -
    it does not normalize them itself.

    Matches:
        observed_domain == ioc_domain
        OR observed_domain ends with "." + ioc_domain
    (i.e. ioc_domain and any of its subdomains match).

    Deliberately NOT substring matching, so:
        "notbad-example.com" does NOT match ioc "bad-example.com"
        "bad-example.com.attacker.org" does NOT match either.
    """

    if not observed_domain or not ioc_domain:
        return False

    return (
        observed_domain == ioc_domain
        or observed_domain.endswith("." + ioc_domain)
    )


# ==================================================
# SEVERITY FROM SCORE (Phase 4 - extracted, no behavior
# change: same thresholds calculate_threat_risk() always used)
# ==================================================

def severity_from_score(score):

    if score >= 80:
        return "CRITICAL"

    elif score >= 60:
        return "HIGH"

    elif score >= 35:
        return "MEDIUM"

    elif score >= 15:
        return "LOW"

    else:
        return "INFO"


# ==================================================
# IOC SEVERITY SCORE CONTRIBUTION
# ==================================================
# Shared by both the IP-IOC and DOMAIN-IOC paths, and by both the
# manual analysis routes and the background worker (all of them
# route through calculate_threat_risk() below) - a single source
# of truth so the same IOC always contributes the same score no
# matter which page or process triggered the analysis. Scaled
# from the same INFO/LOW/MEDIUM/HIGH/CRITICAL vocabulary already
# used everywhere else in the risk engine.

IOC_SEVERITY_SCORE = {
    "CRITICAL": 40,
    "HIGH": 30,
    "MEDIUM": 20,
    "LOW": 10,
    "INFO": 5
}


def score_ioc_severity(ioc_severity):

    return IOC_SEVERITY_SCORE.get(
        (ioc_severity or "").upper(),
        20  # unknown/missing severity - treat as MEDIUM
    )


# ==================================================
# RISK CORRELATION ENGINE
# ==================================================

def calculate_threat_risk(
    virustotal,
    abuseipdb,
    local_ioc=None
):

    score = 0
    reasons = []

    # --------------------------------------------------
    # VIRUSTOTAL
    # --------------------------------------------------

    if virustotal.get(
        "available"
    ):

        malicious = int(
            virustotal.get(
                "malicious",
                0
            )
        )

        suspicious = int(
            virustotal.get(
                "suspicious",
                0
            )
        )

        if malicious >= 10:

            score += 40

            reasons.append(
                (
                    "VirusTotal: "
                    f"{malicious} security vendors "
                    "classified the IP as malicious."
                )
            )

        elif malicious >= 5:

            score += 30

            reasons.append(
                (
                    "VirusTotal: "
                    f"{malicious} malicious detections."
                )
            )

        elif malicious >= 2:

            score += 20

            reasons.append(
                (
                    "VirusTotal: "
                    f"{malicious} malicious detections."
                )
            )

        elif malicious == 1:

            score += 8

            reasons.append(
                "VirusTotal: 1 malicious detection."
            )

        if suspicious >= 5:

            score += 10

            reasons.append(
                (
                    "VirusTotal: "
                    f"{suspicious} suspicious detections."
                )
            )

        elif suspicious > 0:

            score += 5

            reasons.append(
                (
                    "VirusTotal: "
                    f"{suspicious} suspicious detection(s)."
                )
            )

    # --------------------------------------------------
    # ABUSEIPDB
    # --------------------------------------------------

    if abuseipdb.get(
        "available"
    ):

        abuse_score = int(
            abuseipdb.get(
                "abuse_confidence",
                0
            )
        )

        total_reports = int(
            abuseipdb.get(
                "total_reports",
                0
            )
        )

        if abuse_score >= 90:

            score += 40

            reasons.append(
                (
                    "AbuseIPDB: "
                    f"{abuse_score}% abuse confidence."
                )
            )

        elif abuse_score >= 75:

            score += 30

            reasons.append(
                (
                    "AbuseIPDB: "
                    f"{abuse_score}% abuse confidence."
                )
            )

        elif abuse_score >= 50:

            score += 20

            reasons.append(
                (
                    "AbuseIPDB: "
                    f"{abuse_score}% abuse confidence."
                )
            )

        elif abuse_score >= 25:

            score += 10

            reasons.append(
                (
                    "AbuseIPDB: "
                    f"{abuse_score}% abuse confidence."
                )
            )

        # Reports only add extra risk if confidence is already meaningful
        if abuse_score >= 25:

            if total_reports >= 100:

                score += 10

                reasons.append(
                    (
                        "AbuseIPDB: "
                        f"{total_reports} recent reports "
                        f"with {abuse_score}% abuse confidence."
                    )
                )

            elif total_reports >= 20:

                score += 5

                reasons.append(
                    (
                        "AbuseIPDB: "
                        f"{total_reports} recent reports "
                        f"with {abuse_score}% abuse confidence."
                    )
                )

    # --------------------------------------------------
    # LOCAL IOC
    # --------------------------------------------------
    # `local_ioc` is the matched threat_indicators row's own
    # `severity` value (a string) or None if no active IP IOC
    # matched - NOT a plain boolean. Scored with the same
    # graduated table DOMAIN IOC uses, so a CRITICAL-tagged IOC
    # contributes more than an INFO-tagged one instead of every
    # match contributing the same flat amount regardless of how
    # the analyst tagged it.

    if local_ioc:

        score += score_ioc_severity(local_ioc)

        reasons.append(
            "IP matches an active local IOC "
            f"(severity: {local_ioc.upper()})."
        )

    score = min(
        score,
        100
    )

    # --------------------------------------------------
    # SEVERITY
    # --------------------------------------------------

    severity = severity_from_score(score)

    if not reasons:

        reasons.append(
            (
                "No significant malicious reputation "
                "indicators were identified."
            )
        )

    return {
        "score": score,
        "severity": severity,
        "reasons": reasons
    }


# ==================================================
# INCIDENT RESPONSE PLAYBOOK
# ==================================================

def get_response_playbook(
    severity
):
    """
    Base, severity-only response playbook. This is rule-based /
    deterministic guidance for an IT/Security administrator -
    not AI. It is the foundation build_recommended_response()
    (below) extends with alert-specific context; it is also
    used as-is by the manual /reputation page and by
    analyze_ip_reputation() results.
    """

    if severity == "CRITICAL":

        return [
            "Begin immediate investigation.",
            "Consider isolating the affected endpoint.",
            "Consider blocking confirmed malicious destinations.",
            "Preserve relevant logs and evidence.",
            "Search for the IOC across all monitored endpoints.",
            (
                "Check for related activity or lateral "
                "movement indicators."
            ),
            (
                "Review potentially exposed credentials "
                "if compromise is suspected."
            ),
            "Escalate to Incident Response.",
            "Restore connectivity only after validation."
        ]

    if severity == "HIGH":

        return [
            "Investigate the endpoint promptly.",
            "Validate the process responsible for the connection.",
            "Search for the same IOC across other endpoints.",
            "Review relevant endpoint/network logs.",
            "Consider blocking the destination.",
            (
                "Consider isolating the endpoint if "
                "compromise is suspected."
            ),
            "Escalate to an Incident."
        ]

    if severity == "MEDIUM":

        return [
            "Review the process responsible for the connection.",
            "Validate whether the destination is business-related.",
            "Review recent endpoint and network activity.",
            "Search for related IOC activity.",
            (
                "Consider blocking the destination if "
                "additional indicators are found."
            )
        ]

    if severity == "LOW":

        return [
            "Validate whether the activity is expected.",
            "Review recent activity from the endpoint.",
            "Continue monitoring for related indicators."
        ]

    return [
        "Record the event.",
        "Continue monitoring.",
        "No immediate containment action is required."
    ]


# ==================================================
# PHASE 6: CONTEXT-AWARE RECOMMENDED RESPONSE ENGINE
# ==================================================
# Rule-based / deterministic response guidance (NOT "AI").
# Extends get_response_playbook()'s base, severity-only list
# with specific steps ONLY when the system actually collected
# the corresponding evidence - never invents evidence it does
# not have (e.g. no file-hash telemetry exists, so nothing
# hash-related is ever suggested here; see Phase 4/HASH IOC
# "future capability" note).
#
# `context` keys (all optional):
#   domain_ioc        - the matched DOMAIN threat_indicators
#                        row (dict-like) or None
#   ip_ioc_match       - bool, local IP IOC matched
#   vt_malicious       - int, VirusTotal malicious detection count
#   abuse_confidence   - int, AbuseIPDB confidence score (0-100)
#   process_unknown    - bool, the responsible process could not
#                        be identified by the agent
#   resolved_ip        - str or None, the destination IP
#   already_blocked    - bool, destination already in blocked_domains
#   already_isolated   - bool, endpoint status is already ISOLATED

def build_recommended_response(
    severity,
    context=None
):

    context = context or {}

    steps = list(get_response_playbook(severity))

    domain_ioc = context.get("domain_ioc")

    if domain_ioc:

        ioc_domain = (
            domain_ioc.get("indicator_value")
            if hasattr(domain_ioc, "get")
            else str(domain_ioc)
        )

        steps.append(
            f"Verify why the endpoint contacted the known "
            f"IOC domain: {ioc_domain}."
        )
        steps.append(
            f"Search for {ioc_domain} across other "
            f"monitored endpoints."
        )
        steps.append(
            "Review related DNS/network activity for this domain."
        )

        if not context.get("already_blocked"):
            steps.append("Consider blocking the destination domain.")

    if context.get("ip_ioc_match"):

        resolved_ip = context.get("resolved_ip") or "the destination IP"

        steps.append(
            f"Search for connections to {resolved_ip} "
            f"from other monitored endpoints."
        )
        steps.append(
            "Review the process that initiated this connection."
        )
        steps.append(
            "Verify whether this IP is expected for the organization."
        )

    vt_malicious = context.get("vt_malicious", 0) or 0

    if vt_malicious >= 5:

        steps.append(
            "Review the VirusTotal detection details for "
            "this destination."
        )
        steps.append(
            "Investigate the process responsible for this connection."
        )
        steps.append(
            "Search for related domains/IPs associated with "
            "this destination."
        )

    abuse_confidence = context.get("abuse_confidence", 0) or 0

    if abuse_confidence >= 75:

        steps.append(
            "Review the connection history for this destination."
        )
        steps.append(
            "Validate whether the destination has a legitimate "
            "business purpose."
        )
        steps.append(
            "Consider blocking this destination after "
            "analyst validation."
        )

    if context.get("process_unknown"):

        steps.append(
            "Verify the process responsible for this connection "
            "- it could not be positively identified."
        )
        steps.append(
            "Consider additional endpoint investigation to "
            "identify the responsible process."
        )

    if context.get("already_blocked"):
        steps.append(
            "Note: this destination is already on the "
            "internal block list."
        )

    if context.get("already_isolated"):
        steps.append(
            "Note: this endpoint is already isolated."
        )

    return steps


# ==================================================
# COMPLETE LOOKUP
# ==================================================

def analyze_ip_reputation(
    ip_address,
    local_ioc=None
):

    validation = validate_public_ip(
        ip_address
    )

    if not validation["valid"]:

        return {
            "error": validation["error"]
        }

    if not validation["public"]:

        return {
            "error": validation["error"]
        }

    vt = check_virustotal(
        ip_address
    )

    abuse = check_abuseipdb(
        ip_address
    )

    risk = calculate_threat_risk(
        vt,
        abuse,
        local_ioc
    )

    playbook = get_response_playbook(
        risk["severity"]
    )

    return {
        "error": None,
        "ip": ip_address,
        "virustotal": vt,
        "abuseipdb": abuse,
        "risk_score": risk["score"],
        "severity": risk["severity"],
        "reasons": risk["reasons"],
        "playbook": playbook,
        "local_ioc": local_ioc
    }