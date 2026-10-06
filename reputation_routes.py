import json
import os
import re
import db_config
import sqlite3

from datetime import datetime, timedelta

from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    session,
    has_request_context
)

import virustotal_provider
import abuseipdb_provider

import threat_intel_framework as threat_intel_fw
import threat_intel_display

from threat_intelligence import (
    analyze_ip_reputation,
    calculate_threat_risk,
    get_response_playbook,
    normalize_domain,
    domain_matches_ioc
)


# SOC_DB_PATH (optional): see app.py's identical override for the
# full rationale.
_soc_db_path_override = os.getenv("SOC_DB_PATH", "").strip()

if _soc_db_path_override:
    if os.path.isabs(_soc_db_path_override):
        DB_NAME = _soc_db_path_override
    else:
        DB_NAME = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            _soc_db_path_override
        )
else:
    DB_NAME = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cybersec.db")

CACHE_MINUTES = 60


reputation_bp = Blueprint(
    "reputation",
    __name__
)


# ==================================================
# DB
# ==================================================

def get_db_connection():

    # Phase 12B.6C.1: central policy (WAL, busy timeout, synchronous=FULL,
    # tracked so a request/iteration can always release it).
    return db_config.open_connection(DB_NAME)


def init_reputation_db():

    conn = get_db_connection()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS
        threat_reputation (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL UNIQUE,
            vt_malicious INTEGER DEFAULT 0,
            vt_suspicious INTEGER DEFAULT 0,
            vt_harmless INTEGER DEFAULT 0,
            vt_undetected INTEGER DEFAULT 0,
            abuse_confidence INTEGER DEFAULT 0,
            abuse_reports INTEGER DEFAULT 0,
            abuse_country TEXT,
            abuse_isp TEXT,
            abuse_usage_type TEXT,
            local_ioc INTEGER DEFAULT 0,
            risk_score INTEGER DEFAULT 0,
            severity TEXT NOT NULL,
            reasons TEXT,
            checked_at TEXT NOT NULL,
            checked_by TEXT
        )
    """)

    conn.commit()
    conn.close()


# ==================================================
# AUTH
# ==================================================

def login_required():

    return "user_id" in session


# ==================================================
# LOG
# ==================================================

def write_log(
    event_type,
    message,
    target_ip=None
):

    conn = get_db_connection()

    log_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    conn.execute("""
        INSERT INTO system_logs (
            log_time,
            event_type,
            target_ip,
            username,
            message
        )
        VALUES (?, ?, ?, ?, ?)
    """, (
        log_time,
        event_type,
        target_ip,
        session.get(
            "username",
            "anonymous"
        ),
        message
    ))

    conn.commit()
    conn.close()


# ==================================================
# LOCAL IOC CHECK
# ==================================================

def local_ioc_exists(
    ip_address
):

    # Returns the matched IOC's own `severity` (e.g. "HIGH") so
    # callers can score the match proportionally to how the
    # analyst actually tagged it, or None if no active IP IOC
    # matches - NOT a plain boolean. Still truthy/falsy-compatible
    # with existing "if local_ioc_exists(...):" style callers.

    conn = get_db_connection()

    indicator = conn.execute("""
        SELECT severity
        FROM threat_indicators
        WHERE indicator_type = 'IP'
        AND indicator_value = ?
        AND active = 1
        LIMIT 1
    """, (
        ip_address,
    )).fetchone()

    conn.close()

    if indicator is None:
        return None

    return indicator["severity"]


# ==================================================
# DOMAIN IOC CHECK (Phase 4)
# ==================================================
# Always checked fresh, on every event analysis - never cached.
# An Admin may add/disable a DOMAIN IOC at any time, and it must
# take effect on the very next analysis, exactly like IP IOC
# freshness (Phase 3, section 6).
#
# Subdomain-boundary matching (via domain_matches_ioc(), NOT
# substring matching) - see threat_intelligence.py.

def check_domain_ioc(domain):

    normalized_domain = normalize_domain(domain)

    if not normalized_domain:
        return None

    conn = get_db_connection()

    rows = conn.execute("""
        SELECT *
        FROM threat_indicators
        WHERE indicator_type = 'DOMAIN'
        AND active = 1
    """).fetchall()

    conn.close()

    for row in rows:

        ioc_normalized = normalize_domain(
            row["indicator_value"]
        )

        if domain_matches_ioc(
            normalized_domain,
            ioc_normalized
        ):

            return dict(row)

    return None


# ==================================================
# HASH IOC CHECK (Phase 11B)
# ==================================================
# Exact match only (unlike DOMAIN, which allows subdomain
# matching) - a hash is either byte-for-byte identical to a
# stored IOC value or it is not a match at all, never a
# substring/LIKE comparison. Format is validated BEFORE
# querying so a malformed/truncated hash string is never
# compared against threat_indicators at all - this re-validates
# even though the ingestion route already nulls out malformed
# hashes, since this function may be called with values from
# other sources in the future.
#
# SHA-256-first priority: if the SHA-256 value matches an
# active HASH IOC, that match is used and MD5 is never even
# queried. MD5 is checked only as a fallback when SHA-256
# produced no match. This guarantees a single observed
# executable contributes at most ONE HASH-IOC severity
# contribution per event, even if both its SHA-256 and MD5 are
# separately registered as IOCs.

SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
MD5_PATTERN = re.compile(r"^[a-f0-9]{32}$")


def check_hash_ioc(sha256, md5):

    # Returns (ioc_row_dict, "sha256"|"md5") on a match, or
    # (None, None) if neither value matches an active HASH IOC.

    conn = get_db_connection()

    matched_row = None
    matched_field = None

    normalized_sha256 = (sha256 or "").strip().lower()

    if SHA256_PATTERN.match(normalized_sha256):

        matched_row = conn.execute("""
            SELECT *
            FROM threat_indicators
            WHERE indicator_type = 'HASH'
            AND indicator_value = ?
            AND active = 1
            LIMIT 1
        """, (
            normalized_sha256,
        )).fetchone()

        if matched_row:
            matched_field = "sha256"

    if matched_row is None:

        normalized_md5 = (md5 or "").strip().lower()

        if MD5_PATTERN.match(normalized_md5):

            matched_row = conn.execute("""
                SELECT *
                FROM threat_indicators
                WHERE indicator_type = 'HASH'
                AND indicator_value = ?
                AND active = 1
                LIMIT 1
            """, (
                normalized_md5,
            )).fetchone()

            if matched_row:
                matched_field = "md5"

    conn.close()

    if matched_row is None:
        return None, None

    return dict(matched_row), matched_field


# ==================================================
# CACHE
# ==================================================
# _get_fresh_cache_row() is the single place that knows the
# cache-freshness rule (CACHE_MINUTES TTL). Both
# get_cached_result() (used by the manual /reputation page,
# unchanged behavior) and get_reputation_with_cache() (Phase 3,
# used by the web_event_worker) share it - no duplicated TTL
# logic, no second magic number.

def _get_fresh_cache_row(ip_address):

    conn = get_db_connection()

    row = conn.execute("""
        SELECT *
        FROM threat_reputation
        WHERE ip_address = ?
        ORDER BY id DESC
        LIMIT 1
    """, (
        ip_address,
    )).fetchone()

    conn.close()

    if row is None:

        return None

    try:

        checked_at = datetime.strptime(
            row["checked_at"],
            "%Y-%m-%d %H:%M:%S"
        )

    except (
        ValueError,
        TypeError
    ):

        return None

    cache_age = (
        datetime.now()
        - checked_at
    )

    if cache_age > timedelta(
        minutes=CACHE_MINUTES
    ):

        return None

    return row


def get_cached_result(ip_address):

    row = _get_fresh_cache_row(ip_address)

    if row is None:

        return None

    try:

        reasons = json.loads(
            row["reasons"]
        )

    except (
        json.JSONDecodeError,
        TypeError
    ):

        reasons = []


    severity = (
        row["severity"]
        or "INFO"
    )


    result = {

        "ip_address":
            row["ip_address"],

        "risk_score":
            row["risk_score"],

        "severity":
            severity,

        "reasons":
            reasons,

        "local_ioc":
            bool(
                row["local_ioc"]
            ),

        "checked_at":
            row["checked_at"],

        "checked_by":
            row["checked_by"],

        "cached":
            True,


        # ------------------------------------------
        # VIRUSTOTAL
        # ------------------------------------------

        "virustotal": {

            "available": True,

            "malicious":
                row["vt_malicious"]
                or 0,

            "suspicious":
                row["vt_suspicious"]
                or 0,

            "harmless":
                row["vt_harmless"]
                or 0,

            "undetected":
                row["vt_undetected"]
                or 0,

            "timeout": 0,

            "error": None

        },


        # ------------------------------------------
        # ABUSEIPDB
        # ------------------------------------------

        "abuseipdb": {

            "available": True,

            "abuse_confidence_score":
                row["abuse_confidence"]
                or 0,

            "total_reports":
                row["abuse_reports"]
                or 0,

            "country_code":
                row["abuse_country"]
                or "",

            "isp":
                row["abuse_isp"]
                or "",

            "usage_type":
                row["abuse_usage_type"]
                or "",

            "domain": "",

            "last_reported_at": None,

            "error": None

        },


        "playbook":
            get_response_playbook(
                severity
            )

    }


    return result

def get_cached_playbook(
    severity
):

    return get_response_playbook(
        severity
    )


# ==================================================
# SAVE RESULT
# ==================================================

def save_reputation_result(
    result,
    checked_by=None
):

    checked_at = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    # Background callers (the web_event_worker) have no Flask
    # request/session and must pass checked_by explicitly.
    # Every existing caller (the manual /reputation page) keeps
    # working exactly as before - it runs inside a real request,
    # so session.get(...) still resolves the logged-in username.
    if checked_by is None:

        if has_request_context():

            checked_by = session.get(
                "username"
            )

        else:

            checked_by = "system"

    vt = result["virustotal"]

    abuse = result["abuseipdb"]

    conn = get_db_connection()

    conn.execute("""
        INSERT INTO threat_reputation (
            ip_address,
            vt_malicious,
            vt_suspicious,
            vt_harmless,
            vt_undetected,
            abuse_confidence,
            abuse_reports,
            abuse_country,
            abuse_isp,
            abuse_usage_type,
            local_ioc,
            risk_score,
            severity,
            reasons,
            checked_at,
            checked_by
        )
        VALUES (
            ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?
        )

        ON CONFLICT(ip_address)
        DO UPDATE SET
            vt_malicious =
                excluded.vt_malicious,
            vt_suspicious =
                excluded.vt_suspicious,
            vt_harmless =
                excluded.vt_harmless,
            vt_undetected =
                excluded.vt_undetected,
            abuse_confidence =
                excluded.abuse_confidence,
            abuse_reports =
                excluded.abuse_reports,
            abuse_country =
                excluded.abuse_country,
            abuse_isp =
                excluded.abuse_isp,
            abuse_usage_type =
                excluded.abuse_usage_type,
            local_ioc =
                excluded.local_ioc,
            risk_score =
                excluded.risk_score,
            severity =
                excluded.severity,
            reasons =
                excluded.reasons,
            checked_at =
                excluded.checked_at,
            checked_by =
                excluded.checked_by
    """, (
        result["ip"],
        vt.get(
            "malicious",
            0
        ),
        vt.get(
            "suspicious",
            0
        ),
        vt.get(
            "harmless",
            0
        ),
        vt.get(
            "undetected",
            0
        ),
        abuse.get(
            "abuse_confidence",
            0
        ),
        abuse.get(
            "total_reports",
            0
        ),
        abuse.get(
            "country_code"
        ),
        abuse.get(
            "isp"
        ),
        abuse.get(
            "usage_type"
        ),
        1
        if result["local_ioc"]
        else 0,
        result["risk_score"],
        result["severity"],
        json.dumps(
            result["reasons"]
        ),
        checked_at,
        checked_by
    ))

    conn.commit()
    conn.close()

    # PHASE 12B.3: reuse the VirusTotal IP result this live legacy lookup
    # JUST fetched to record normalized (context-only) evidence - so the
    # same IP is never requested from VirusTotal a second time. Runs only
    # after the legacy row above is committed and closed, never reads or
    # changes `result`, and can never affect risk_score/severity or raise
    # into the caller.
    try:
        virustotal_provider.record_legacy_ip_result(result["ip"], vt)
    except Exception:
        pass

    # PHASE 12B.4: same principle for AbuseIPDB - derive normalized
    # (context-only) evidence from the result this live legacy lookup JUST
    # fetched, so the IP is never requested from AbuseIPDB twice. Its own
    # try/except: a failure here can never affect the VirusTotal hook, the
    # legacy row above, `result`, or the caller. Failed lookups write
    # nothing (the provider requires proof of a real provider answer).
    try:
        abuseipdb_provider.record_legacy_ip_result(result["ip"], abuse)
    except Exception:
        pass

    result["checked_at"] = checked_at

    return result


# ==================================================
# PHASE 3: CACHE-AWARE REPUTATION LOOKUP
# ==================================================
# Single entry point used by web_event_worker.py (and safe to
# reuse anywhere else that wants the same behavior). Returns a
# result dict shaped exactly like analyze_ip_reputation()'s
# return value, PLUS "reputation_source": "CACHE" or "LIVE", so
# every caller can treat the two cases identically.
#
# LOCAL IOC FRESHNESS: local_ioc_exists() is always re-checked
# right now, never taken from the cached row. The cached
# threat_reputation.local_ioc column only remembers WHETHER an
# IOC was active at cache time (0/1) - not its severity - so a
# cached row is reused as-is only when neither the cached row nor
# the current check involves any IOC at all. If an IOC is or was
# involved in any way (added, removed, or simply still active -
# its severity may have been edited since caching), the risk
# score is recalculated from the cached VirusTotal/AbuseIPDB
# numbers (no new external API calls) using calculate_threat_risk()
# - the same engine analyze_ip_reputation() itself uses. This
# means an IOC added, removed, or re-tagged with a different
# severity after a value was cached is reflected on the very next
# analysis of that IP, without waiting for the cache to expire.
#
# KNOWN, ACCEPTED RACE CONDITION: if two worker processes claim
# different PENDING events for the SAME public IP at nearly the
# same instant, both may find no fresh cache row yet and both
# will call VirusTotal/AbuseIPDB live for that IP once each. No
# data corruption results - threat_reputation.ip_address is
# UNIQUE and save_reputation_result() upserts via
# ON CONFLICT(ip_address) DO UPDATE, so the row simply reflects
# whichever save committed last. This is a narrow, low-impact
# window (typically milliseconds) and is left undefended on
# purpose: a proper fix would need distributed locking, which is
# unnecessary complexity for this project. Document, don't
# over-engineer.

def get_reputation_with_cache(
    ip_address,
    checked_by=None
):

    current_local_ioc = local_ioc_exists(
        ip_address
    )

    row = _get_fresh_cache_row(
        ip_address
    )

    if row is not None:

        # Rebuild vt/abuse dicts using the SAME key names
        # check_virustotal()/check_abuseipdb() use, so
        # calculate_threat_risk() reads them correctly. (Not
        # get_cached_result()'s reshaped dict - that one uses
        # "abuse_confidence_score" for display purposes, which
        # calculate_threat_risk() does not read.)

        vt = {
            "available": True,
            "malicious": row["vt_malicious"] or 0,
            "suspicious": row["vt_suspicious"] or 0,
            "harmless": row["vt_harmless"] or 0,
            "undetected": row["vt_undetected"] or 0,
            "timeout": 0,
            "error": None
        }

        abuse = {
            "available": True,
            "abuse_confidence": row["abuse_confidence"] or 0,
            "total_reports": row["abuse_reports"] or 0,
            "country_code": row["abuse_country"] or "",
            "isp": row["abuse_isp"] or "",
            "usage_type": row["abuse_usage_type"] or "",
            "domain": "",
            "last_reported_at": None,
            "error": None
        }

        cached_local_ioc = bool(
            row["local_ioc"]
        )

        current_has_ioc = current_local_ioc is not None

        # The cache column only remembers WHETHER an IP IOC was
        # active when this row was saved (0/1), not which severity
        # it was tagged with - severity now affects the score, so
        # a cached row can only be trusted as-is when we are sure
        # no IOC was involved either then or now. Any other case
        # (presence changed, OR an IOC is currently active - even
        # if presence is unchanged, its severity may have been
        # edited since caching) is recomputed locally below, which
        # reuses the cached VirusTotal/AbuseIPDB numbers and makes
        # no new external API call.

        if cached_local_ioc == current_has_ioc and not current_has_ioc:

            # Nothing IOC-relevant changed since this row was
            # cached - the stored risk/severity/reasons are
            # still accurate, reuse them directly.

            try:

                reasons = json.loads(
                    row["reasons"]
                )

            except (
                json.JSONDecodeError,
                TypeError
            ):

                reasons = []

            risk_score = row["risk_score"]
            severity = row["severity"] or "INFO"

        else:

            # Local IOC state (presence or severity) may differ
            # from what was cached - recompute using the fresh
            # IOC state, reusing the cached external numbers.
            # No VirusTotal/AbuseIPDB call happens here.

            risk = calculate_threat_risk(
                vt,
                abuse,
                current_local_ioc
            )

            risk_score = risk["score"]
            severity = risk["severity"]
            reasons = risk["reasons"]

        return {
            "error": None,
            "ip": ip_address,
            "virustotal": vt,
            "abuseipdb": abuse,
            "risk_score": risk_score,
            "severity": severity,
            "reasons": reasons,
            "playbook": get_response_playbook(severity),
            "local_ioc": current_local_ioc,
            "reputation_source": "CACHE",
            "checked_at": row["checked_at"]
        }

    # --------------------------------------------------
    # NO FRESH CACHE - LIVE LOOKUP
    # --------------------------------------------------

    result = analyze_ip_reputation(
        ip_address,
        current_local_ioc
    )

    if result.get("error"):

        return result

    result["cached"] = False

    result = save_reputation_result(
        result,
        checked_by=checked_by
    )

    result["reputation_source"] = "LIVE"

    return result


# ==================================================
# AUTO INCIDENT
# ==================================================

def create_reputation_incident(
    result
):

    if result["severity"] not in [
        "HIGH",
        "CRITICAL"
    ]:

        return False

    conn = get_db_connection()

    existing = conn.execute("""
        SELECT id
        FROM security_events
        WHERE event_type =
            'MALICIOUS_IP_REPUTATION'
        AND target_ip = ?
        AND status != 'RESOLVED'
        ORDER BY id DESC
        LIMIT 1
    """, (
        result["ip"],
    )).fetchone()

    if existing:

        conn.close()

        return False

    event_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    reason_text = "\n".join(
        (
            f"- {reason}"
            for reason in result["reasons"]
        )
    )

    response_text = "\n".join(
        (
            f"{index}. {step}"
            for index, step
            in enumerate(
                result["playbook"],
                start=1
            )
        )
    )

    description = (
        f"Threat intelligence analysis "
        f"identified IP {result['ip']} "
        f"with risk score "
        f"{result['risk_score']}/100.\n\n"
        f"Detection reasons:\n"
        f"{reason_text}\n\n"
        f"Recommended response:\n"
        f"{response_text}"
    )

    conn.execute("""
        INSERT INTO security_events (
            event_time,
            event_type,
            severity,
            username,
            target_ip,
            title,
            description,
            status,
            updated_by,
            updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event_time,
        "MALICIOUS_IP_REPUTATION",
        result["severity"],
        session.get(
            "username"
        ),
        result["ip"],
        "High-Risk IP Reputation Detected",
        description,
        "OPEN",
        None,
        None
    ))

    conn.commit()
    conn.close()

    write_log(
        "THREAT_INCIDENT_CREATED",
        (
            f"Automatic {result['severity']} "
            f"incident created for "
            f"{result['ip']}."
        ),
        result["ip"]
    )

    return True


# ==================================================
# REPUTATION PAGE
# ==================================================

@reputation_bp.route(
    "/reputation",
    methods=[
        "GET",
        "POST"
    ]
)
def reputation():

    if not login_required():

        return redirect(
            url_for("login")
        )

    result = None
    error = None
    incident_created = False

    # Oct 2026 Step 5: after a manual Threat-Intel re-check (POST to
    # /api/threat-intel/recheck), the admin is redirected back here with
    # ?ip_address=<ip> so the now-refreshed result is shown again. This
    # GET path is READ-ONLY: it only displays a CACHED result if one
    # exists (get_cached_result never performs a live lookup) - it never
    # triggers a new VirusTotal/AbuseIPDB call on its own.
    if request.method == "GET" and request.args.get("ip_address", "").strip():

        cached = get_cached_result(
            request.args.get("ip_address").strip()
        )

        if cached:
            result = cached

    if request.method == "POST":

        ip_address = request.form.get(
            "ip_address",
            ""
        ).strip()

        if not ip_address:

            error = (
                "Please enter an IP address."
            )

        else:

            cached = get_cached_result(
                ip_address
            )

            if cached:

                result = cached

            else:

                local_ioc = (
                    local_ioc_exists(
                        ip_address
                    )
                )

                result = (
                    analyze_ip_reputation(
                        ip_address,
                        local_ioc
                    )
                )

                if result.get(
                    "error"
                ):

                    error = result["error"]

                else:

                    result["cached"] = False

                    result = (
                        save_reputation_result(
                            result
                        )
                    )

                    incident_created = (
                        create_reputation_incident(
                            result
                        )
                    )

                    write_log(
                        "IP_REPUTATION_CHECK",
                        (
                            f"Threat reputation checked "
                            f"for {ip_address}. "
                            f"Risk score: "
                            f"{result['risk_score']}/100. "
                            f"Severity: "
                            f"{result['severity']}."
                        ),
                        ip_address
                    )

    conn = get_db_connection()

    history = conn.execute("""
        SELECT *
        FROM threat_reputation
        ORDER BY checked_at DESC
        LIMIT 25
    """).fetchall()

    conn.close()

    # Oct 2026 Step 5: read-only multi-source evidence + a live,
    # DISPLAY-ONLY Legacy-vs-Shadow comparison for the analyzed IP. Never
    # performs a new live lookup itself (only reads whatever evidence is
    # already cached) and never writes anywhere - this is NOT the
    # persistent Step 4 Shadow Mode pipeline, which remains exactly as
    # inactive on the live system as before this page existed.
    ti_evidence = None
    ti_comparison = None
    ti_provider_status = None

    if result and not result.get("error"):

        ip_for_ti = result.get("ip") or result.get("ip_address") or ip_address

        conn_ti = threat_intel_fw.get_db_connection()

        try:
            ti_evidence = threat_intel_fw.get_all_provider_evidence_for_event_with_conn(
                conn_ti, ip_for_ti, None, None, None
            )
        finally:
            conn_ti.close()

        ti_comparison = threat_intel_display.compute_display_only_comparison(
            ip_for_ti, None, None, None,
            result.get("risk_score", 0), result.get("severity", "INFO")
        )

        # Oct 2026 Step 13: per-indicator provider status (no "analyzing"
        # concept on this page - it is a manual, synchronous check, not a
        # stored/queued event - so PROCESSING never applies here).
        # Step 15: no event_time to check against the Threat Intel
        # Worker's real recent-event window either (this page analyzes a
        # raw IP, not a specific stored/queued event) - so an async
        # provider with no cached result is honestly reported ELIGIBLE
        # here, never an unverified QUEUED promise.
        ti_provider_status = threat_intel_display.per_event_provider_status(
            ip_for_ti, None, None, None
        )

    return render_template(
        "reputation.html",
        result=result,
        error=error,
        incident_created=incident_created,
        history=history,
        ti_evidence=ti_evidence,
        ti_comparison=ti_comparison,
        ti_provider_status=ti_provider_status
    )