# ==================================================
# OCT 2026: URLSCAN.IO - CONTEXT-ONLY ENRICHMENT (never a risk signal)
# ==================================================
#
# context_only (see threat_intel_framework.PROVIDER_REGISTRY["urlscan"]):
# this module only ever SEARCHES existing public scan results and NEVER
# submits a URL for scanning - no code here calls the /scan/ endpoint. A
# match is descriptive investigation enrichment (a report link, scan
# count), never independent evidence of malicious activity, and can never
# contribute to risk scoring regardless of what it finds (enforced in
# threat_intel_risk.py via evidence_class, not by this module).
#
# API contract verified against the official documentation at
# https://urlscan.io/docs/api/ (fetched at implementation time - not
# guessed):
#   GET https://urlscan.io/api/v1/search/?q=<query>
#   header: api-key: <key>   (DOC-CONFIRMED: searching existing results
#     works with reduced quota even without a key; a key raises quota -
#     this module calls keyless when no key is configured)
#   response: {"results": [...], "total": N}, each result has "page"
#     (url, domain, ip) and "task"/"result" (report link).
#   query syntax used here: domain:<value> for a DOMAIN indicator,
#     page.url:"<value>" for a URL indicator (quoted, exact phrase match).
# manual_eligible only (automatic_eligible=False in the registry) per the
# original project instruction: never auto-submit, manual/on-demand only.
# ==================================================

import os

import requests

from dotenv import load_dotenv

import threat_intel_framework as framework

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))


URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY", "").strip()

URLSCAN_SEARCH_URL = "https://urlscan.io/api/v1/search/"

URLSCAN_HTTP_TIMEOUT_SECONDS = 10

PROVIDER_NAME = "urlscan"


def _log_lookup_error(indicator_type, exc):

    framework.log_provider_lookup_error(PROVIDER_NAME, indicator_type, exc)


def _build_query(indicator_type, indicator_value):

    if indicator_type == "DOMAIN":
        return f"domain:{indicator_value}"

    if indicator_type == "URL":
        escaped = indicator_value.replace('"', '')
        return f'page.url:"{escaped}"'

    return None


def _parse_urlscan_response(response_json):

    total = response_json.get("total")
    results = response_json.get("results")

    if not isinstance(results, list) or not isinstance(total, int):
        return {"lookup_status": "ERROR", "summary": "urlscan.io returned an unexpected response shape."}

    if total <= 0:
        return {"lookup_status": "NO_MATCH"}

    newest = results[0] if results else {}
    report_url = None
    if isinstance(newest, dict):
        result_block = newest.get("result") or newest.get("_id")
        if isinstance(newest.get("result"), str):
            report_url = newest["result"]

    return {
        "lookup_status": "MATCH",
        "threat_type": "scan_results_found",
        "summary": f"urlscan.io: {total} existing public scan result(s) found." + (f" Most recent: {report_url}" if report_url else ""),
    }


def query_urlscan_live(indicator_type, indicator_value):

    query = _build_query(indicator_type, indicator_value)

    if query is None:
        return {"lookup_status": "ERROR", "summary": "urlscan.io supports DOMAIN and URL indicators only."}

    headers = {}
    if URLSCAN_API_KEY:
        headers["api-key"] = URLSCAN_API_KEY

    try:

        response = requests.get(
            URLSCAN_SEARCH_URL,
            params={"q": query},
            headers=headers,
            timeout=URLSCAN_HTTP_TIMEOUT_SECONDS
        )

        if response.status_code == 429:
            return {"lookup_status": "RATE_LIMITED"}

        if response.status_code in (401, 403):
            return {"lookup_status": "ERROR", "summary": "urlscan.io authentication failed."}

        if response.status_code != 200:
            return {"lookup_status": "ERROR", "summary": f"urlscan.io returned HTTP {response.status_code}."}

        try:
            response_json = response.json()
        except ValueError:
            return {"lookup_status": "ERROR", "summary": "urlscan.io returned invalid JSON."}

        return _parse_urlscan_response(response_json)

    except requests.Timeout:
        return {"lookup_status": "ERROR", "summary": "urlscan.io request timed out."}

    except requests.RequestException:
        return {"lookup_status": "ERROR", "summary": "urlscan.io connection error."}


def get_urlscan_evidence(indicator_type, indicator_value, conn=None):

    own = conn is None

    if own:
        conn = framework.get_db_connection()

    try:

        cached = framework.get_cached_evidence(conn, PROVIDER_NAME, indicator_type, indicator_value)

        if cached is not None:
            return cached

        try:
            live_result = query_urlscan_live(indicator_type, indicator_value)
        except Exception as exc:
            _log_lookup_error(indicator_type, exc)
            live_result = {"lookup_status": "ERROR", "summary": "Unexpected urlscan.io integration error."}

        return framework.store_evidence(conn, PROVIDER_NAME, indicator_type, indicator_value, live_result)

    finally:
        if own:
            conn.close()
