# ==================================================
# STEP 24B.2A: PHISHTANK BULK FEED PARSER
# ==================================================
#
# Parses PhishTank's documented "online-valid" bulk-download JSON format
# (https://phishtank.org/developer_info.php) into the generic record
# shape local_feed_store.ingest_snapshot() expects. This module performs
# NO HTTP request of any kind - per the Step 24B.2A scope boundary, no
# real download happens in this step. FEED_URL_TEMPLATE is recorded here
# (matching the "download URL lives in the feed-provider module, not the
# central registry" requirement) purely as reference documentation for a
# future, separately-approved download step - nothing in this module or
# anywhere else in this step calls it.
#
# Field mapping is based on PhishTank's own published documentation
# only (not verified against a real downloaded file, since none was
# downloaded): "url" -> raw_value (indicator_type is always URL - the
# online-valid feed is URL-only, see local_feed_providers.py), "phish_id"
# / "target" / "verified" / "online" kept as provider_metadata (never
# used for matching, display-only), "submission_time" -> first_seen,
# "verification_time" -> last_seen.
# ==================================================

import json

PROVIDER_NAME = "phishtank"

# Reference only - not called anywhere in this step. See module header.
FEED_URL_TEMPLATE = "http://data.phishtank.com/data/{app_key}/online-valid.json"
FEED_URL_NO_KEY = "http://data.phishtank.com/data/online-valid.json"


class PhishTankFeedParseError(Exception):
    pass


def parse_online_valid_json(json_text):
    """
    json_text: str or bytes containing the raw online-valid.json feed
    content. Returns a list of generic feed records (see
    feed_providers/__init__.py for the shape). Malformed individual
    entries are skipped (not fatal) - an entry missing a usable "url"
    field contributes nothing. A completely unparsable document (not
    valid JSON, or not a list) raises PhishTankFeedParseError - this is
    the feed-level "malformed feed" condition local_feed_store treats as
    a full rejection (previous snapshot stays active).
    """

    try:
        data = json.loads(json_text)
    except (ValueError, TypeError) as exc:
        raise PhishTankFeedParseError(f"online-valid.json is not valid JSON: {exc}") from exc

    if not isinstance(data, list):
        raise PhishTankFeedParseError("online-valid.json root is not a list")

    records = []

    for entry in data:

        if not isinstance(entry, dict):
            continue

        url = entry.get("url")

        if not url or not isinstance(url, str):
            continue

        provider_metadata = {}

        for key in ("phish_id", "target", "verified", "online", "phish_detail_url"):
            if key in entry:
                provider_metadata[key] = entry[key]

        records.append({
            "indicator_type": "URL",
            "raw_value": url,
            "first_seen": entry.get("submission_time"),
            "last_seen": entry.get("verification_time"),
            "provider_metadata": provider_metadata or None,
        })

    return records


# Step 24B.2E: standard, well-known alias every feed_providers/<name>.py
# module exposes under this EXACT name, so the generic scheduler
# (local_feed_scheduler.py) can dynamically resolve "the parser
# function" for any provider from its registry's parser_module string
# alone, without hard-coding PhishTank (or any provider) by name - a
# second provider's module just needs this same alias pointing at its
# own bytes->records function.
parse_feed_bytes = parse_online_valid_json
