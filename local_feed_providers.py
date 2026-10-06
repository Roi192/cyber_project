# ==================================================
# STEP 24B.2A: LOCAL THREAT INTELLIGENCE FEED - PROVIDER CAPABILITY REGISTRY
# ==================================================
#
# Deliberately a SEPARATE registry from threat_intel_framework.
# PROVIDER_REGISTRY, not an extension of it (see the Step 24B.2A report
# for why): threat_intel_risk.py / threat_intel_shadow.py treat ANY
# provider name absent from threat_intel_framework.PROVIDER_REGISTRY as
# evidence_class "context_only" (never contributing to corroboration or
# risk scoring) purely as a side effect of a dict .get() default. Adding
# Local Feed providers to that SAME registry would be one incidental
# code change away from accidentally making a future maintainer's edit
# there pull Local Feed evidence into Legacy TI/Shadow TI scoring -
# something this phase must never do. Keeping genuinely separate
# registries makes that structurally impossible, not just currently
# unconfigured.
#
# Generic CAPABILITIES only - a feed provider's download URL, file
# format and record-parsing logic are NEVER here; they live in that
# provider's own module under feed_providers/ (e.g.
# feed_providers/phishtank_feed.py). Adding a second provider means
# adding one more feed_providers/<name>.py module plus one more entry
# below - no change to local_feed_store.py or local_feed_evidence.py.
# ==================================================

LOCAL_FEED_PROVIDER_REGISTRY = {
    "phishtank": {
        # PhishTank's online-valid feed is a URL-only feed (see the Step
        # 24B.2 planning report's feed research) - it does not publish
        # separate DOMAIN or IP indicators.
        "supported_indicator_types": ("URL",),
        "feed_type": "bulk_download",
        # No scheduler exists yet (Step 24B.2D scope boundary) - this
        # flag exists for a FUTURE automatic-refresh step to key off,
        # and currently has no effect anywhere.
        "automatic_eligible": False,
        "manual_eligible": True,
        "implemented": True,
        "parser_module": "feed_providers.phishtank_feed",
        "update_frequency_hours": 1,  # per PhishTank's own documentation
        # Step 24B.2D: generic download configuration - consumed ONLY by
        # local_feed_downloader.py's generic engine, which is never
        # hard-coded to this (or any) provider. Adding a second provider
        # means adding one more block exactly like this one - no change
        # to local_feed_downloader.py. "url" is the documented official
        # endpoint (Step 24B.2 feed research) - NOT fetched anywhere in
        # this step (no real download happens in 24B.2D).
        #
        # Step 24B.2D (verification round): the initial URL MUST be
        # https:// - local_feed_downloader.validate_initial_url() now
        # refuses an http:// starting point unconditionally in
        # production (no provider's registry config can opt out of
        # this - there is no field for it here). The documented
        # endpoint is only published as http:// (which 302-redirects to
        # this same https:// path - see Step 24B.2B's diagnostic), but
        # since the https:// form is independently confirmed to exist
        # at the identical host+path, it is used directly as the
        # initial URL, skipping that redirect hop entirely rather than
        # relying on it.
        "download": {
            "url": "https://data.phishtank.com/data/online-valid.json.gz",
            "allowed_redirect_hosts": ("data.phishtank.com",),
            "compression": "gzip",
            "expected_content_types": (
                "application/json", "application/gzip", "application/x-gzip",
                "application/octet-stream", "binary/octet-stream",
            ),
            "user_agent": "phishtank/CyberProject-LocalFeedDownloader",
        },
        # Step 24B.2D section 14 (commercial/licensing): documentation
        # metadata only - never enforced in code at this stage. Per the
        # Step 24B.2 feed research: PhishTank's Data (via API/feed) is
        # usable commercially per their own Terms of Use; only the
        # Site/Service UI itself is restricted to personal use.
        "commercial_use_ok": True,
        "license_note": (
            "PhishTank Terms of Use: the Site/Service is for personal use, "
            "but the Data (including via the API/feed) is available for "
            "commercial use at no charge. Attribution is requested, not "
            "contractually required for internal/non-public use."
        ),
        "requires_attribution": False,
    },
}


def get_provider_meta(provider):

    return LOCAL_FEED_PROVIDER_REGISTRY.get(provider)


def provider_supports_indicator_type(provider, indicator_type):

    meta = LOCAL_FEED_PROVIDER_REGISTRY.get(provider)

    if meta is None or not meta.get("implemented"):
        return False

    return indicator_type in meta.get("supported_indicator_types", ())


def known_providers():

    return tuple(
        name for name, meta in LOCAL_FEED_PROVIDER_REGISTRY.items()
        if meta.get("implemented")
    )
