# Step 24B.2A: provider-specific feed parsers. Each module here parses
# ONE provider's native feed format into the generic record shape
# local_feed_store.ingest_snapshot() expects:
#   {"indicator_type": "URL"|"DOMAIN"|"IP", "raw_value": str,
#    "first_seen": str|None, "last_seen": str|None,
#    "provider_metadata": dict|None}
# No module in this package performs an HTTP download in this step -
# every parser here takes already-fetched text/bytes as input.
