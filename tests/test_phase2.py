"""Phase 2 tests: browser-extension event format, server dedupe, polling API,
VirusTotal handling (fully mocked - no network, no quota), cache TTLs and
the threat-intel status indicator.  Run:  python -m unittest discover -s tests -v
"""
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta

import requests

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

_TMP = tempfile.mkdtemp(prefix="monitor_p2_")
os.environ["DATABASE_PATH"] = os.path.join(_TMP, "test.db")
os.environ["API_KEY"] = ""
os.environ["VT_API_KEY"] = ""

import config  # noqa: E402
import database  # noqa: E402
from services import reputation  # noqa: E402
from validation import sanitize_url, validate_web_event  # noqa: E402
import app as app_module  # noqa: E402

FAKE_KEY = "FAKE-VT-KEY-DO-NOT-LEAK-0123456789"

# Exactly what browser_extension/background.js sends.
EXT_EVENT = {
    "endpoint_uid": "3f1c2a9e-5b7d-4c61-9e2f-0a1b2c3d4e5f",
    "computer_name": "BROWSER-3F1C2A9E",
    "domain": "www.wikipedia.org",
    "url": "https://www.wikipedia.org/wiki/Main_Page",
    "browser": "Edge",
    "timestamp": "2026-10-06T19:30:00",
}


# --------------------------------------------------------------------
# VirusTotal mock
# --------------------------------------------------------------------
class FakeResponse(object):
    def __init__(self, status_code, payload=None, raw="not json"):
        self.status_code = status_code
        self._payload = payload
        self.text = raw

    def json(self):
        if self._payload is None:
            raise ValueError("No JSON object could be decoded")
        return self._payload


class FakeSession(object):
    """Hands out scripted responses (or raises scripted exceptions)."""

    def __init__(self, *scripted):
        self.scripted = list(scripted)
        self.calls = []

    def get(self, url, headers=None, timeout=None):
        self.calls.append({"url": url, "headers": headers, "timeout": timeout})
        if not self.scripted:
            raise AssertionError("unexpected VirusTotal call for %s" % url)
        item = self.scripted.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def vt_payload(malicious=0, suspicious=0, harmless=60, undetected=10):
    return {"data": {"attributes": {"last_analysis_stats": {
        "malicious": malicious, "suspicious": suspicious, "harmless": harmless,
        "undetected": undetected, "timeout": 0}}}}


def vt_provider(*scripted):
    session = FakeSession(*scripted)
    return reputation.VirusTotalProvider(FAKE_KEY, session=session), session


class Phase2Base(unittest.TestCase):
    def setUp(self):
        self.client = app_module.app.test_client()
        conn = database.get_connection()
        for table in ("alerts", "web_visits", "domain_reputation", "endpoints"):
            conn.execute("DELETE FROM %s" % table)
        conn.commit()
        conn.close()
        reputation.reset_state()
        config.VT_API_KEY = ""
        config.API_KEY = ""

    def tearDown(self):
        reputation.reset_state()
        config.VT_API_KEY = ""
        config.API_KEY = ""
        reputation.build_provider = _ORIGINAL_BUILD

    def use_provider(self, provider):
        """Make the app use this provider for every event."""
        config.VT_API_KEY = FAKE_KEY
        reputation.build_provider = lambda: provider


_ORIGINAL_BUILD = reputation.build_provider


# --------------------------------------------------------------------
# 1. Event format / sanitization / dedupe / polling
# --------------------------------------------------------------------
class ExtensionEventTests(Phase2Base):
    def test_extension_event_format_accepted(self):
        r = self.client.post("/api/web-events", json=EXT_EVENT)
        self.assertEqual(r.status_code, 201, r.get_json())
        body = r.get_json()
        self.assertFalse(body["duplicate"])
        conn = database.get_connection()
        row = conn.execute("SELECT v.*, e.endpoint_uid, e.computer_name FROM web_visits v "
                           "JOIN endpoints e ON e.id = v.endpoint_id").fetchone()
        conn.close()
        self.assertEqual(row["endpoint_uid"], EXT_EVENT["endpoint_uid"])
        self.assertEqual(row["computer_name"], "BROWSER-3F1C2A9E")
        self.assertEqual(row["domain"], "www.wikipedia.org")
        self.assertEqual(row["sanitized_url"], "https://www.wikipedia.org/wiki/Main_Page")
        self.assertEqual(row["browser"], "Edge")
        self.assertEqual(row["visited_at"], "2026-10-06 19:30:00")
        self.assertEqual(row["reputation_status"], "UNKNOWN")   # no provider configured

    def test_domain_normalization_and_url_sanitization(self):
        event = validate_web_event(dict(EXT_EVENT, domain="WWW.Wikipedia.ORG.",
                                        url="https://user:pw@WWW.Wikipedia.ORG:443/wiki/Page?q=secret&t=1#frag"))
        self.assertEqual(event["domain"], "www.wikipedia.org")
        self.assertEqual(event["sanitized_url"], "https://www.wikipedia.org/wiki/Page")
        self.assertEqual(sanitize_url("http://example.com/?only=query", "example.com"), "http://example.com/")
        self.assertEqual(sanitize_url("https://example.com#only-fragment", "example.com"), "https://example.com/")
        for forbidden in ("?", "#", "secret", "user:pw", ":443"):
            self.assertNotIn(forbidden, event["sanitized_url"])

    def test_server_side_dedupe(self):
        first = self.client.post("/api/web-events", json=EXT_EVENT).get_json()
        again = self.client.post("/api/web-events", json=EXT_EVENT).get_json()
        self.assertFalse(first["duplicate"])
        self.assertTrue(again["duplicate"])
        self.assertEqual(again["visit_id"], first["visit_id"])
        # 4 seconds later, same page: still a reload burst
        burst = self.client.post("/api/web-events", json=dict(EXT_EVENT, timestamp="2026-10-06T19:30:04")).get_json()
        self.assertTrue(burst["duplicate"])
        # different page: a new visit
        other = self.client.post("/api/web-events", json=dict(
            EXT_EVENT, url="https://www.wikipedia.org/wiki/Other")).get_json()
        self.assertFalse(other["duplicate"])
        # same page but outside the window: a new visit
        later = self.client.post("/api/web-events", json=dict(EXT_EVENT, timestamp="2026-10-06T19:31:00")).get_json()
        self.assertFalse(later["duplicate"])
        # same page from another computer: a new visit
        other_pc = self.client.post("/api/web-events", json=dict(
            EXT_EVENT, endpoint_uid="other-pc", computer_name="BROWSER-OTHER")).get_json()
        self.assertFalse(other_pc["duplicate"])
        conn = database.get_connection()
        count = conn.execute("SELECT COUNT(*) FROM web_visits").fetchone()[0]
        conn.close()
        self.assertEqual(count, 4)

    def test_visits_polling_endpoint(self):
        ids = []
        for path in ("/a", "/b", "/c"):
            r = self.client.post("/api/web-events", json=dict(EXT_EVENT, url="https://www.wikipedia.org" + path))
            ids.append(r.get_json()["visit_id"])
        data = self.client.get("/api/visits?after_id=0").get_json()
        self.assertEqual([v["id"] for v in data["visits"]], sorted(ids, reverse=True))
        self.assertEqual(data["last_id"], ids[-1])
        data = self.client.get("/api/visits?after_id=%d" % ids[1]).get_json()
        self.assertEqual([v["id"] for v in data["visits"]], [ids[2]])
        self.assertEqual(data["visits"][0]["sanitized_url"], "https://www.wikipedia.org/c")
        data = self.client.get("/api/visits?after_id=%d" % ids[2]).get_json()
        self.assertEqual(data["visits"], [])
        self.assertEqual(data["last_id"], ids[2])
        self.assertEqual(self.client.get("/api/visits?after_id=0&status=SAFE").get_json()["visits"], [])
        self.assertEqual(len(self.client.get("/api/visits?after_id=0&status=UNKNOWN").get_json()["visits"]), 3)

    def test_status_reports_dev_mode_and_threat_intel(self):
        data = self.client.get("/api/status").get_json()
        self.assertTrue(data["dev_mode"])
        self.assertEqual(data["threat_intel"]["status"], "NOT_CONFIGURED")
        self.assertFalse(data["provider_configured"])
        config.API_KEY = "k"
        self.assertFalse(self.client.get("/api/status").get_json()["dev_mode"])
        self.assertEqual(self.client.post("/api/web-events", json=EXT_EVENT).status_code, 401)
        config.API_KEY = ""
        page = self.client.get("/").data
        self.assertIn(b"Not configured", page)
        self.assertIn(b'id="visits-body"', page)
        # UNKNOWN visits must render with their own badge class (styled distinctly from SAFE)
        self.client.post("/api/web-events", json=EXT_EVENT)
        self.assertIn(b"badge-unknown", self.client.get("/browsing").data)
        self.assertNotIn(b"badge-safe", self.client.get("/browsing").data)


# --------------------------------------------------------------------
# 2. VirusTotal (mocked) verdicts and failures
# --------------------------------------------------------------------
class VirusTotalTests(Phase2Base):
    def lookup(self, domain, *scripted):
        provider, session = vt_provider(*scripted)
        conn = database.get_connection()
        try:
            result = reputation.check_domain(conn, domain, provider)
        finally:
            conn.close()
        return result, session

    def test_safe_verdict(self):
        result, session = self.lookup("safe.example", FakeResponse(200, vt_payload()))
        self.assertEqual(result["status"], "SAFE")
        self.assertEqual(result["source"], "VirusTotal")
        self.assertEqual(session.calls[0]["url"], "https://www.virustotal.com/api/v3/domains/safe.example")
        self.assertEqual(session.calls[0]["headers"]["x-apikey"], FAKE_KEY)

    def test_suspicious_verdicts(self):
        for stats in ({"malicious": 1}, {"malicious": 2}, {"suspicious": 2}, {"malicious": 1, "suspicious": 5}):
            reputation.reset_state()
            result, _ = self.lookup("susp-%d.example" % len(stats), FakeResponse(200, vt_payload(**stats)))
            self.assertEqual(result["status"], "SUSPICIOUS", stats)
        result, _ = self.lookup("one-susp.example", FakeResponse(200, vt_payload(suspicious=1)))
        self.assertEqual(result["status"], "SAFE", "a single suspicious vote is below the threshold")

    def test_malicious_verdict(self):
        result, _ = self.lookup("bad.example", FakeResponse(200, vt_payload(malicious=3)))
        self.assertEqual(result["status"], "MALICIOUS")
        result, _ = self.lookup("worse.example", FakeResponse(200, vt_payload(malicious=20, suspicious=4)))
        self.assertEqual(result["status"], "MALICIOUS")

    def test_no_engines_is_unknown(self):
        result, _ = self.lookup("fresh.example", FakeResponse(200, vt_payload(harmless=0, undetected=0)))
        self.assertEqual(result["status"], "UNKNOWN")

    def test_404_is_unknown_without_cooldown(self):
        config.VT_API_KEY = FAKE_KEY
        result, _ = self.lookup("nobody-knows.example", FakeResponse(404, {"error": {"code": "NotFoundError"}}))
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertEqual(reputation.provider_status()["status"], "ACTIVE")

    def test_401_and_403_never_safe_and_pause_provider(self):
        for code in (401, 403):
            reputation.reset_state()
            config.VT_API_KEY = FAKE_KEY
            provider, session = vt_provider(FakeResponse(code, {"error": {"code": "WrongCredentialsError"}}))
            conn = database.get_connection()
            try:
                first = reputation.check_domain(conn, "auth-%d.example" % code, provider)
                second = reputation.check_domain(conn, "auth-%d-other.example" % code, provider)
            finally:
                conn.close()
            self.assertEqual(first["status"], "UNKNOWN")
            self.assertEqual(second["status"], "UNKNOWN")
            self.assertEqual(len(session.calls), 1, "while paused no further VirusTotal calls are made")
            status = reputation.provider_status()
            self.assertEqual(status["status"], "TEMPORARILY_UNAVAILABLE")
            self.assertIn(str(code), status["detail"])

    def test_429_rate_limit_no_rapid_retry(self):
        config.VT_API_KEY = FAKE_KEY
        provider, session = vt_provider(FakeResponse(429, {"error": {"code": "QuotaExceededError"}}))
        conn = database.get_connection()
        try:
            results = [reputation.check_domain(conn, "rl-%d.example" % i, provider) for i in range(5)]
        finally:
            conn.close()
        self.assertTrue(all(r["status"] == "UNKNOWN" for r in results))
        self.assertEqual(len(session.calls), 1)
        self.assertEqual(reputation.provider_status()["status"], "TEMPORARILY_UNAVAILABLE")

    def test_5xx_timeout_connection_and_malformed_are_unknown(self):
        cases = {
            "server-error.example": FakeResponse(503, raw="<html>upstream down</html>"),
            "timeout.example": requests.Timeout("read timed out"),
            "conn.example": requests.ConnectionError("connection refused"),
            "badjson.example": FakeResponse(200, None, raw="<html>captive portal</html>"),
            "badshape.example": FakeResponse(200, {"data": {"attributes": {}}}),
            "badvalues.example": FakeResponse(200, {"data": {"attributes": {"last_analysis_stats": {"malicious": "x"}}}}),
        }
        for domain, scripted in cases.items():
            reputation.reset_state()
            result, _ = self.lookup(domain, scripted)
            self.assertEqual(result["status"], "UNKNOWN", domain)
            self.assertNotEqual(result["status"], "SAFE")

    def test_provider_recovers_after_cooldown(self):
        config.VT_API_KEY = FAKE_KEY
        provider, session = vt_provider(FakeResponse(503), FakeResponse(200, vt_payload()))
        conn = database.get_connection()
        try:
            self.assertEqual(reputation.check_domain(conn, "r1.example", provider)["status"], "UNKNOWN")
            self.assertEqual(reputation.provider_status()["status"], "TEMPORARILY_UNAVAILABLE")
            reputation._entry("VirusTotal")["unavailable_until"] = datetime.now() - timedelta(seconds=1)
            self.assertEqual(reputation.provider_status()["status"], "ACTIVE")
            self.assertEqual(reputation.check_domain(conn, "r2.example", provider)["status"], "SAFE")
        finally:
            conn.close()
        self.assertEqual(len(session.calls), 2)

    def test_api_key_never_appears_in_results_or_status(self):
        config.VT_API_KEY = FAKE_KEY
        result, _ = self.lookup("leak.example", FakeResponse(401, raw=FAKE_KEY))
        texts = [result["reason"], reputation.provider_status()["detail"]]
        conn = database.get_connection()
        texts.append(str(dict(conn.execute("SELECT * FROM domain_reputation").fetchone())))
        conn.close()
        for text in texts:
            self.assertNotIn(FAKE_KEY, text)
        self.assertNotIn(FAKE_KEY, self.client.get("/").data.decode("utf-8"))
        self.assertNotIn(FAKE_KEY, self.client.get("/api/status").data.decode("utf-8"))

    def test_thresholds_are_deterministic(self):
        self.assertEqual(reputation.interpret_stats(0, 0, 70)["status"], "SAFE")
        self.assertEqual(reputation.interpret_stats(0, 1, 70)["status"], "SAFE")
        self.assertEqual(reputation.interpret_stats(0, 2, 70)["status"], "SUSPICIOUS")
        self.assertEqual(reputation.interpret_stats(1, 0, 70)["status"], "SUSPICIOUS")
        self.assertEqual(reputation.interpret_stats(2, 0, 70)["status"], "SUSPICIOUS")
        self.assertEqual(reputation.interpret_stats(3, 0, 70)["status"], "MALICIOUS")
        self.assertEqual(reputation.interpret_stats(0, 0, 0)["status"], "UNKNOWN")


# --------------------------------------------------------------------
# 3. Cache behaviour
# --------------------------------------------------------------------
class CacheTests(Phase2Base):
    def test_cache_hit_skips_provider(self):
        provider, session = vt_provider(FakeResponse(200, vt_payload()))
        conn = database.get_connection()
        try:
            for _ in range(3):
                self.assertEqual(reputation.check_domain(conn, "hit.example", provider)["status"], "SAFE")
        finally:
            conn.close()
        self.assertEqual(len(session.calls), 1)

    def test_cache_expiry_requeries(self):
        provider, session = vt_provider(FakeResponse(200, vt_payload()), FakeResponse(200, vt_payload(malicious=5)))
        conn = database.get_connection()
        try:
            self.assertEqual(reputation.check_domain(conn, "exp.example", provider)["status"], "SAFE")
            past = (datetime.now() - timedelta(seconds=1)).strftime(reputation.TIME_FORMAT)
            conn.execute("UPDATE domain_reputation SET expires_at = ? WHERE domain = 'exp.example'", (past,))
            conn.commit()
            self.assertEqual(reputation.check_domain(conn, "exp.example", provider)["status"], "MALICIOUS")
        finally:
            conn.close()
        self.assertEqual(len(session.calls), 2)

    def test_ttl_per_status(self):
        self.assertEqual(reputation.ttl_for("SAFE"), timedelta(hours=config.REPUTATION_CACHE_HOURS))
        self.assertEqual(reputation.ttl_for("UNKNOWN"), timedelta(minutes=30))
        self.assertEqual(reputation.ttl_for("SUSPICIOUS"), timedelta(hours=6))
        self.assertEqual(reputation.ttl_for("MALICIOUS"), timedelta(hours=6))
        self.assertLess(reputation.ttl_for("UNKNOWN"), reputation.ttl_for("MALICIOUS"))
        self.assertLess(reputation.ttl_for("MALICIOUS"), reputation.ttl_for("SAFE"))
        provider, _ = vt_provider(FakeResponse(200, vt_payload()), FakeResponse(503))
        conn = database.get_connection()
        try:
            reputation.check_domain(conn, "ttl-safe.example", provider)
            reputation.check_domain(conn, "ttl-unknown.example", provider)
            rows = {r["domain"]: r for r in conn.execute("SELECT * FROM domain_reputation")}
        finally:
            conn.close()
        fmt = reputation.TIME_FORMAT
        safe_ttl = datetime.strptime(rows["ttl-safe.example"]["expires_at"], fmt) - \
            datetime.strptime(rows["ttl-safe.example"]["checked_at"], fmt)
        unknown_ttl = datetime.strptime(rows["ttl-unknown.example"]["expires_at"], fmt) - \
            datetime.strptime(rows["ttl-unknown.example"]["checked_at"], fmt)
        self.assertEqual(safe_ttl, timedelta(hours=config.REPUTATION_CACHE_HOURS))
        self.assertEqual(unknown_ttl, timedelta(minutes=30))


# --------------------------------------------------------------------
# 4. End-to-end through the API: alerts
# --------------------------------------------------------------------
class AlertFlowTests(Phase2Base):
    def alerts(self):
        conn = database.get_connection()
        rows = conn.execute("SELECT * FROM alerts").fetchall()
        conn.close()
        return rows

    def test_malicious_site_creates_alert(self):
        provider, _ = vt_provider(FakeResponse(200, vt_payload(malicious=7)))
        self.use_provider(provider)
        r = self.client.post("/api/web-events", json=dict(EXT_EVENT, domain="evil.example", url="https://evil.example/login"))
        body = r.get_json()
        self.assertEqual(body["reputation"]["status"], "MALICIOUS")
        self.assertIsNotNone(body["alert_id"])
        rows = self.alerts()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["severity"], "HIGH")
        self.assertEqual(rows[0]["domain"], "evil.example")
        status = self.client.get("/api/status").get_json()
        self.assertEqual(status["summary"]["security_status"], "ALERT")
        self.assertEqual(status["threat_intel"]["status"], "ACTIVE")

    def test_suspicious_site_creates_medium_alert(self):
        provider, _ = vt_provider(FakeResponse(200, vt_payload(malicious=1)))
        self.use_provider(provider)
        body = self.client.post("/api/web-events", json=dict(EXT_EVENT, domain="odd.example", url=None)).get_json()
        self.assertEqual(body["reputation"]["status"], "SUSPICIOUS")
        self.assertEqual(self.alerts()[0]["severity"], "MEDIUM")

    def test_safe_site_no_alert(self):
        provider, _ = vt_provider(FakeResponse(200, vt_payload()))
        self.use_provider(provider)
        body = self.client.post("/api/web-events", json=EXT_EVENT).get_json()
        self.assertEqual(body["reputation"]["status"], "SAFE")
        self.assertIsNone(body["alert_id"])
        self.assertEqual(self.alerts(), [])
        self.assertEqual(self.client.get("/api/status").get_json()["summary"]["security_status"], "OK")

    def test_provider_failure_marks_unknown_and_no_alert(self):
        provider, session = vt_provider(FakeResponse(429))
        self.use_provider(provider)
        for path in ("/a", "/b"):
            body = self.client.post("/api/web-events", json=dict(EXT_EVENT, url="https://www.wikipedia.org" + path)).get_json()
            self.assertEqual(body["reputation"]["status"], "UNKNOWN")
            self.assertIsNone(body["alert_id"])
        self.assertEqual(self.alerts(), [])
        self.assertEqual(len(session.calls), 1)
        status = self.client.get("/api/status").get_json()["threat_intel"]
        self.assertEqual(status["status"], "TEMPORARILY_UNAVAILABLE")
        self.assertIn(b"Temporarily unavailable", self.client.get("/").data)


if __name__ == "__main__":
    unittest.main()
