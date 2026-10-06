"""Phase 1 tests - run with:  python -m unittest discover -s tests -v
Uses a temporary database; never touches data/monitoring.db."""
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

_TMP = tempfile.mkdtemp(prefix="monitor_test_")
os.environ["DATABASE_PATH"] = os.path.join(_TMP, "test.db")
os.environ["API_KEY"] = ""
os.environ["VT_API_KEY"] = ""

import config  # noqa: E402
import database  # noqa: E402
from services import reputation  # noqa: E402
from validation import ValidationError, sanitize_url, normalize_domain  # noqa: E402
import app as app_module  # noqa: E402

EVENT = {
    "endpoint_uid": "test-pc-001",
    "computer_name": "PC-ACCOUNTING-01",
    "username": "david",
    "domain": "Example.COM.",
    "url": "https://example.com/page?id=123&token=abc#section",
    "browser": "Chrome 120",
    "timestamp": "2026-10-06T12:00:00",
}


class FakeProvider(object):
    name = "FakeTI"

    def __init__(self, status, fail=False):
        self.status = status
        self.fail = fail
        self.calls = 0

    def lookup(self, domain):
        self.calls += 1
        if self.fail:
            raise RuntimeError("provider down")
        return {"status": self.status, "source": self.name, "reason": "test verdict"}


class AppTests(unittest.TestCase):
    def setUp(self):
        self.client = app_module.app.test_client()
        conn = database.get_connection()
        for table in ("alerts", "web_visits", "domain_reputation", "endpoints"):
            conn.execute("DELETE FROM %s" % table)
        conn.commit()
        conn.close()

    # 1. app starts / 2. database created
    def test_app_starts_and_db_exists(self):
        self.assertEqual(self.client.get("/").status_code, 200)
        self.assertTrue(os.path.exists(config.DATABASE_PATH))
        conn = database.get_connection()
        names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        conn.close()
        self.assertTrue({"endpoints", "web_visits", "domain_reputation", "alerts"} <= names)

    # 3. endpoint registration
    def test_register_endpoint(self):
        r = self.client.post("/api/endpoints/register", json={"endpoint_uid": "pc-1", "computer_name": "PC-1"})
        self.assertEqual(r.status_code, 201)
        self.assertTrue(r.get_json()["ok"])
        self.assertEqual(self.client.get("/endpoints").status_code, 200)
        self.assertIn(b"PC-1", self.client.get("/endpoints").data)

    # 4/5. event submitted, appears on dashboard; 6. no query/fragment stored
    def test_web_event_sanitized_and_shown(self):
        r = self.client.post("/api/web-events", json=EVENT)
        self.assertEqual(r.status_code, 201, r.get_json())
        body = r.get_json()
        self.assertEqual(body["domain"], "example.com")
        self.assertEqual(body["reputation"]["status"], "UNKNOWN")  # no provider configured
        conn = database.get_connection()
        row = conn.execute("SELECT * FROM web_visits").fetchone()
        conn.close()
        self.assertEqual(row["sanitized_url"], "https://example.com/page")
        self.assertNotIn("token", row["sanitized_url"])
        self.assertNotIn("#", row["sanitized_url"])
        self.assertEqual(row["browser"], "Chrome")
        self.assertEqual(row["visited_at"], "2026-10-06 12:00:00")
        page = self.client.get("/").data
        self.assertIn(b"PC-ACCOUNTING-01", page)
        self.assertIn(b"example.com", page)
        self.assertNotIn(b"token=abc", page)
        self.assertIn(b"example.com", self.client.get("/browsing").data)

    # 7. invalid input rejected
    def test_invalid_input_rejected(self):
        bad = [
            dict(EVENT, domain="not a domain"),
            dict(EVENT, domain="192.168.1.1"),
            dict(EVENT, domain="http://example.com/x"),
            dict(EVENT, url="ftp://example.com/file"),
            dict(EVENT, url="https://other.com/page"),
            dict(EVENT, endpoint_uid="bad uid!"),
            dict(EVENT, computer_name="x" * 101),
            dict(EVENT, timestamp="yesterday"),
            {k: v for k, v in EVENT.items() if k != "domain"},
            [],
        ]
        for payload in bad:
            r = self.client.post("/api/web-events", json=payload)
            self.assertEqual(r.status_code, 400, payload)
            self.assertFalse(r.get_json()["ok"])
        r = self.client.post("/api/web-events", data="not json", content_type="text/plain")
        self.assertEqual(r.status_code, 400)

    def test_url_and_domain_helpers(self):
        self.assertEqual(normalize_domain("WWW.Example.com:443."), "www.example.com")
        self.assertEqual(sanitize_url("https://user:pw@example.com/a/b?x=1#f", "example.com"), "https://example.com/a/b")
        self.assertIsNone(sanitize_url(None, "example.com"))
        with self.assertRaises(ValidationError):
            sanitize_url("javascript:alert(1)", "example.com")

    def test_api_key_enforced_when_configured(self):
        config.API_KEY = "secret-123"
        try:
            r = self.client.post("/api/web-events", json=EVENT)
            self.assertEqual(r.status_code, 401)
            r = self.client.post("/api/web-events", json=EVENT, headers={"X-Api-Key": "secret-123"})
            self.assertEqual(r.status_code, 201)
        finally:
            config.API_KEY = ""

    # reputation: cache, failure -> UNKNOWN, malicious -> alert
    def test_reputation_cache_and_failure(self):
        conn = database.get_connection()
        try:
            provider = FakeProvider("SAFE")
            first = reputation.check_domain(conn, "cached.example", provider)
            second = reputation.check_domain(conn, "cached.example", provider)
            self.assertEqual(first["status"], "SAFE")
            self.assertEqual(second, first)
            self.assertEqual(provider.calls, 1, "cached verdict must not re-query the provider")

            broken = FakeProvider("SAFE", fail=True)
            result = reputation.check_domain(conn, "down.example", broken)
            self.assertEqual(result["status"], "UNKNOWN")

            # expired cache entry is re-checked
            old = (datetime.now() - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
            conn.execute("UPDATE domain_reputation SET expires_at = ? WHERE domain = 'cached.example'", (old,))
            conn.commit()
            reputation.check_domain(conn, "cached.example", provider)
            self.assertEqual(provider.calls, 2)
        finally:
            conn.close()

    def test_malicious_domain_creates_one_alert(self):
        original = reputation.build_provider
        reputation.build_provider = lambda: FakeProvider("MALICIOUS")
        try:
            for _ in range(3):
                r = self.client.post("/api/web-events", json=dict(EVENT, domain="bad.example", url=None))
                self.assertEqual(r.status_code, 201)
                self.assertEqual(r.get_json()["reputation"]["status"], "MALICIOUS")
        finally:
            reputation.build_provider = original
        conn = database.get_connection()
        alerts = conn.execute("SELECT * FROM alerts").fetchall()
        conn.close()
        self.assertEqual(len(alerts), 1, "repeat visits inside 24h must not create duplicate alerts")
        self.assertEqual(alerts[0]["severity"], "HIGH")
        self.assertIn("PC-ACCOUNTING-01 visited a website identified as malicious", alerts[0]["reason"])
        page = self.client.get("/alerts").data
        self.assertIn(b"bad.example", page)
        self.assertIn(b"Recommended action", page)
        status = self.client.get("/api/status").get_json()["summary"]
        self.assertEqual(status["security_status"], "ALERT")
        self.assertEqual(status["open_alerts"], 1)
        r = self.client.post("/alerts/%d/close" % alerts[0]["id"])
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self.client.get("/api/status").get_json()["summary"]["open_alerts"], 0)

    def test_retention_deletes_old_visits(self):
        self.client.post("/api/web-events", json=dict(EVENT, timestamp="2020-01-01T10:00:00"))
        self.client.post("/api/web-events", json=dict(EVENT, timestamp=None))
        conn = database.get_connection()
        try:
            self.assertEqual(database.apply_retention(conn, days=30), 1)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM web_visits").fetchone()[0], 1)
            self.assertEqual(database.apply_retention(conn, days=0), 0)  # 0 = keep forever
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
