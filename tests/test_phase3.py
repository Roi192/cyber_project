"""Phase 3 tests: many computers, one central server.

Everything here runs against a TEMPORARY database. The "computers" are
TEST/SIMULATED endpoints identified by test UUIDs - they are not physical
machines. VirusTotal is always mocked (no network, no quota).
Run:  python -m unittest discover -s tests -v
"""
import json
import logging
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

_TMP = tempfile.mkdtemp(prefix="monitor_p3_")
os.environ["DATABASE_PATH"] = os.path.join(_TMP, "test.db")
os.environ["API_KEY"] = ""
os.environ["VT_API_KEY"] = ""

import config  # noqa: E402
import database  # noqa: E402
from services import reputation  # noqa: E402
from validation import is_browser_noise  # noqa: E402
import app as app_module  # noqa: E402

TIME = "%Y-%m-%d %H:%M:%S"
SIMULATED = {  # TEST / SIMULATED endpoints - not physical computers
    "A": {"endpoint_uid": "test-sim-aaaa-0001", "computer_name": "TEST-ACCOUNTING-PC", "username": "Dana", "browser": "Edge"},
    "B": {"endpoint_uid": "test-sim-bbbb-0002", "computer_name": "TEST-RECEPTION-PC", "username": "Sarah", "browser": "Chrome"},
    "C": {"endpoint_uid": "test-sim-cccc-0003", "computer_name": "TEST-WAREHOUSE-PC", "username": "", "browser": "Chrome"},
}


class DomainProvider(object):
    """Mock VirusTotal: evil.example is malicious, everything else is safe."""
    name = "MockVT"

    def __init__(self):
        self.calls = 0

    def lookup(self, domain):
        self.calls += 1
        status = "MALICIOUS" if domain.startswith("evil") else "SAFE"
        return {"status": status, "source": self.name, "reason": "mock verdict"}


def visit(endpoint, domain, path="/", **extra):
    event = {
        "endpoint_uid": endpoint["endpoint_uid"],
        "computer_name": endpoint["computer_name"],
        "username": endpoint["username"],
        "browser": endpoint["browser"],
        "domain": domain,
        "url": "https://%s%s" % (domain, path),
    }
    event.update(extra)
    return event


class Phase3Base(unittest.TestCase):
    def setUp(self):
        self.client = app_module.app.test_client()
        conn = database.get_connection()
        for table in ("alerts", "web_visits", "domain_reputation", "endpoints"):
            conn.execute("DELETE FROM %s" % table)
        conn.commit()
        conn.close()
        reputation.reset_state()
        config.API_KEY = ""
        config.VT_API_KEY = ""
        self._original_build = reputation.build_provider
        self.provider = DomainProvider()
        reputation.build_provider = lambda: self.provider     # never the real VirusTotal

    def tearDown(self):
        reputation.build_provider = self._original_build
        reputation.reset_state()
        config.API_KEY = ""
        config.VT_API_KEY = ""

    def db(self):
        return database.get_connection()

    def count(self, table):
        conn = self.db()
        try:
            return conn.execute("SELECT COUNT(*) FROM %s" % table).fetchone()[0]
        finally:
            conn.close()

    def set_last_seen(self, uid, seconds_ago):
        conn = self.db()
        stamp = (datetime.now() - timedelta(seconds=seconds_ago)).strftime(TIME)
        conn.execute("UPDATE endpoints SET last_seen = ? WHERE endpoint_uid = ?", (stamp, uid))
        conn.commit()
        conn.close()

    def endpoint_rows(self):
        conn = self.db()
        try:
            return [dict(r) for r in conn.execute("SELECT * FROM endpoints ORDER BY id")]
        finally:
            conn.close()


# --------------------------------------------------------------------
# enrollment / identity
# --------------------------------------------------------------------
class EnrollmentTests(Phase3Base):
    def test_registration_stores_name_user_browser_last_seen(self):
        r = self.client.post("/api/endpoints/register", json=SIMULATED["A"])
        self.assertEqual(r.status_code, 201, r.get_json())
        row = self.endpoint_rows()[0]
        self.assertEqual((row["endpoint_uid"], row["computer_name"], row["username"], row["browser"]),
                         ("test-sim-aaaa-0001", "TEST-ACCOUNTING-PC", "Dana", "Edge"))
        self.assertIsNotNone(row["last_seen"])

    def test_label_change_updates_same_endpoint_no_duplicate(self):
        self.client.post("/api/endpoints/register", json=SIMULATED["A"])
        renamed = dict(SIMULATED["A"], computer_name="ACCOUNTING-PC-01", username="Dana K.")
        self.client.post("/api/endpoints/register", json=renamed)
        rows = self.endpoint_rows()
        self.assertEqual(len(rows), 1, "same UUID must stay a single endpoint")
        self.assertEqual(rows[0]["computer_name"], "ACCOUNTING-PC-01")
        self.assertEqual(rows[0]["username"], "Dana K.")

    def test_label_change_via_web_event_also_updates_same_endpoint(self):
        self.client.post("/api/web-events", json=visit(SIMULATED["A"], "example.com"))
        renamed = dict(SIMULATED["A"], computer_name="RENAMED-PC")
        self.client.post("/api/web-events", json=visit(renamed, "example.org"))
        rows = self.endpoint_rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["computer_name"], "RENAMED-PC")

    def test_username_can_be_cleared_and_absent_username_keeps_it(self):
        self.client.post("/api/endpoints/register", json=SIMULATED["A"])
        no_key = {k: v for k, v in SIMULATED["A"].items() if k != "username"}
        self.client.post("/api/heartbeat", json=no_key)                       # username absent -> kept
        self.assertEqual(self.endpoint_rows()[0]["username"], "Dana")
        self.client.post("/api/heartbeat", json=dict(SIMULATED["A"], username=""))   # explicit empty -> cleared
        self.assertIsNone(self.endpoint_rows()[0]["username"])

    def test_different_uuids_are_separate_endpoints(self):
        for key in ("A", "B", "C"):
            self.client.post("/api/endpoints/register", json=SIMULATED[key])
        rows = self.endpoint_rows()
        self.assertEqual(len(rows), 3)
        self.assertEqual(len({r["endpoint_uid"] for r in rows}), 3)
        # same computer name on two different installations is still two endpoints
        twin = dict(SIMULATED["B"], endpoint_uid="test-sim-dddd-0004")
        self.client.post("/api/endpoints/register", json=twin)
        self.assertEqual(self.count("endpoints"), 4)

    def test_same_uuid_many_times_is_one_endpoint(self):
        for _ in range(5):
            self.client.post("/api/endpoints/register", json=SIMULATED["A"])
            self.client.post("/api/heartbeat", json=SIMULATED["A"])
            self.client.post("/api/web-events", json=visit(SIMULATED["A"], "example.com"))
        self.assertEqual(self.count("endpoints"), 1)

    def test_invalid_endpoint_input_rejected(self):
        good = SIMULATED["A"]
        bad = [
            dict(good, endpoint_uid="bad uid!"),
            dict(good, endpoint_uid=""),
            dict(good, endpoint_uid="x" * 65),
            dict(good, endpoint_uid=12345),
            {k: v for k, v in good.items() if k != "endpoint_uid"},
            {k: v for k, v in good.items() if k != "computer_name"},
            dict(good, computer_name="x" * 101),
            dict(good, computer_name="line\nbreak"),
            dict(good, username="u" * 101),
            dict(good, username=["list"]),
            dict(good, browser={"nested": "object"}),
            [],
            "just a string",
        ]
        for path in ("/api/endpoints/register", "/api/heartbeat"):
            for payload in bad:
                r = self.client.post(path, json=payload)
                self.assertEqual(r.status_code, 400, (path, payload))
                self.assertFalse(r.get_json()["ok"])
            r = self.client.post(path, data="not json", content_type="text/plain")
            self.assertEqual(r.status_code, 400)
        for payload in (visit(dict(good, endpoint_uid="bad uid!"), "example.com"),
                        visit(good, "not a domain"), visit(good, "192.168.1.1")):
            self.assertEqual(self.client.post("/api/web-events", json=payload).status_code, 400)
        self.assertEqual(self.count("endpoints"), 0, "rejected requests must not create endpoints")

    def test_unknown_browser_does_not_overwrite_known_one(self):
        self.client.post("/api/endpoints/register", json=SIMULATED["A"])
        self.client.post("/api/web-events", json=visit(SIMULATED["A"], "example.com", browser="SomethingElse"))
        self.assertEqual(self.endpoint_rows()[0]["browser"], "Edge")


# --------------------------------------------------------------------
# API authentication
# --------------------------------------------------------------------
class AuthTests(Phase3Base):
    KEY = "test-org-key-0123456789"

    def posts(self, headers=None):
        a = SIMULATED["A"]
        return [
            self.client.post("/api/endpoints/register", json=a, headers=headers),
            self.client.post("/api/heartbeat", json=a, headers=headers),
            self.client.post("/api/web-events", json=visit(a, "example.com"), headers=headers),
            self.client.get("/api/ping", headers=headers),
        ]

    def test_auth_success_on_every_endpoint_route(self):
        config.API_KEY = self.KEY
        for r in self.posts({"X-Api-Key": self.KEY}):
            self.assertIn(r.status_code, (200, 201), r.get_json())

    def test_auth_failure_on_every_endpoint_route(self):
        config.API_KEY = self.KEY
        for headers in (None, {"X-Api-Key": ""}, {"X-Api-Key": "wrong"}, {"X-Api-Key": self.KEY + "x"},
                        {"X-Api-Key": self.KEY[:-1]}):
            for r in self.posts(headers):
                self.assertEqual(r.status_code, 401, headers)
                self.assertFalse(r.get_json()["ok"])
        self.assertEqual(self.count("endpoints"), 0, "unauthenticated requests must not write anything")
        self.assertEqual(self.count("web_visits"), 0)

    def test_dev_mode_allows_empty_key(self):
        config.API_KEY = ""
        for r in self.posts():
            self.assertIn(r.status_code, (200, 201))
        self.assertTrue(self.client.get("/api/status").get_json()["dev_mode"])

    def test_dashboard_reads_stay_open_when_key_is_set(self):
        config.API_KEY = self.KEY
        for path in ("/", "/browsing", "/alerts", "/endpoints", "/api/status", "/api/visits", "/api/endpoints"):
            self.assertEqual(self.client.get(path).status_code, 200, path)
        self.assertFalse(self.client.get("/api/status").get_json()["dev_mode"])

    def test_ping_changes_nothing(self):
        before = (self.count("endpoints"), self.count("web_visits"), self.count("alerts"), self.count("domain_reputation"))
        r = self.client.get("/api/ping")
        self.assertEqual(r.get_json()["service"], "website-monitor")
        after = (self.count("endpoints"), self.count("web_visits"), self.count("alerts"), self.count("domain_reputation"))
        self.assertEqual(before, after)

    def test_api_key_never_in_logs_responses_or_database(self):
        key = "SUPER-SECRET-KEY-d41d8cd98f00b204"
        config.API_KEY = key
        records = []

        class Capture(logging.Handler):
            def emit(self, record):
                records.append(self.format(record))

        handler = Capture()
        root = logging.getLogger()
        old_level = root.level
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)
        bodies = []
        try:
            for headers in ({"X-Api-Key": key}, {"X-Api-Key": "wrong-" + key}, None):
                for r in self.posts(headers):
                    bodies.append(r.data)
            for path in ("/", "/browsing", "/alerts", "/endpoints", "/api/status", "/api/visits", "/api/endpoints"):
                bodies.append(self.client.get(path, headers={"X-Api-Key": key}).data)
        finally:
            root.removeHandler(handler)
            root.setLevel(old_level)
        needle = key.encode("utf-8")
        for body in bodies:
            self.assertNotIn(needle, body)
        for line in records:
            self.assertNotIn(key, line)
        with open(config.DATABASE_PATH, "rb") as fh:
            self.assertNotIn(needle, fh.read(), "the API key must never be stored in SQLite")
        # and it is not in any source file that gets committed
        for folder in (ROOT, os.path.join(ROOT, "browser_extension")):
            for name in os.listdir(folder):
                if name.endswith((".py", ".js", ".html", ".json", ".md")):
                    with open(os.path.join(folder, name), "rb") as fh:
                        self.assertNotIn(needle, fh.read())


# --------------------------------------------------------------------
# heartbeat + ONLINE / OFFLINE
# --------------------------------------------------------------------
class HeartbeatTests(Phase3Base):
    def test_heartbeat_updates_last_seen_and_reports_online(self):
        self.client.post("/api/endpoints/register", json=SIMULATED["A"])
        self.set_last_seen("test-sim-aaaa-0001", 3600)
        old = self.endpoint_rows()[0]["last_seen"]
        r = self.client.post("/api/heartbeat", json=SIMULATED["A"])
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["status"], "ONLINE")
        new = self.endpoint_rows()[0]["last_seen"]
        self.assertGreater(new, old)
        self.assertLess((datetime.now() - datetime.strptime(new, TIME)).total_seconds(), 5)

    def test_heartbeat_creates_no_history_rows(self):
        self.client.post("/api/endpoints/register", json=SIMULATED["A"])
        conn = self.db()
        tables_before = sorted(r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'"))
        conn.close()
        for _ in range(25):
            self.assertEqual(self.client.post("/api/heartbeat", json=SIMULATED["A"]).status_code, 200)
        self.assertEqual(self.count("endpoints"), 1)
        self.assertEqual(self.count("web_visits"), 0)
        self.assertEqual(self.count("alerts"), 0)
        conn = self.db()
        tables_after = sorted(r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'"))
        conn.close()
        self.assertEqual(tables_before, tables_after, "no heartbeat history table may exist")

    def test_heartbeat_of_unregistered_endpoint_enrolls_it(self):
        self.assertEqual(self.client.post("/api/heartbeat", json=SIMULATED["B"]).status_code, 200)
        self.assertEqual(self.endpoint_rows()[0]["computer_name"], "TEST-RECEPTION-PC")

    def test_online_calculation(self):
        self.client.post("/api/heartbeat", json=SIMULATED["A"])
        self.set_last_seen("test-sim-aaaa-0001", 60)                  # one beat ago
        rows = {r["endpoint_uid"]: r for r in self.listed()}
        self.assertEqual(rows["test-sim-aaaa-0001"]["status"], "ONLINE")
        self.assertEqual(self.client.get("/api/status").get_json()["summary"]["online_now"], 1)

    def test_offline_calculation(self):
        self.client.post("/api/heartbeat", json=SIMULATED["A"])
        self.set_last_seen("test-sim-aaaa-0001", database.ONLINE_WINDOW_SECONDS + 120)
        rows = {r["endpoint_uid"]: r for r in self.listed()}
        self.assertEqual(rows["test-sim-aaaa-0001"]["status"], "OFFLINE")
        self.assertEqual(self.client.get("/api/status").get_json()["summary"]["online_now"], 0)
        self.assertIn(b"Offline", self.client.get("/endpoints").data)

    def test_online_window_boundary(self):
        now = datetime(2026, 10, 7, 12, 0, 0)
        window = database.ONLINE_WINDOW_SECONDS
        self.assertEqual(window, 180)
        at = lambda secs: (now - timedelta(seconds=secs)).strftime(TIME)  # noqa: E731
        self.assertEqual(database.endpoint_status(at(0), now), "ONLINE")
        self.assertEqual(database.endpoint_status(at(window), now), "ONLINE")
        self.assertEqual(database.endpoint_status(at(window + 1), now), "OFFLINE")
        self.assertEqual(database.endpoint_status(None, now), "OFFLINE")
        self.assertEqual(database.endpoint_status("garbage", now), "OFFLINE")
        self.assertEqual(database.last_seen_label(now.strftime(TIME), now), "12:00")
        self.assertEqual(database.last_seen_label("2026-10-05 18:22:00", now), "05 Oct 18:22")

    def listed(self):
        conn = self.db()
        try:
            return database.list_endpoints(conn)
        finally:
            conn.close()


# --------------------------------------------------------------------
# several computers on one server
# --------------------------------------------------------------------
class MultiEndpointTests(Phase3Base):
    def populate(self):
        a, b, c = SIMULATED["A"], SIMULATED["B"], SIMULATED["C"]
        self.client.post("/api/web-events", json=visit(a, "example.com", "/one"))
        self.client.post("/api/web-events", json=visit(a, "evil.example", "/login"))
        self.client.post("/api/web-events", json=visit(b, "example.org"))
        self.client.post("/api/heartbeat", json=c)

    def test_malicious_visit_is_associated_with_the_right_endpoint(self):
        self.populate()
        conn = self.db()
        alert = conn.execute("SELECT a.*, e.endpoint_uid, e.computer_name FROM alerts a "
                             "JOIN endpoints e ON e.id = a.endpoint_id").fetchall()
        visit_row = conn.execute("SELECT v.domain, v.reputation_status, e.endpoint_uid FROM web_visits v "
                                 "JOIN endpoints e ON e.id = v.endpoint_id WHERE v.domain = 'evil.example'").fetchone()
        conn.close()
        self.assertEqual(len(alert), 1)
        self.assertEqual(alert[0]["endpoint_uid"], "test-sim-aaaa-0001")
        self.assertEqual(alert[0]["computer_name"], "TEST-ACCOUNTING-PC")
        self.assertEqual(visit_row["endpoint_uid"], "test-sim-aaaa-0001")
        self.assertEqual(visit_row["reputation_status"], "MALICIOUS")
        page = self.client.get("/alerts").data
        self.assertIn(b"TEST-ACCOUNTING-PC", page)
        self.assertNotIn(b"TEST-RECEPTION-PC", page)

    def test_same_domain_from_two_computers_alerts_each_computer(self):
        a, b = SIMULATED["A"], SIMULATED["B"]
        self.client.post("/api/web-events", json=visit(a, "evil.example"))
        self.client.post("/api/web-events", json=visit(b, "evil.example"))
        self.assertEqual(self.count("alerts"), 2)
        self.assertEqual(self.provider.calls, 1, "the domain cache is shared, VirusTotal is asked once")

    def test_dashboard_counts_across_computers(self):
        self.populate()
        summary = self.client.get("/api/status").get_json()["summary"]
        self.assertEqual(summary["computers"], 3)
        self.assertEqual(summary["online_now"], 3)
        self.assertEqual(summary["visits_today"], 3)
        self.assertEqual(summary["threats_today"], 1)
        self.assertEqual(summary["open_alerts"], 1)
        self.assertEqual(summary["security_status"], "ALERT")
        self.set_last_seen("test-sim-cccc-0003", 3600)
        self.assertEqual(self.client.get("/api/status").get_json()["summary"]["online_now"], 2)
        page = self.client.get("/").data
        for label in (b"Monitored computers", b"Online now", b"Websites visited today", b"Threats detected today"):
            self.assertIn(label, page)

    def test_websites_and_threats_today_per_endpoint(self):
        self.populate()
        data = self.client.get("/api/endpoints").get_json()["endpoints"]
        by_name = {e["computer_name"]: e for e in data}
        self.assertEqual((by_name["TEST-ACCOUNTING-PC"]["websites_today"], by_name["TEST-ACCOUNTING-PC"]["threats_today"]), (2, 1))
        self.assertEqual((by_name["TEST-RECEPTION-PC"]["websites_today"], by_name["TEST-RECEPTION-PC"]["threats_today"]), (1, 0))
        self.assertEqual((by_name["TEST-WAREHOUSE-PC"]["websites_today"], by_name["TEST-WAREHOUSE-PC"]["threats_today"]), (0, 0))
        self.assertEqual(by_name["TEST-ACCOUNTING-PC"]["browser"], "Edge")
        self.assertEqual(by_name["TEST-ACCOUNTING-PC"]["status"], "ONLINE")

    def test_visits_on_other_days_do_not_count_as_today(self):
        a = SIMULATED["A"]
        self.client.post("/api/web-events", json=visit(a, "example.com", timestamp="2020-01-01T10:00:00"))
        self.client.post("/api/web-events", json=visit(a, "example.org"))
        row = self.client.get("/api/endpoints").get_json()["endpoints"][0]
        self.assertEqual(row["websites_today"], 1)

    def test_endpoints_page_columns_and_uuid_only_in_technical_details(self):
        self.populate()
        html = self.client.get("/endpoints").get_data(as_text=True)
        # Phase 3.5 renamed the last column from "Threats today" to "Security issues today"
        for header in ("Computer", "User", "Browser", "Status", "Last seen", "Websites today", "Security issues today"):
            self.assertIn("<th>%s</th>" % header, html)
        for name in ("TEST-ACCOUNTING-PC", "TEST-RECEPTION-PC", "TEST-WAREHOUSE-PC", "Dana", "Sarah", "Online"):
            self.assertIn(name, html)
        uid = SIMULATED["A"]["endpoint_uid"]
        self.assertIn(uid, html)
        outside_details = re.sub(r"<details.*?</details>", "", html, flags=re.S)
        self.assertNotIn(uid, outside_details, "the UUID is only shown inside the technical-details view")
        api = self.client.get("/api/endpoints").get_data(as_text=True)
        self.assertNotIn("test-sim-", api)
        self.assertNotIn("endpoint_uid", api)

    def test_online_endpoints_are_listed_first(self):
        self.populate()
        self.set_last_seen("test-sim-aaaa-0001", 3600)
        names = [e["computer_name"] for e in self.client.get("/api/endpoints").get_json()["endpoints"]]
        self.assertEqual(names[-1], "TEST-ACCOUNTING-PC")


# --------------------------------------------------------------------
# browser internal noise
# --------------------------------------------------------------------
class NoiseFilterTests(Phase3Base):
    def test_edge_new_tab_page_is_ignored_but_endpoint_stays_alive(self):
        a = SIMULATED["A"]
        r = self.client.post("/api/web-events", json=visit(a, "ntp.msn.com", "/edge/ntp"))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["ignored"], "browser_internal_page")
        self.assertEqual(self.count("web_visits"), 0)
        self.assertEqual(self.count("domain_reputation"), 0, "no reputation lookup for browser noise")
        self.assertEqual(self.provider.calls, 0)
        self.assertEqual(self.count("endpoints"), 1)
        for variant in ("/edge/ntp/", ):
            self.client.post("/api/web-events", json=visit(a, "ntp.msn.com", variant))
        self.assertEqual(self.count("web_visits"), 0)
        # the query string never matters (it is stripped before the check)
        self.client.post("/api/web-events", json=dict(visit(a, "ntp.msn.com"), url="https://ntp.msn.com/edge/ntp?ocid=x&locale=en"))
        self.assertEqual(self.count("web_visits"), 0)

    def test_normal_msn_browsing_is_not_filtered(self):
        a = SIMULATED["A"]
        for domain, path in (("www.msn.com", "/en-us/news"), ("msn.com", "/"), ("ntp.msn.com", "/other"),
                             ("ntp.msn.com", "/edge/ntp/extra"), ("www.msn.com", "/edge/ntp")):
            r = self.client.post("/api/web-events", json=visit(a, domain, path))
            self.assertEqual(r.status_code, 201, (domain, path))
            self.assertNotIn("ignored", r.get_json())
        self.assertEqual(self.count("web_visits"), 5)

    def test_noise_helper_needs_exact_host_and_path(self):
        self.assertTrue(is_browser_noise("ntp.msn.com", "https://ntp.msn.com/edge/ntp"))
        self.assertFalse(is_browser_noise("ntp.msn.com", None), "without a URL nothing is treated as noise")
        self.assertFalse(is_browser_noise("msn.com", "https://msn.com/edge/ntp"))
        self.assertFalse(is_browser_noise("www.msn.com", "https://www.msn.com/"))


# --------------------------------------------------------------------
# Phase 2 behaviour must still work
# --------------------------------------------------------------------
class Phase2StillWorksTests(Phase3Base):
    def test_browsing_flow_unchanged(self):
        a = SIMULATED["A"]
        r = self.client.post("/api/web-events", json=dict(
            visit(a, "www.wikipedia.org", "/wiki/Main_Page"),
            url="https://www.wikipedia.org/wiki/Main_Page?search=secret#frag", timestamp="2026-10-06T12:00:00"))
        self.assertEqual(r.status_code, 201)
        body = r.get_json()
        self.assertEqual(body["reputation"]["status"], "SAFE")
        self.assertFalse(body["duplicate"])
        conn = self.db()
        row = conn.execute("SELECT * FROM web_visits").fetchone()
        conn.close()
        self.assertEqual(row["sanitized_url"], "https://www.wikipedia.org/wiki/Main_Page")
        self.assertEqual(row["visited_at"], "2026-10-06 12:00:00")
        self.assertIn(b"www.wikipedia.org", self.client.get("/browsing").data)
        self.assertNotIn(b"secret", self.client.get("/browsing").data)
        self.assertEqual(len(self.client.get("/api/visits?after_id=0").get_json()["visits"]), 1)
        again = self.client.post("/api/web-events", json=dict(
            visit(a, "www.wikipedia.org", "/wiki/Main_Page"), timestamp="2026-10-06T12:00:03")).get_json()
        self.assertTrue(again["duplicate"])

    def test_provider_failure_still_unknown_never_safe(self):
        class Rate429(object):
            name = "MockVT"

            def lookup(self, domain):
                raise reputation.ProviderError("HTTP 429 (rate limited)", 15)

        self.provider = Rate429()
        reputation.build_provider = lambda: self.provider
        body = self.client.post("/api/web-events", json=visit(SIMULATED["A"], "example.com")).get_json()
        self.assertEqual(body["reputation"]["status"], "UNKNOWN")
        self.assertIsNone(body["alert_id"])
        self.assertEqual(self.count("alerts"), 0)


# --------------------------------------------------------------------
# schema migration from the Phase 2 database
# --------------------------------------------------------------------
class MigrationTests(unittest.TestCase):
    def test_phase2_database_gets_browser_column_and_keeps_rows(self):
        path = os.path.join(tempfile.mkdtemp(prefix="monitor_mig_"), "old.db")
        conn = sqlite3.connect(path)
        conn.executescript(
            "CREATE TABLE endpoints (id INTEGER PRIMARY KEY AUTOINCREMENT, endpoint_uid TEXT NOT NULL UNIQUE,"
            " computer_name TEXT NOT NULL, username TEXT, last_seen TEXT NOT NULL);"
            "INSERT INTO endpoints (endpoint_uid, computer_name, username, last_seen)"
            " VALUES ('old-uid-1', 'OLD-PC', 'Old User', '2026-10-06 19:00:00');")
        conn.commit()
        conn.close()
        database.init_db(path)
        database.init_db(path)                       # idempotent
        conn = database.get_connection(path)
        columns = [r["name"] for r in conn.execute("PRAGMA table_info(endpoints)")]
        row = dict(conn.execute("SELECT * FROM endpoints").fetchone())
        row_count = conn.execute("SELECT COUNT(*) FROM endpoints").fetchone()[0]
        conn.close()
        self.assertEqual(columns.count("browser"), 1)
        self.assertEqual(row_count, 1)
        self.assertEqual((row["computer_name"], row["username"], row["browser"]), ("OLD-PC", "Old User", None))


# --------------------------------------------------------------------
# extension: permissions, no hard-coded addresses, URL validation
# --------------------------------------------------------------------
EXT = os.path.join(ROOT, "browser_extension")


class ExtensionStaticTests(unittest.TestCase):
    def read(self, name):
        with open(os.path.join(EXT, name), encoding="utf-8") as fh:
            return fh.read()

    def test_manifest_permissions_are_minimal(self):
        manifest = json.loads(self.read("manifest.json"))
        self.assertEqual(manifest["manifest_version"], 3)
        self.assertEqual(sorted(manifest["permissions"]), ["alarms", "storage", "webNavigation"])
        for forbidden in ("tabs", "history", "cookies", "webRequest", "activeTab", "scripting", "<all_urls>"):
            self.assertNotIn(forbidden, manifest["permissions"])
        self.assertEqual(sorted(manifest["host_permissions"]), ["http://127.0.0.1:5002/*", "http://localhost:5002/*"])
        self.assertEqual(sorted(manifest["optional_host_permissions"]), ["http://*/*", "https://*/*"])
        self.assertNotIn("content_scripts", manifest)

    def test_no_hard_coded_lan_address_or_secret_in_extension(self):
        for name in ("background.js", "common.js", "options.js", "options.html", "manifest.json"):
            text = self.read(name)
            self.assertIsNone(re.search(r"\b(192\.168|10\.\d{1,3})\.\d{1,3}\.\d{1,3}", text.replace("192.168.1.50", "")), name)
            self.assertNotIn("VT_API_KEY", text)
        self.assertNotIn("api_key:", self.read("background.js").replace("cfg.api_key", ""))

    def test_options_validate_before_saving_and_have_test_button(self):
        js = self.read("options.js")
        html = self.read("options.html")
        self.assertIn("normalizeServerUrl", js)
        self.assertIn('id="test"', html)
        self.assertIn("/api/ping", js)
        self.assertIn("/api/endpoints/register", js)
        self.assertIn('type="password"', html)

    def test_background_uses_heartbeat_alarm_and_noise_filter(self):
        js = self.read("background.js")
        self.assertIn("chrome.alarms", js)
        self.assertIn("/api/heartbeat", js)
        self.assertIn("isBrowserNoise", js)
        self.assertIn("frameId !== 0", js)


NODE = shutil.which("node")


@unittest.skipUnless(NODE, "Node.js is not installed - the extension helper checks are skipped")
class ExtensionHelperTests(unittest.TestCase):
    """Runs the extension's real common.js under Node (only for testing; nothing in the project needs Node)."""

    def js(self, expression):
        env = dict(os.environ, COMMON_JS=os.path.join(EXT, "common.js"))
        script = "const c=require(process.env.COMMON_JS); console.log(JSON.stringify(%s));" % expression
        out = subprocess.check_output([NODE, "-e", script], env=env, universal_newlines=True)
        return json.loads(out)

    def test_server_url_validation(self):
        good = {
            "http://127.0.0.1:5002": "http://127.0.0.1:5002",
            "http://192.168.1.50:5002/": "http://192.168.1.50:5002",
            "https://monitor.example.com//": "https://monitor.example.com",
            "  HTTP://Server:5002  ": "http://server:5002",
            "http://192.168.1.50:5002/?x=1#y": "http://192.168.1.50:5002",
            "http://srv:5002/sub/path/": "http://srv:5002/sub/path",
        }
        for given, expected in good.items():
            result = self.js("c.normalizeServerUrl(%s)" % json.dumps(given))
            self.assertTrue(result["ok"], given)
            self.assertEqual(result["url"], expected, given)
            self.assertTrue(result["pattern"].endswith("/*"))
            self.assertFalse(result["pattern"].startswith("file"))
        for bad in ("file:///C:/secret.txt", "javascript:alert(1)", "data:text/html,hi", "chrome://extensions",
                    "edge://settings", "ftp://host", "http://user:pw@host:5002", "localhost:5002",
                    "192.168.1.50:5002", "", "   ", "http://", "not a url", "chrome-extension://abc/x.html"):
            result = self.js("c.normalizeServerUrl(%s)" % json.dumps(bad))
            self.assertFalse(result["ok"], bad)
            self.assertTrue(result["error"])
        self.assertEqual(self.js("c.normalizeServerUrl(null).ok"), False)

    def test_extension_noise_filter_matches_server_rule(self):
        self.assertTrue(self.js('c.isBrowserNoise("ntp.msn.com", "/edge/ntp")'))
        self.assertTrue(self.js('c.isBrowserNoise("ntp.msn.com", "/edge/ntp/")'))
        self.assertFalse(self.js('c.isBrowserNoise("www.msn.com", "/en-us/news")'))
        self.assertFalse(self.js('c.isBrowserNoise("msn.com", "/")'))
        self.assertFalse(self.js('c.isBrowserNoise("ntp.msn.com", "/other")'))

    def test_extension_sanitization(self):
        clean = self.js('c.sanitizeNavigation("https://User:pw@Example.com:8443/a/b?token=1#frag")')
        self.assertEqual(clean, {"domain": "example.com", "path": "/a/b", "url": "https://example.com/a/b"})
        for blocked in ("chrome://newtab", "edge://settings", "file:///c:/x", "about:blank",
                        "chrome-extension://abc/page.html", "http://192.168.1.5/x", "http://intranet/x"):
            self.assertIsNone(self.js("c.sanitizeNavigation(%s)" % json.dumps(blocked)), blocked)


if __name__ == "__main__":
    unittest.main()
