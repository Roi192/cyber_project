"""Phase 3.5 tests: truthful security status, reputation coverage, business wording,
archive, search, empty states and the compact DEV MODE warning.

Temporary database only; VirusTotal is never called (provider states are set
directly or seeded). Run:  python -m unittest discover -s tests -v
"""
import itertools
import os
import re
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime, timedelta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

_TMP = tempfile.mkdtemp(prefix="monitor_p35_")
os.environ["DATABASE_PATH"] = os.path.join(_TMP, "test.db")
os.environ["API_KEY"] = ""
os.environ["VT_API_KEY"] = ""

import config  # noqa: E402
import database  # noqa: E402
import overview  # noqa: E402
from services import reputation  # noqa: E402
import app as app_module  # noqa: E402

FAKE_KEY = "test-key-not-real-0001"
TIME = "%Y-%m-%d %H:%M:%S"

TI_ACTIVE = {"status": "ACTIVE", "provider": "VirusTotal", "summary": "ok", "detail": "ok"}
TI_NONE = {"status": "NOT_CONFIGURED", "provider": None, "summary": "none", "detail": "none"}
TI_DOWN = {"status": "TEMPORARILY_UNAVAILABLE", "provider": "VirusTotal", "summary": "down", "detail": "HTTP 429"}


def summ(**kw):
    s = {"computers": 2, "online_now": 2, "visits_today": 10, "evaluated_today": 10, "unchecked_today": 0,
         "threats_today": 0, "open_alerts": 0, "open_high": 0, "open_medium": 0}
    s.update(kw)
    return s


def alert(severity="HIGH", computer="ACCT-PC", domain="evil.example"):
    return {"id": 1, "severity": severity, "computer_name": computer, "username": None, "domain": domain,
            "created_at": "2026-10-07 10:00:00"}


# --------------------------------------------------------------------
# the decision hierarchy (pure logic, no database)
# --------------------------------------------------------------------
class SecurityStatusLogicTests(unittest.TestCase):
    def test_unknown_alone_never_produces_all_clear(self):
        v = overview.build_overview(summ(evaluated_today=0), TI_ACTIVE, [], [])
        self.assertEqual(v["status"], "LIMITED")
        self.assertEqual(v["title"], "Limited visibility")
        self.assertNotEqual(v["title"], "All clear")
        self.assertIn("could not currently be verified", v["message"])
        self.assertEqual(v["coverage"]["percent"], 0)

    def test_provider_unavailable_is_limited_even_with_full_coverage(self):
        v = overview.build_overview(summ(), TI_DOWN, [], [])
        self.assertEqual(v["status"], "LIMITED")

    def test_provider_rate_limited_or_in_cooldown_is_limited(self):
        # the provider reports rate limiting / cooldown as TEMPORARILY_UNAVAILABLE ("Limited" to users)
        v = overview.build_overview(summ(visits_today=3, evaluated_today=3), TI_DOWN, [], [])
        self.assertEqual((v["status"], v["ti"]["label"]), ("LIMITED", "Limited"))

    def test_unconfigured_provider_is_limited(self):
        v = overview.build_overview(summ(), TI_NONE, [], [])
        self.assertEqual(v["status"], "LIMITED")
        self.assertIn("not set up", v["message"])
        self.assertEqual(v["ti"]["label"], "Not configured")

    def test_open_malicious_alert_is_threat_detected(self):
        v = overview.build_overview(summ(open_alerts=1, open_high=1), TI_ACTIVE, [alert("HIGH")], [])
        self.assertEqual((v["status"], v["title"]), ("ALERT", "Threat detected"))
        self.assertIn("A dangerous website was detected on one of your monitored computers", v["message"])
        self.assertIn("ACCT-PC visited evil.example", v["affected"])
        self.assertEqual(v["action"]["url"], "/alerts")

    def test_open_suspicious_alert_is_attention_required(self):
        v = overview.build_overview(summ(open_alerts=1, open_medium=1), TI_ACTIVE, [alert("MEDIUM", domain="odd.example")], [])
        self.assertEqual((v["status"], v["title"]), ("WARNING", "Attention required"))
        self.assertEqual(v["message"], "A suspicious website visit requires review.")
        self.assertIn("odd.example", v["affected"])

    def test_malicious_beats_suspicious_and_beats_limited(self):
        both = overview.build_overview(summ(open_alerts=2, open_high=1, open_medium=1), TI_DOWN,
                                       [alert("HIGH"), alert("MEDIUM", domain="odd.example")], [])
        self.assertEqual(both["status"], "ALERT")
        self.assertEqual(both["affected"], "ACCT-PC visited evil.example.", "the headline names the dangerous alert")
        self.assertIn("Needs review: ACCT-PC visited odd.example.", [i["text"] for i in both["attention"]])
        two_dangerous = overview.build_overview(summ(open_alerts=2, open_high=2), TI_ACTIVE,
                                                [alert("HIGH"), alert("HIGH", domain="evil2.example")], [])
        self.assertIn("and 1 more open alert", two_dangerous["affected"])
        limited_and_suspicious = overview.build_overview(summ(open_alerts=1, open_medium=1), TI_NONE, [alert("MEDIUM")], [])
        self.assertEqual(limited_and_suspicious["status"], "WARNING")

    def test_healthy_evaluated_traffic_without_alerts_is_all_clear(self):
        v = overview.build_overview(summ(), TI_ACTIVE, [], [])
        self.assertEqual((v["status"], v["title"]), ("OK", "All clear"))
        self.assertEqual(v["coverage_line"], "All 10 website visits today were checked.")
        self.assertEqual(v["attention"], [])

    def test_zero_visits_today_uses_neutral_wording(self):
        v = overview.build_overview(summ(visits_today=0, evaluated_today=0), TI_ACTIVE, [], [])
        self.assertEqual(v["coverage_line"], "No browsing activity yet today.")
        self.assertIsNone(v["coverage"]["percent"])
        self.assertEqual(v["status"], "OK")          # service works and nothing to evaluate: not a coverage problem
        self.assertNotIn("100", v["coverage_line"])

    def test_coverage_calculation(self):
        c = overview.coverage(summ(visits_today=14, evaluated_today=12))
        self.assertEqual((c["total"], c["evaluated"], c["unchecked"], c["percent"]), (14, 12, 2, 85))
        self.assertEqual(overview.coverage(summ(visits_today=200, evaluated_today=199))["percent"], 99,
                         "one unchecked visit must never round up to 100%")
        self.assertEqual(overview.coverage(summ(visits_today=4, evaluated_today=4))["percent"], 100)
        self.assertEqual(overview.coverage(summ(visits_today=5, evaluated_today=0))["percent"], 0)

    def test_zero_over_zero_is_not_one_hundred_percent(self):
        c = overview.coverage(summ(visits_today=0, evaluated_today=0))
        self.assertIsNone(c["percent"])
        self.assertEqual((c["total"], c["evaluated"], c["unchecked"]), (0, 0, 0))

    def test_coverage_threshold_boundary(self):
        self.assertEqual(overview.COVERAGE_OK_PERCENT, 80)
        ok = overview.build_overview(summ(visits_today=10, evaluated_today=8), TI_ACTIVE, [], [])
        self.assertEqual(ok["status"], "OK")
        low = overview.build_overview(summ(visits_today=100, evaluated_today=79), TI_ACTIVE, [], [])
        self.assertEqual(low["status"], "LIMITED")
        self.assertIn("21 of 100 website visits today could not be verified.", [i["text"] for i in low["attention"]])

    def test_no_monitored_computers_is_limited_not_clear(self):
        v = overview.build_overview(summ(computers=0, online_now=0, visits_today=0, evaluated_today=0), TI_ACTIVE, [], [])
        self.assertEqual(v["status"], "LIMITED")
        self.assertIn("No computers are being monitored yet", v["message"])

    def test_needs_attention_is_never_empty_when_limited_and_always_empty_when_clear(self):
        providers = (TI_ACTIVE, TI_NONE, TI_DOWN)
        traffic = ((0, 0), (10, 10), (10, 0), (10, 7), (10, 8))
        for ti, (total, evaluated), computers, online in itertools.product(providers, traffic, (0, 2), (0, 2)):
            online_now = online if computers else 0
            v = overview.build_overview(
                summ(visits_today=total, evaluated_today=evaluated, computers=computers, online_now=online_now), ti, [], [])
            healthy = (ti["status"] == "ACTIVE" and computers > 0 and online_now > 0
                       and (total == 0 or evaluated * 100 // total >= 80))
            label = (ti["status"], total, evaluated, computers, online_now)
            if healthy:
                self.assertEqual((v["status"], v["attention"]), ("OK", []), label)
            else:
                self.assertEqual(v["status"], "LIMITED", label)
                self.assertTrue(v["attention"], label)

    def test_offline_computers_are_information_not_an_alert(self):
        v = overview.build_overview(summ(), TI_ACTIVE, [], ["PC-A", "PC-B", "PC-C", "PC-D"])
        self.assertEqual(v["status"], "OK", "being offline must not change the security status")
        texts = [i["text"] for i in v["attention"]]
        self.assertEqual(texts, ["4 computers have been offline for more than 1 hour: PC-A, PC-B, PC-C and 1 more."])
        self.assertEqual(v["attention"][0]["level"], "info")
        single = overview.build_overview(summ(), TI_ACTIVE, [], ["PC-A"])
        self.assertEqual(single["attention"][0]["text"], "1 computer has been offline for more than 1 hour: PC-A.")

    def test_coverage_item_is_not_duplicated_when_the_provider_already_explains_it(self):
        v = overview.build_overview(summ(evaluated_today=0), TI_DOWN, [], [])
        self.assertEqual(len(v["attention"]), 1)
        self.assertIn("temporarily unavailable", v["attention"][0]["text"])

    def test_action_button_targets(self):
        self.assertEqual(overview.build_overview(summ(evaluated_today=0), TI_ACTIVE, [], [])["action"]["url"],
                         "/browsing?status=UNKNOWN")
        self.assertEqual(overview.build_overview(summ(), TI_ACTIVE, [], [])["action"]["url"], "/browsing")

    def test_user_facing_reputation_wording(self):
        self.assertEqual(overview.reputation_label("SAFE"), "Safe")
        self.assertEqual(overview.reputation_label("SUSPICIOUS"), "Needs review")
        self.assertEqual(overview.reputation_label("MALICIOUS"), "Dangerous")
        self.assertEqual(overview.reputation_label("UNKNOWN"), "Not checked")
        self.assertEqual(overview.reputation_label("garbage"), "Not checked", "anything unrecognised is not checked")
        self.assertEqual(overview.reputation_hint("UNKNOWN"),
                         "The system could not currently determine this website's reputation.")
        self.assertEqual(overview.reputation_hint("SAFE"), "No known threat was detected by the reputation service.")
        self.assertEqual(overview.reputation_hint("MALICIOUS"), "This website was identified as potentially malicious.")
        self.assertEqual(overview.reputation_hint("SUSPICIOUS"),
                         "This website received suspicious reputation signals and should be reviewed.")


# --------------------------------------------------------------------
# pages and API with seeded data
# --------------------------------------------------------------------
class Base(unittest.TestCase):
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

    def tearDown(self):
        reputation.reset_state()
        config.API_KEY = ""
        config.VT_API_KEY = ""

    def conn(self):
        return database.get_connection()

    def endpoint(self, name, uid=None, user=None, browser="Edge", seconds_ago=10):
        conn = self.conn()
        stamp = (datetime.now() - timedelta(seconds=seconds_ago)).strftime(TIME)
        cur = conn.execute("INSERT INTO endpoints (endpoint_uid, computer_name, username, browser, last_seen) VALUES (?,?,?,?,?)",
                           (uid or "uid-" + name.lower(), name, user, browser, stamp))
        conn.commit()
        conn.close()
        return cur.lastrowid

    def visit(self, endpoint_id, domain, status="SAFE", path="/"):
        conn = self.conn()
        cur = conn.execute("INSERT INTO web_visits (endpoint_id, domain, sanitized_url, browser, visited_at, reputation_status) "
                           "VALUES (?,?,?,?,?,?)",
                           (endpoint_id, domain, "https://%s%s" % (domain, path), "Edge", database.now_str(), status))
        conn.commit()
        conn.close()
        return cur.lastrowid

    def alert(self, endpoint_id, domain, severity="HIGH", status="OPEN"):
        conn = self.conn()
        cur = conn.execute("INSERT INTO alerts (endpoint_id, domain, severity, reason, created_at, status) VALUES (?,?,?,?,?,?)",
                           (endpoint_id, domain, severity, "technical reason text", database.now_str(), status))
        conn.commit()
        conn.close()
        return cur.lastrowid

    def reputation_row(self, domain, status, reason, source="VirusTotal", minutes_ago=1, ttl_minutes=30):
        conn = self.conn()
        now = datetime.now()
        conn.execute("INSERT INTO domain_reputation (domain, status, source, reason, checked_at, expires_at) VALUES (?,?,?,?,?,?)",
                     (domain, status, source, reason, (now - timedelta(minutes=minutes_ago)).strftime(TIME),
                      (now + timedelta(minutes=ttl_minutes)).strftime(TIME)))
        conn.commit()
        conn.close()

    def provider_active(self):
        config.VT_API_KEY = FAKE_KEY
        reputation.reset_state()

    def status(self):
        return self.client.get("/api/status").get_json()

    def html(self, path):
        return self.client.get(path).get_data(as_text=True)


class TruthfulDashboardTests(Base):
    def test_all_unknown_traffic_is_limited_visibility_not_all_clear(self):
        self.provider_active()
        e = self.endpoint("PC-1")
        for i in range(6):
            self.visit(e, "site%d.example" % i, "UNKNOWN")
        data = self.status()
        self.assertEqual(data["summary"]["security_status"], "LIMITED")
        page = self.html("/")
        self.assertIn("Limited visibility", page)
        self.assertNotIn("All clear", page)
        self.assertIn("6 of 6 website visits today could not be verified.", page)
        self.assertEqual(data["summary"]["coverage_percent"], 0)
        self.assertIn("0%", page)

    def test_provider_in_cooldown_shows_limited_everywhere(self):
        self.provider_active()
        e = self.endpoint("PC-1")
        self.visit(e, "a.example", "SAFE")
        reputation._record_failure("VirusTotal", "HTTP 429 (rate limited)", 15, datetime.now())
        data = self.status()
        self.assertEqual(data["threat_intel"]["status"], "TEMPORARILY_UNAVAILABLE")
        self.assertEqual(data["threat_intel"]["label"], "Limited")
        self.assertEqual(data["summary"]["security_status"], "LIMITED")
        page = self.html("/")
        self.assertIn("Threat intelligence: <span class=\"ti-pill-label\">Limited</span>", page)
        self.assertIn("Temporarily unavailable", page)
        self.assertNotIn("Threat intelligence: <span class=\"ti-pill-label\">Active</span>", page)

    def test_limited_survives_a_restart_because_the_last_failed_lookup_is_cached(self):
        self.provider_active()                        # fresh process: no in-memory cooldown
        self.endpoint("PC-1")
        self.reputation_row("x.example", "UNKNOWN", "Reputation service temporarily unavailable (HTTP 429 (rate limited)).")
        self.assertEqual(reputation.provider_status()["status"], "ACTIVE", "without the database it cannot know")
        data = self.status()
        self.assertEqual(data["threat_intel"]["status"], "TEMPORARILY_UNAVAILABLE")
        self.assertEqual(data["summary"]["security_status"], "LIMITED")
        self.assertIn("HTTP 429", data["threat_intel"]["detail"])          # raw detail only in the technical field

    def test_a_later_successful_lookup_restores_active(self):
        self.provider_active()
        self.endpoint("PC-1")
        self.reputation_row("x.example", "UNKNOWN", "Reputation service temporarily unavailable (HTTP 429 (rate limited)).",
                            minutes_ago=10)
        self.reputation_row("y.example", "SAFE", "No security vendor flagged this website.", minutes_ago=1)
        self.assertEqual(self.status()["threat_intel"]["status"], "ACTIVE")

    def test_an_expired_failure_does_not_keep_the_provider_limited(self):
        self.provider_active()
        self.endpoint("PC-1")
        self.reputation_row("x.example", "UNKNOWN", "Reputation service temporarily unavailable (HTTP 429 (rate limited)).",
                            minutes_ago=45, ttl_minutes=-15)
        self.assertEqual(self.status()["threat_intel"]["status"], "ACTIVE")

    def test_unconfigured_provider_is_limited_visibility(self):
        e = self.endpoint("PC-1")
        self.visit(e, "a.example", "UNKNOWN")
        data = self.status()
        self.assertEqual(data["threat_intel"]["status"], "NOT_CONFIGURED")
        self.assertEqual(data["threat_intel"]["label"], "Not configured")
        self.assertEqual(data["summary"]["security_status"], "LIMITED")
        self.assertIn("Not configured", self.html("/"))

    def test_open_malicious_alert_shows_threat_detected_with_computer_and_website(self):
        self.provider_active()
        e = self.endpoint("ACCOUNTING-PC-01", user="David")
        self.visit(e, "evil.example", "MALICIOUS")
        self.alert(e, "evil.example", "HIGH")
        self.assertEqual(self.status()["summary"]["security_status"], "ALERT")
        page = self.html("/")
        self.assertIn("Threat detected", page)
        self.assertIn("A dangerous website was detected on one of your monitored computers", page)
        self.assertIn("ACCOUNTING-PC-01 visited evil.example.", page)
        self.assertIn("Dangerous website: ACCOUNTING-PC-01 visited evil.example.", page)
        self.assertIn("Review alerts", page)
        self.assertNotIn("All clear", page)

    def test_open_suspicious_alert_shows_attention_required(self):
        self.provider_active()
        e = self.endpoint("PC-1")
        self.visit(e, "odd.example", "SUSPICIOUS")
        self.alert(e, "odd.example", "MEDIUM")
        self.assertEqual(self.status()["summary"]["security_status"], "WARNING")
        page = self.html("/")
        self.assertIn("Attention required", page)
        self.assertIn("A suspicious website visit requires review.", page)
        self.assertIn("Needs review: PC-1 visited odd.example.", page)

    def test_handled_alerts_no_longer_drive_the_status(self):
        self.provider_active()
        e = self.endpoint("PC-1")
        self.visit(e, "evil.example", "MALICIOUS")
        alert_id = self.alert(e, "evil.example", "HIGH")
        self.client.post("/alerts/%d/close" % alert_id)
        self.assertNotEqual(self.status()["summary"]["security_status"], "ALERT")

    def test_healthy_evaluated_traffic_is_all_clear(self):
        self.provider_active()
        e = self.endpoint("PC-1")
        for i in range(5):
            self.visit(e, "ok%d.example" % i, "SAFE")
        data = self.status()
        self.assertEqual(data["summary"]["security_status"], "OK")
        page = self.html("/")
        self.assertIn("All clear", page)
        self.assertIn("All 5 website visits today were checked.", page)
        self.assertIn("No issues currently require your attention.", page)
        self.assertEqual(data["overview"]["attention"], [])

    def test_no_visits_today_is_neutral(self):
        self.provider_active()
        self.endpoint("PC-1")
        page = self.html("/")
        self.assertIn("No browsing activity yet today.", page)
        self.assertNotIn("100%", page)
        self.assertIsNone(self.status()["summary"]["coverage_percent"])

    def test_no_computers_enrolled_is_not_all_clear(self):
        self.provider_active()
        data = self.status()
        self.assertEqual(data["summary"]["security_status"], "LIMITED")
        self.assertIn("No computers are being monitored yet", self.html("/"))

    def test_reputation_coverage_card(self):
        self.provider_active()
        e = self.endpoint("PC-1")
        for domain, status in (("a.example", "SAFE"), ("b.example", "SAFE"), ("c.example", "SUSPICIOUS"), ("d.example", "UNKNOWN")):
            self.visit(e, domain, status)
        data = self.status()
        cov = data["overview"]["coverage"]
        self.assertEqual((cov["total"], cov["evaluated"], cov["unchecked"], cov["percent"]), (4, 3, 1, 75))
        page = self.html("/")
        self.assertIn("Reputation coverage", page)
        self.assertIn("75%", page)
        self.assertIn("3 of 4 checked", page)

    def test_dashboard_cards(self):
        self.provider_active()
        e = self.endpoint("PC-1")
        self.endpoint("PC-2", seconds_ago=3600)
        self.visit(e, "a.example", "SAFE")
        page = self.html("/")
        for label in ("Monitored computers", "Online now", "Websites visited today", "Threats detected today", "Reputation coverage"):
            self.assertIn(label, page)
        summary = self.status()["summary"]
        self.assertEqual((summary["computers"], summary["online_now"], summary["visits_today"]), (2, 1, 1))

    def test_offline_computer_for_over_an_hour_is_listed_but_not_a_threat(self):
        self.provider_active()
        e = self.endpoint("ONLINE-PC")
        self.visit(e, "a.example", "SAFE")
        self.endpoint("DEAD-PC", seconds_ago=4 * 3600)
        data = self.status()
        self.assertEqual(data["summary"]["security_status"], "OK")
        texts = [i["text"] for i in data["overview"]["attention"]]
        self.assertEqual(texts, ["1 computer has been offline for more than 1 hour: DEAD-PC."])

    def test_recent_activity_has_no_long_path_and_uses_business_columns(self):
        self.provider_active()
        e = self.endpoint("PC-1", user="Roi")
        self.visit(e, "example.org", "UNKNOWN", path="/a/very/long/private/path/segment")
        page = self.html("/")
        self.assertIn("<th>Security</th>", page)
        self.assertIn("Recent activity", page)
        self.assertNotIn("/a/very/long/private/path/segment", page)
        self.assertIn("example.org", page)

    def test_recent_activity_is_limited_to_eight(self):
        e = self.endpoint("PC-1")
        for i in range(12):
            self.visit(e, "s%02d.example" % i, "SAFE")
        page = self.html("/")
        self.assertEqual(len(re.findall(r"<td class=\"domain\">", page)), 8)


# --------------------------------------------------------------------
# user-facing wording
# --------------------------------------------------------------------
class WordingTests(Base):
    def setUp(self):
        super(WordingTests, self).setUp()
        e = self.endpoint("PC-1")
        self.visit(e, "unknown.example", "UNKNOWN")
        self.visit(e, "bad.example", "MALICIOUS")
        self.visit(e, "odd.example", "SUSPICIOUS")
        self.visit(e, "fine.example", "SAFE")

    def test_visit_labels_on_pages(self):
        for path in ("/", "/browsing"):
            page = self.html(path)
            self.assertIn(">Not checked<", page, path)
            self.assertIn(">Dangerous<", page, path)
            self.assertIn(">Needs review<", page, path)
            self.assertIn(">Safe<", page, path)
            for old in (">Unknown<", ">Malicious<", ">Suspicious<"):
                self.assertNotIn(old, page, path)

    def test_labels_and_explanations_in_the_api(self):
        by_domain = {v["domain"]: v for v in self.client.get("/api/visits?after_id=0").get_json()["visits"]}
        self.assertEqual(by_domain["unknown.example"]["status_label"], "Not checked")
        self.assertEqual(by_domain["unknown.example"]["reputation_status"], "UNKNOWN", "internal status is unchanged")
        self.assertEqual(by_domain["bad.example"]["status_label"], "Dangerous")
        self.assertEqual(by_domain["odd.example"]["status_label"], "Needs review")
        self.assertEqual(by_domain["fine.example"]["status_label"], "Safe")
        self.assertEqual(by_domain["unknown.example"]["status_hint"],
                         "The system could not currently determine this website's reputation.")

    def test_unknown_uses_its_own_style_not_the_safe_style(self):
        page = self.html("/browsing?status=UNKNOWN")
        self.assertIn("badge-unknown", page)
        self.assertNotIn("badge-safe", page)

    def test_tooltips_explain_each_status(self):
        page = self.html("/browsing")
        self.assertIn("No known threat was detected by the reputation service.", page)
        self.assertIn("This website was identified as potentially malicious.", page)

    def test_privacy_wording(self):
        page = self.html("/")
        self.assertIn("Website domains and sanitized paths are recorded.", page)
        self.assertIn("query parameters and URL fragments are not collected", page)


# --------------------------------------------------------------------
# alerts page
# --------------------------------------------------------------------
class AlertsPageTests(Base):
    def test_empty_state(self):
        page = self.html("/alerts")
        self.assertIn("No security alerts", page)
        self.assertIn("No suspicious or dangerous website visits currently require your attention.", page)

    def test_dangerous_alert_card(self):
        e = self.endpoint("ACCOUNTING-PC-01", user="David")
        self.alert(e, "example-malicious.test", "HIGH")
        page = self.html("/alerts")
        for text in ("DANGEROUS WEBSITE DETECTED", "ACCOUNTING-PC-01", "David", "example-malicious.test", "Computer", "User",
                     "Website", "Detected", "Why this matters:", "Recommended action:", "Open", "Mark as handled"):
            self.assertIn(text, page)
        self.assertIn("Ask the user to close the website and avoid reopening it. If the visit was unexpected, "
                      "contact your IT administrator for further review.", page)

    def test_suspicious_alert_card_and_recommendation(self):
        e = self.endpoint("PC-1")
        self.alert(e, "odd.example", "MEDIUM")
        page = self.html("/alerts")
        self.assertIn("SUSPICIOUS WEBSITE - NEEDS REVIEW", page)
        self.assertIn("Review whether this website was expected. If not, ask the user to avoid reopening it "
                      "and contact your IT administrator.", page)

    def test_alert_text_never_claims_infection_blocking_or_remediation(self):
        e = self.endpoint("PC-1")
        self.alert(e, "evil.example", "HIGH")
        self.alert(e, "odd.example", "MEDIUM")
        page = self.html("/alerts").lower()
        for forbidden in ("infected", "we blocked", "was blocked", "antivirus", "compromised by", "quarantine"):
            self.assertNotIn(forbidden, page)
        self.assertIn("does not by itself mean the computer is compromised", page)

    def test_handled_alert_is_shown_as_handled_without_a_button(self):
        e = self.endpoint("PC-1")
        alert_id = self.alert(e, "evil.example", "HIGH", status="CLOSED")
        page = self.html("/alerts")
        self.assertIn("Handled", page)
        self.assertNotIn("/alerts/%d/close" % alert_id, page)

    def test_technical_reason_is_only_in_technical_details(self):
        e = self.endpoint("PC-1")
        self.alert(e, "evil.example", "HIGH")
        page = self.html("/alerts")
        outside = re.sub(r"<details.*?</details>", "", page, flags=re.S)
        self.assertIn("technical reason text", page)
        self.assertNotIn("technical reason text", outside)


# --------------------------------------------------------------------
# computers page + archive
# --------------------------------------------------------------------
class ComputersPageTests(Base):
    def test_columns_online_offline_and_relative_time(self):
        self.endpoint("ONLINE-PC", user="Dana", seconds_ago=5)
        self.endpoint("OFFLINE-PC", seconds_ago=14 * 60)
        page = self.html("/endpoints")
        for header in ("Computer", "User", "Browser", "Status", "Last seen", "Websites today", "Security issues today"):
            self.assertIn("<th>%s</th>" % header, page)
        self.assertIn(">Now<", page)
        self.assertIn(">14 min ago<", page)
        self.assertIn("badge-online", page)
        self.assertIn("badge-offline", page)
        self.assertNotIn("badge-malicious", page)

    def test_relative_time_helper(self):
        now = datetime(2026, 10, 7, 12, 0, 0)
        ago = lambda **kw: (now - timedelta(**kw)).strftime(TIME)  # noqa: E731
        self.assertEqual(database.relative_time(ago(seconds=5), now), "Now")
        self.assertEqual(database.relative_time(ago(seconds=60), now), "1 min ago")
        self.assertEqual(database.relative_time(ago(minutes=14), now), "14 min ago")
        self.assertEqual(database.relative_time(ago(hours=2, minutes=10), now), "2 h ago")
        self.assertEqual(database.relative_time(ago(days=3), now), "3 d ago")
        self.assertEqual(database.relative_time(None, now), "-")
        self.assertEqual(database.relative_time((now + timedelta(minutes=5)).strftime(TIME), now), "Now")

    def test_empty_state(self):
        self.assertIn("No monitored computers have been enrolled yet.", self.html("/endpoints"))

    def test_exact_time_and_uuid_stay_in_technical_details(self):
        self.endpoint("PC-1", uid="secret-uid-1234")
        page = self.html("/endpoints")
        outside = re.sub(r"<details.*?</details>", "", page, flags=re.S)
        self.assertIn("secret-uid-1234", page)
        self.assertNotIn("secret-uid-1234", outside)
        self.assertNotIn("secret-uid-1234", self.client.get("/api/endpoints").get_data(as_text=True))


class ArchiveTests(Base):
    def setUp(self):
        super(ArchiveTests, self).setUp()
        self.provider_active()
        self.keep = self.endpoint("KEEP-PC", user="Dana")
        self.old = self.endpoint("OLD-TEST-PC", uid="old-uid-9999", user="Tester", seconds_ago=5 * 3600)
        self.visit(self.keep, "kept.example", "SAFE")
        self.visit(self.old, "oldsite.example", "UNKNOWN")
        self.old_alert = self.alert(self.old, "oldbad.example", "MEDIUM", status="CLOSED")

    def counts(self):
        conn = self.conn()
        try:
            return tuple(conn.execute("SELECT COUNT(*) FROM %s" % t).fetchone()[0]
                         for t in ("endpoints", "web_visits", "alerts"))
        finally:
            conn.close()

    def archive(self):
        return self.client.post("/endpoints/%d/archive" % self.old)

    def test_archive_hides_the_computer_from_the_normal_view(self):
        before = self.counts()
        r = self.archive()
        self.assertEqual(r.status_code, 302)
        page = self.html("/endpoints")
        self.assertIn("KEEP-PC", page)
        self.assertNotIn("OLD-TEST-PC", page)
        names = [e["computer_name"] for e in self.client.get("/api/endpoints").get_json()["endpoints"]]
        self.assertEqual(names, ["KEEP-PC"])
        self.assertEqual(self.counts(), before, "archiving deletes nothing")

    def test_archived_view_and_restore(self):
        self.archive()
        self.assertIn("Show archived (1)", self.html("/endpoints"))
        archived = self.html("/endpoints?archived=1")
        self.assertIn("OLD-TEST-PC", archived)
        self.assertNotIn("KEEP-PC", archived)
        self.assertIn("Restore this computer", archived)
        names = [e["computer_name"] for e in self.client.get("/api/endpoints?archived=1").get_json()["endpoints"]]
        self.assertEqual(names, ["OLD-TEST-PC"])
        r = self.client.post("/endpoints/%d/restore" % self.old, data={"view": "archived"})
        self.assertEqual(r.status_code, 302)
        self.assertIn("archived=1", r.headers["Location"])
        self.assertIn("OLD-TEST-PC", self.html("/endpoints"))
        self.assertNotIn("Show archived", self.html("/endpoints"))

    def test_archived_computer_is_not_counted_as_monitored(self):
        self.assertEqual(self.status()["summary"]["computers"], 2)
        self.archive()
        summary = self.status()["summary"]
        self.assertEqual(summary["computers"], 1)
        self.assertEqual(summary["visits_today"], 1, "an archived computer's visits no longer count towards today's totals")
        self.assertEqual(summary["evaluated_today"], 1)
        self.assertEqual(summary["online_now"], 1)
        self.assertEqual(self.status()["overview"]["coverage"]["percent"], 100)

    def test_archived_computer_history_is_preserved_in_browsing(self):
        self.archive()
        browsing = self.html("/browsing")
        self.assertIn("oldsite.example", browsing)
        self.assertIn("kept.example", browsing)
        self.assertIn("OLD-TEST-PC", browsing)
        self.assertIn("oldsite.example", self.html("/browsing?q=old-test"))

    def test_archived_computer_visits_leave_recent_activity_but_not_history(self):
        self.archive()
        recent = self.html("/")
        self.assertIn("kept.example", recent)
        self.assertNotIn("oldsite.example", recent)
        active = [v["domain"] for v in self.client.get("/api/visits?after_id=0&active=1").get_json()["visits"]]
        everything = [v["domain"] for v in self.client.get("/api/visits?after_id=0").get_json()["visits"]]
        self.assertEqual(active, ["kept.example"])
        self.assertEqual(sorted(everything), ["kept.example", "oldsite.example"])

    def test_archived_computer_alerts_are_preserved(self):
        self.archive()
        page = self.html("/alerts")
        self.assertIn("oldbad.example", page)
        self.assertIn("OLD-TEST-PC", page)

    def test_an_open_alert_still_counts_after_archiving_its_computer(self):
        open_alert = self.alert(self.old, "stillbad.example", "HIGH")
        self.archive()
        self.assertEqual(self.status()["summary"]["security_status"], "ALERT",
                         "archiving must never hide an unresolved threat")
        self.assertEqual(self.status()["summary"]["open_alerts"], 1)
        self.client.post("/alerts/%d/close" % open_alert)
        self.assertNotEqual(self.status()["summary"]["security_status"], "ALERT")

    def test_normal_computer_stays_visible(self):
        self.archive()
        self.assertIn("KEEP-PC", self.html("/endpoints"))
        self.assertEqual(self.status()["summary"]["computers"], 1)

    def test_archiving_is_idempotent_and_unknown_ids_return_404(self):
        self.archive()
        self.assertEqual(self.archive().status_code, 302)
        self.assertEqual(self.client.post("/endpoints/999999/archive").status_code, 404)
        self.assertEqual(self.client.post("/endpoints/999999/restore").status_code, 404)

    def test_a_connecting_archived_computer_is_restored_automatically(self):
        self.archive()
        r = self.client.post("/api/heartbeat", json={"endpoint_uid": "old-uid-9999", "computer_name": "OLD-TEST-PC",
                                                     "username": "Tester", "browser": "Edge"})
        self.assertEqual(r.status_code, 200)
        self.assertIn("OLD-TEST-PC", self.html("/endpoints"))
        self.assertEqual(self.status()["summary"]["computers"], 2)

    def test_nothing_is_archived_automatically(self):
        conn = self.conn()
        archived = conn.execute("SELECT COUNT(*) FROM endpoints WHERE archived_at IS NOT NULL").fetchone()[0]
        conn.close()
        self.assertEqual(archived, 0)
        database.init_db()                                   # a restart must not archive anything either
        conn = self.conn()
        try:
            self.assertEqual(len(database.list_endpoints(conn)), 2)
        finally:
            conn.close()

    def test_migration_adds_archived_at_without_touching_existing_rows(self):
        path = os.path.join(tempfile.mkdtemp(prefix="monitor_mig35_"), "phase3.db")
        conn = sqlite3.connect(path)
        conn.executescript(
            "CREATE TABLE endpoints (id INTEGER PRIMARY KEY AUTOINCREMENT, endpoint_uid TEXT NOT NULL UNIQUE,"
            " computer_name TEXT NOT NULL, username TEXT, browser TEXT, last_seen TEXT NOT NULL);"
            "INSERT INTO endpoints (endpoint_uid, computer_name, username, browser, last_seen)"
            " VALUES ('p3-uid', 'PHASE3-PC', 'Roi', 'Edge', '2026-10-06 22:00:00');")
        conn.commit()
        conn.close()
        database.init_db(path)
        database.init_db(path)                               # idempotent
        conn = database.get_connection(path)
        columns = [r["name"] for r in conn.execute("PRAGMA table_info(endpoints)")]
        row = dict(conn.execute("SELECT * FROM endpoints").fetchone())
        conn.close()
        self.assertEqual(columns.count("archived_at"), 1)
        self.assertEqual((row["computer_name"], row["username"], row["browser"], row["archived_at"]),
                         ("PHASE3-PC", "Roi", "Edge", None))


# --------------------------------------------------------------------
# browsing: search + filters
# --------------------------------------------------------------------
class BrowsingSearchTests(Base):
    def setUp(self):
        super(BrowsingSearchTests, self).setUp()
        a = self.endpoint("ACCT-PC", user="Dana")
        b = self.endpoint("FRONT-DESK", user="Sarah")
        self.visit(a, "alpha.example", "SAFE")
        self.visit(a, "gamma.example", "UNKNOWN")
        self.visit(b, "beta.example", "MALICIOUS")

    def domains(self, query_string):
        page = self.html("/browsing" + query_string)
        return sorted(set(re.findall(r'<span class="domain">([^<]+)</span>', page)))

    def test_search_by_website(self):
        self.assertEqual(self.domains("?q=alpha"), ["alpha.example"])
        self.assertEqual(self.domains("?q=EXAMPLE"), ["alpha.example", "beta.example", "gamma.example"])

    def test_search_by_computer(self):
        self.assertEqual(self.domains("?q=front"), ["beta.example"])
        self.assertEqual(self.domains("?q=acct-pc"), ["alpha.example", "gamma.example"])

    def test_search_by_user(self):
        self.assertEqual(self.domains("?q=sarah"), ["beta.example"])
        self.assertEqual(self.domains("?q=DANA"), ["alpha.example", "gamma.example"])

    def test_status_filters_still_work(self):
        self.assertEqual(self.domains("?status=SAFE"), ["alpha.example"])
        self.assertEqual(self.domains("?status=UNKNOWN"), ["gamma.example"])
        self.assertEqual(self.domains("?status=MALICIOUS"), ["beta.example"])
        self.assertEqual(self.domains("?status=SUSPICIOUS"), [])
        self.assertEqual(len(self.domains("")), 3)
        self.assertEqual(len(self.domains("?status=nonsense")), 3, "an invalid filter is ignored")

    def test_search_and_filter_combine(self):
        self.assertEqual(self.domains("?q=acct&status=UNKNOWN"), ["gamma.example"])
        self.assertEqual(self.domains("?q=front&status=SAFE"), [])

    def test_filter_chips_use_business_wording_and_keep_the_search(self):
        page = self.html("/browsing?q=acct")
        for label in (">All<", ">Safe<", ">Needs review<", ">Dangerous<", ">Not checked<"):
            self.assertIn(label, page)
        self.assertIn("status=UNKNOWN", page)
        self.assertIn("q=acct", page)
        self.assertIn('value="acct"', page)
        self.assertIn("Search website, computer or user", page)

    def test_wildcards_and_injection_are_treated_as_plain_text(self):
        for term in ("%", "_", "' OR 1=1 --", '"; DROP TABLE web_visits; --', "\\"):
            r = self.client.get("/browsing", query_string={"q": term})
            self.assertEqual(r.status_code, 200, term)
            found = sorted(set(re.findall(r'<span class="domain">([^<]+)</span>', r.get_data(as_text=True))))
            self.assertEqual(found, [], "%r must match literally, not as a wildcard or SQL" % term)
        self.assertIn("No browsing activity matches the selected filters.", self.html("/browsing?q=%25"))
        conn = self.conn()
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM web_visits").fetchone()[0], 3)
        conn.close()

    def test_polling_api_honours_search_and_status(self):
        got = self.client.get("/api/visits?after_id=0&q=front").get_json()["visits"]
        self.assertEqual([v["domain"] for v in got], ["beta.example"])
        got = self.client.get("/api/visits?after_id=0&q=acct&status=SAFE").get_json()["visits"]
        self.assertEqual([v["domain"] for v in got], ["alpha.example"])
        long_term = "x" * 5000
        self.assertEqual(self.client.get("/api/visits", query_string={"q": long_term}).status_code, 200)

    def test_full_path_is_secondary_and_data_is_kept(self):
        page = self.html("/browsing")
        self.assertIn('class="path muted mono"', page)
        self.assertIn("https://alpha.example/", page)
        for header in ("Time", "Computer", "User", "Website", "Browser", "Security"):
            self.assertIn("<th>%s</th>" % header, page)

    def test_empty_state(self):
        self.assertIn("No browsing activity matches the selected filters.", self.html("/browsing?q=zzzzzz"))


# --------------------------------------------------------------------
# monitored computers exist but none is online -> Limited visibility
# --------------------------------------------------------------------
NONE_ONLINE_MESSAGE = "No monitored computers are currently online. No confirmed threats were detected in the available data."


class NoComputerOnlineLogicTests(unittest.TestCase):
    def test_five_monitored_none_online_is_limited_visibility(self):
        v = overview.build_overview(summ(computers=5, online_now=0), TI_ACTIVE, [], [])
        self.assertEqual((v["status"], v["title"]), ("LIMITED", "Limited visibility"))
        self.assertEqual(v["message"], NONE_ONLINE_MESSAGE)
        self.assertNotEqual(v["title"], "All clear")
        self.assertIn("No monitored computers are currently online.", [i["text"] for i in v["attention"]])
        self.assertEqual(v["action"]["url"], "/endpoints")

    def test_one_monitored_none_online_is_limited_visibility(self):
        v = overview.build_overview(summ(computers=1, online_now=0), TI_ACTIVE, [], [])
        self.assertEqual((v["status"], v["message"]), ("LIMITED", NONE_ONLINE_MESSAGE))

    def test_five_monitored_one_online_with_sufficient_coverage_may_be_all_clear(self):
        v = overview.build_overview(summ(computers=5, online_now=1, visits_today=10, evaluated_today=10), TI_ACTIVE, [], [])
        self.assertEqual((v["status"], v["title"]), ("OK", "All clear"))
        self.assertEqual(v["attention"], [])
        # one online computer is not enough when the other conditions fail
        low = overview.build_overview(summ(computers=5, online_now=1, visits_today=10, evaluated_today=2), TI_ACTIVE, [], [])
        self.assertEqual(low["status"], "LIMITED")
        down = overview.build_overview(summ(computers=5, online_now=1), TI_DOWN, [], [])
        self.assertEqual(down["status"], "LIMITED")

    def test_no_computers_enrolled_keeps_its_own_limited_message(self):
        v = overview.build_overview(summ(computers=0, online_now=0, visits_today=0, evaluated_today=0), TI_ACTIVE, [], [])
        self.assertEqual(v["status"], "LIMITED")
        self.assertIn("No computers are being monitored yet", v["message"])
        self.assertNotIn("currently online", v["message"])
        self.assertNotIn("No monitored computers are currently online.", [i["text"] for i in v["attention"]])

    def test_malicious_alert_overrides_offline_visibility(self):
        v = overview.build_overview(summ(computers=5, online_now=0, open_alerts=1, open_high=1), TI_ACTIVE, [alert("HIGH")], [])
        self.assertEqual((v["status"], v["title"]), ("ALERT", "Threat detected"))
        self.assertIn("ACCT-PC visited evil.example", v["affected"])

    def test_suspicious_alert_overrides_offline_visibility(self):
        v = overview.build_overview(summ(computers=5, online_now=0, open_alerts=1, open_medium=1), TI_ACTIVE,
                                    [alert("MEDIUM", domain="odd.example")], [])
        self.assertEqual((v["status"], v["title"]), ("WARNING", "Attention required"))

    def test_other_limitations_still_explain_themselves_when_nobody_is_online(self):
        v = overview.build_overview(summ(computers=3, online_now=0), TI_NONE, [], [])
        texts = [i["text"] for i in v["attention"]]
        self.assertEqual(v["status"], "LIMITED")
        self.assertIn("No monitored computers are currently online.", texts)
        self.assertTrue(any("not set up" in t for t in texts), "the reputation problem is still listed")


class NoComputerOnlineIntegrationTests(Base):
    def five_offline(self, with_visits=True):
        ids = [self.endpoint("PC-%d" % n, seconds_ago=3600 * n) for n in range(1, 6)]
        if with_visits:
            for n, endpoint_id in enumerate(ids):
                self.visit(endpoint_id, "ok%d.example" % n, "SAFE")
        return ids

    def test_five_offline_computers_show_limited_visibility_on_the_dashboard_and_api(self):
        self.provider_active()
        self.five_offline()
        data = self.status()
        self.assertEqual((data["summary"]["computers"], data["summary"]["online_now"]), (5, 0))
        self.assertEqual(data["summary"]["security_status"], "LIMITED")
        page = self.html("/")
        self.assertIn("Limited visibility", page)
        self.assertIn("No monitored computers are currently online.", page)
        self.assertIn("No confirmed threats were detected in the available data.", page)
        self.assertNotIn("All clear", page)
        self.assertIn("View computers", page)

    def test_an_offline_computer_alone_creates_no_alert(self):
        self.provider_active()
        self.five_offline()
        self.endpoint("DEAD-PC", seconds_ago=3 * 86400)
        conn = self.conn()
        try:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0], 0)
        finally:
            conn.close()
        data = self.status()
        self.assertEqual((data["summary"]["open_alerts"], data["summary"]["threats_today"]), (0, 0))
        self.assertIn("No security alerts", self.html("/alerts"))
        self.assertEqual(data["summary"]["security_status"], "LIMITED")      # a limitation, not an alert

    def test_one_computer_coming_online_restores_all_clear(self):
        self.provider_active()
        ids = self.five_offline()
        self.assertEqual(self.status()["summary"]["security_status"], "LIMITED")
        conn = self.conn()
        uid = conn.execute("SELECT endpoint_uid FROM endpoints WHERE id = ?", (ids[0],)).fetchone()[0]
        conn.close()
        r = self.client.post("/api/heartbeat", json={"endpoint_uid": uid, "computer_name": "PC-1", "browser": "Edge"})
        self.assertEqual(r.get_json()["status"], "ONLINE")
        data = self.status()
        self.assertEqual((data["summary"]["computers"], data["summary"]["online_now"]), (5, 1))
        self.assertEqual(data["summary"]["security_status"], "OK")
        self.assertIn("All clear", self.html("/"))

    def test_a_single_offline_computer(self):
        self.provider_active()
        e = self.endpoint("ONLY-PC", seconds_ago=7200)
        self.visit(e, "ok.example", "SAFE")
        self.assertEqual(self.status()["summary"]["security_status"], "LIMITED")

    def test_archived_online_computer_does_not_count_as_online(self):
        self.provider_active()
        online = self.endpoint("ONLINE-PC")
        self.endpoint("OFFLINE-PC", seconds_ago=7200)
        self.assertEqual(self.status()["summary"]["security_status"], "OK")
        self.client.post("/endpoints/%d/archive" % online)
        data = self.status()
        self.assertEqual((data["summary"]["computers"], data["summary"]["online_now"]), (1, 0))
        self.assertEqual(data["summary"]["security_status"], "LIMITED")

    def test_open_alerts_still_override_when_nobody_is_online(self):
        self.provider_active()
        e = self.endpoint("OFFLINE-PC", seconds_ago=7200)
        self.visit(e, "evil.example", "MALICIOUS")
        alert_id = self.alert(e, "evil.example", "HIGH")
        self.assertEqual(self.status()["summary"]["security_status"], "ALERT")
        self.assertIn("Threat detected", self.html("/"))
        self.client.post("/alerts/%d/close" % alert_id)
        self.alert(e, "odd.example", "MEDIUM")
        self.assertEqual(self.status()["summary"]["security_status"], "WARNING")
        self.assertIn("Attention required", self.html("/"))

    def test_heartbeat_behaviour_is_unchanged(self):
        r = self.client.post("/api/heartbeat", json={"endpoint_uid": "hb-uid-1", "computer_name": "HB-PC", "browser": "Edge"})
        self.assertEqual((r.status_code, r.get_json()["status"]), (200, "ONLINE"))
        self.assertEqual(database.ONLINE_WINDOW_SECONDS, 180)
        conn = self.conn()
        try:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM endpoints").fetchone()[0], 1)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0], 0)
        finally:
            conn.close()


# --------------------------------------------------------------------
# polling cursor (bug found while verifying the live UI)
# --------------------------------------------------------------------
class PollingCursorTests(Base):
    def skewed_visits(self):
        """Newest row by TIME is not the row with the highest ID (a computer with a slow clock)."""
        a = self.endpoint("FAST-CLOCK-PC")
        b = self.endpoint("SLOW-CLOCK-PC")
        conn = self.conn()
        now = datetime.now()
        rows = (
            (a, "first.example", now - timedelta(minutes=1)),
            (b, "second.example", now - timedelta(minutes=30)),     # higher id, much older timestamp
            (b, "third.example", now - timedelta(minutes=40)),      # highest id, oldest timestamp
        )
        for endpoint_id, domain, when in rows:
            conn.execute("INSERT INTO web_visits (endpoint_id, domain, sanitized_url, browser, visited_at, reputation_status) "
                         "VALUES (?,?,?,?,?,'SAFE')", (endpoint_id, domain, "https://%s/" % domain, "Edge", when.strftime(TIME)))
        conn.commit()
        highest = conn.execute("SELECT MAX(id) FROM web_visits").fetchone()[0]
        conn.close()
        return highest

    def test_page_cursor_is_the_highest_id_so_the_next_poll_adds_nothing_twice(self):
        highest = self.skewed_visits()
        for path in ("/", "/browsing"):
            page = self.html(path)
            self.assertIn('data-last-id="%d"' % highest, page, path)
            self.assertEqual(len(re.findall(r'<tr data-id="\d+"', page)), 3, path)
        self.assertEqual(self.client.get("/api/visits?after_id=%d" % highest).get_json()["visits"], [],
                         "rows already on the page must not be delivered again")

    def test_a_visit_after_the_cursor_is_delivered_once(self):
        highest = self.skewed_visits()
        new_id = self.visit(self.endpoint("NEW-PC"), "fresh.example", "SAFE")
        got = self.client.get("/api/visits?after_id=%d" % highest).get_json()["visits"]
        self.assertEqual([v["id"] for v in got], [new_id])

    def test_cursor_on_an_empty_database_is_zero(self):
        self.assertIn('data-last-id="0"', self.html("/"))
        self.assertIn('data-last-id="0"', self.html("/browsing"))

    def test_singular_and_plural_coverage_wording(self):
        one = overview.build_overview(summ(visits_today=1, evaluated_today=1), TI_ACTIVE, [], [])
        self.assertEqual(one["coverage_line"], "The website visit today was checked.")
        two = overview.build_overview(summ(visits_today=2, evaluated_today=2), TI_ACTIVE, [], [])
        self.assertEqual(two["coverage_line"], "All 2 website visits today were checked.")
        unverified = overview.build_overview(summ(visits_today=1, evaluated_today=0), TI_ACTIVE, [], [])
        self.assertEqual(unverified["coverage_line"], "1 of 1 website visit today could not be verified.")


# --------------------------------------------------------------------
# DEV MODE warning, empty states, regressions
# --------------------------------------------------------------------
class DevModeAndEmptyStateTests(Base):
    def test_dev_mode_warning_is_compact_and_visible(self):
        page = self.html("/")
        self.assertIn('id="dev-bar" >', page)
        self.assertNotIn('id="dev-bar" hidden', page)
        self.assertIn("Development mode", page)
        self.assertIn("API authentication is disabled.", page)
        self.assertIn("<summary>Technical details</summary>", page)
        self.assertNotIn("lan-warning", page)

    def test_dev_mode_warning_disappears_when_authentication_is_configured(self):
        config.API_KEY = "configured-key"
        self.assertIn('id="dev-bar" hidden', self.html("/"))
        self.assertFalse(self.status()["dev_mode"])

    def test_every_page_has_a_useful_empty_state(self):
        self.assertIn("No browsing activity yet today.", self.html("/"))
        self.assertIn("No browsing activity matches the selected filters.", self.html("/browsing"))
        self.assertIn("No security alerts", self.html("/alerts"))
        self.assertIn("No monitored computers have been enrolled yet.", self.html("/endpoints"))

    def test_needs_attention_empty_message_is_only_visible_when_nothing_needs_attention(self):
        self.provider_active()
        e = self.endpoint("PC-1")
        self.visit(e, "a.example", "SAFE")
        page = self.html("/")
        self.assertIn('id="attention-empty" >', page)                 # visible
        self.assertIn('id="attention-list" hidden', page)
        self.visit(e, "b.example", "UNKNOWN")
        self.visit(e, "c.example", "UNKNOWN")
        limited = self.html("/")
        self.assertIn('id="attention-empty" hidden', limited)         # never claims "no issues" while limited
        self.assertNotIn('id="attention-list" hidden', limited)


class RegressionTests(Base):
    EVENT = {"endpoint_uid": "reg-uid-0001", "computer_name": "REG-PC", "username": "Roi", "browser": "Edge",
             "domain": "example.org", "url": "https://example.org/account?token=SECRET#frag"}

    def test_browser_noise_is_still_filtered_but_normal_msn_is_not(self):
        r = self.client.post("/api/web-events", json=dict(self.EVENT, domain="ntp.msn.com", url="https://ntp.msn.com/edge/ntp"))
        self.assertEqual(r.get_json()["ignored"], "browser_internal_page")
        r = self.client.post("/api/web-events", json=dict(self.EVENT, domain="www.msn.com", url="https://www.msn.com/en-us/news"))
        self.assertEqual(r.status_code, 201)
        conn = self.conn()
        self.assertEqual([r[0] for r in conn.execute("SELECT domain FROM web_visits")], ["www.msn.com"])
        conn.close()

    def test_privacy_nothing_sensitive_reaches_any_page_or_api(self):
        self.client.post("/api/web-events", json=self.EVENT)
        for path in ("/", "/browsing", "/alerts", "/endpoints", "/api/status", "/api/visits?after_id=0", "/api/endpoints"):
            text = self.client.get(path).get_data(as_text=True)
            self.assertNotIn("SECRET", text, path)
            self.assertNotIn("#frag", text, path)
            self.assertNotIn("token=", text, path)
        self.assertIn("https://example.org/account", self.html("/browsing"))

    def test_api_key_never_appears_in_any_new_page_or_response(self):
        key = "SUPER-SECRET-KEY-35-d41d8cd98f00"
        config.API_KEY = key
        config.VT_API_KEY = key[::-1]
        e = self.endpoint("PC-1")
        self.alert(e, "evil.example", "HIGH")
        self.visit(e, "evil.example", "MALICIOUS")
        bodies = []
        for path in ("/", "/browsing", "/browsing?q=evil", "/alerts", "/endpoints", "/endpoints?archived=1", "/api/status",
                     "/api/visits?after_id=0", "/api/endpoints", "/api/ping"):
            bodies.append(self.client.get(path, headers={"X-Api-Key": key}).get_data(as_text=True))
        bodies.append(self.client.post("/endpoints/%d/archive" % e, headers={"X-Api-Key": key}).get_data(as_text=True))
        for body in bodies:
            self.assertNotIn(key, body)
            self.assertNotIn(key[::-1], body)
        with open(config.DATABASE_PATH, "rb") as fh:
            raw = fh.read()
        self.assertNotIn(key.encode(), raw)
        self.assertNotIn(key[::-1].encode(), raw)

    def test_phase_one_to_three_monitoring_still_works(self):
        r = self.client.post("/api/web-events", json=self.EVENT)
        self.assertEqual(r.status_code, 201)
        self.assertEqual(r.get_json()["reputation"]["status"], "UNKNOWN")        # no provider configured
        self.assertTrue(self.client.post("/api/heartbeat", json={k: self.EVENT[k] for k in
                        ("endpoint_uid", "computer_name", "username", "browser")}).get_json()["ok"])
        self.assertEqual(self.client.get("/api/ping").get_json()["service"], "website-monitor")
        row = self.client.get("/api/endpoints").get_json()["endpoints"][0]
        self.assertEqual((row["computer_name"], row["status"], row["websites_today"]), ("REG-PC", "ONLINE", 1))

    def test_security_status_field_keeps_its_codes_for_api_consumers(self):
        self.assertIn(self.status()["summary"]["security_status"], ("ALERT", "WARNING", "LIMITED", "OK"))


if __name__ == "__main__":
    unittest.main()
