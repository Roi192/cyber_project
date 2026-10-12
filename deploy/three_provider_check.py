"""ONE controlled lookup per new provider - APIVoid, MetaDefender Cloud, AbuseIPDB (Phase F3.24). Dry run unless --live AND you type SEND.

    cd C:\\Users\\Moshe\\cyber_project
    venv\\Scripts\\python.exe deploy\\three_provider_check.py                              dry run: nothing is sent; shows what would be
    venv\\Scripts\\python.exe deploy\\three_provider_check.py --live --provider all        LIVE: at most 3 requests (one per provider), after you type SEND
    venv\\Scripts\\python.exe deploy\\three_provider_check.py --live --provider abuseipdb

Each provider gets exactly ONE request about a harmless public name (default example.com). APIVoid and MetaDefender receive the website NAME; AbuseIPDB receives ONE validated public
IP ADDRESS that the name resolves to (its answer is IP reputation, not a verdict about the website). Nothing is uploaded, scanned or submitted. There is never a retry: a rejected key
(401/403), a rate limit or quota stop (429), a timeout or an unreadable answer ends the test of THAT provider with a plain report. TLS verification stays ON.
Keys are read from .env (or the environment) and are never printed; nothing is written to a database or a file; the application is not started.
Standard library plus the project's own modules; Python 3.8 compatible. It is not run by the test suite against the network (the tests use a fake one).
"""
import argparse
import os
import re
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOMAIN_PATTERN = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
KEYS = {"apivoid": "APIVOID_API_KEY", "metadefender": "METADEFENDER_API_KEY", "abuseipdb": "ABUSEIPDB_API_KEY"}
HOSTS = {"apivoid": "api.apivoid.com", "metadefender": "api.metadefender.com", "abuseipdb": "api.abuseipdb.com"}
LABELS = {"apivoid": "APIVoid", "metadefender": "MetaDefender Cloud", "abuseipdb": "AbuseIPDB"}


def read_key(name, env_path=None):
    """The value of NAME from the environment or .env, or ''. Never printed."""
    path = env_path or os.path.join(ROOT, ".env")
    value = os.environ.get(name, "").strip()
    if not value and os.path.isfile(path):
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                if re.match(r"^\s*%s\s*=" % re.escape(name), line):
                    value = line.split("=", 1)[1].strip().strip('"').strip("'")
    return value


def describe(value, depth=0):
    """The shape of a JSON value: field names and types only, never values."""
    if isinstance(value, dict):
        return "{" + ", ".join("%s: %s" % (k, describe(v, depth + 1)) for k, v in sorted(value.items())) + "}" if depth < 3 else "{...}"
    if isinstance(value, list):
        return "[%d x %s]" % (len(value), describe(value[0], depth + 1) if value else "empty")
    return type(value).__name__


class OneRequest(object):
    """Passes exactly one request through and keeps the answer for the report; a second one is refused."""

    def __init__(self, inner):
        self.inner = inner
        self.calls = 0
        self.response = None

    def _send(self, method, url, **kwargs):
        self.calls += 1
        if self.calls > 1:
            raise AssertionError("only one request per provider is allowed")
        self.response = getattr(self.inner, method)(url, **kwargs)
        return self.response

    def get(self, url, **kwargs):
        return self._send("get", url, **kwargs)

    def post(self, url, **kwargs):
        return self._send("post", url, **kwargs)


def check_one(which, domain, key, session, resolver, out):
    """One lookup of one provider. Returns True when it worked."""
    from services import panels, reputation
    recording = OneRequest(session)
    if which == "apivoid":
        provider = reputation.ApivoidProvider(key, session=recording)
    elif which == "metadefender":
        provider = reputation.MetaDefenderProvider(key, session=recording)
    else:
        provider = reputation.AbuseIpdbProvider(key, session=recording, resolver=resolver)
    label = LABELS[which]
    try:
        result = provider.lookup(domain)
    except reputation.ProviderError as error:
        response = recording.response
        out("[%s] HTTP status: %s" % (label, response.status_code if response is not None else "no answer"))
        out("[%s] STOPPED, no retry: %s%s" % (label, error, " - the credential was rejected (wrong key, or the plan has no access to this API)" if error.auth else ""))
        if response is not None:
            out("[%s] quota headers: %s" % (label, reputation.MetaDefenderProvider._quota(getattr(response, "headers", None)) or "none sent"))
        return False
    response = recording.response
    out("[%s] HTTP status: %s" % (label, response.status_code if response is not None else "answered from this run's own cache"))
    if response is not None:
        out("[%s] quota headers: %s" % (label, reputation.MetaDefenderProvider._quota(response.headers) or "none sent"))
        try:
            body = response.json()
        except ValueError:
            body = None
        out("[%s] answer structure: %s" % (label, describe(body) if body is not None else "not JSON"))
    d = result["details"]
    out("[%s] application mapping: verdict=%s classification=%s strength=%s scope=%s coverage_gap=%s alert=%s (observation only: this never raises an alert)" % (
        label, result["status"], d.get("classification"), d.get("strength"), d.get("scope"), bool(d.get("coverage_gap")), result.get("alert_severity")))
    card = {"provider": label, "state": "CHECKED", "verdict": result["status"], "reason": result["reason"], "counts": None, "details": d, "checked_at": "now", "valid_until": ""}
    panel = panels.build(label, card)
    out("[%s] analysis-page panel: scope=%s | verdict=%s | headline=%s" % (label, panel.get("scope_label"), panel["verdict_label"], panel["headline"]))
    out("[%s]   plain text: %s" % (label, panel["plain"]))
    return True


def run(which, domain, live, ask=input, session=None, resolver=None, out=print, env_path=None):
    """Returns an exit code: 0 every requested provider answered, 1 some stopped or have no key, 2 refused."""
    if not DOMAIN_PATTERN.match(domain or ""):
        out("REFUSED: '%s' is not a plain public domain name (letters, digits, hyphens and dots only)." % domain)
        return 2
    chosen = sorted(KEYS) if which == "all" else [which]
    keys = dict((p, read_key(KEYS[p], env_path)) for p in chosen)
    for p in chosen:
        out("%-18s key: %s | would send to: %s | what: %s" % (LABELS[p], "present (%d characters, not shown)" % len(keys[p]) if keys[p] else "MISSING (set it with deploy\\set_local_secret.py)",
                                                          HOSTS[p], "one IP address (resolved from %s locally; IP reputation only)" % domain if p == "abuseipdb" else "the name %s" % domain))
    ready = [p for p in chosen if keys[p]]
    if not live:
        out("Dry run: nothing was sent. Re-run with --live to make %d request(s), one per provider." % len(ready))
        return 0 if len(ready) == len(chosen) else 1
    if not ready:
        out("No key is configured; nothing to do.")
        return 1
    answer = ask("LIVE: %d request(s) to: %s. Type SEND to continue: " % (len(ready), ", ".join(HOSTS[p] for p in ready)))
    if (answer or "").strip() != "SEND":
        out("Cancelled; nothing was sent.")
        return 2
    os.environ["WEBSITE_MONITOR_TEST_MODE"] = "1"                              # the project's modules refuse to open the real database in this process
    os.environ.setdefault("DATABASE_PATH", os.path.join(tempfile.mkdtemp(prefix="tpcheck_"), "never_used.db"))
    sys.path.insert(0, ROOT)
    if session is None:
        import requests
        session = requests.Session()
    worked = [check_one(p, domain, keys[p], session, resolver, out) for p in ready]
    out("Result: %d of %d requested provider(s) answered. Nothing was stored anywhere." % (sum(1 for w in worked if w), len(chosen)))
    return 0 if all(worked) and len(ready) == len(chosen) else 1


def main(argv=None, ask=input, session=None, resolver=None, out=print, env_path=None):
    parser = argparse.ArgumentParser(description="One controlled lookup per new provider (dry run unless --live and SEND).")
    parser.add_argument("--provider", choices=sorted(KEYS) + ["all"], default="all")
    parser.add_argument("--domain", default="example.com", help="a safe public domain name (default example.com)")
    parser.add_argument("--live", action="store_true")
    args = parser.parse_args(argv)
    return run(args.provider, args.domain.strip().lower(), args.live, ask=ask, session=session, resolver=resolver, out=out, env_path=env_path)


if __name__ == "__main__":
    sys.exit(main())
