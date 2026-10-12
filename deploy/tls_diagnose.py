"""TLS reachability diagnosis for the provider hosts (Phase F3.26). DNS -> TCP -> TLS handshake only: NO HTTP request is sent, no key is read or sent.

    venv\\Scripts\\python.exe deploy\\tls_diagnose.py api.apivoid.com api.metadefender.com

For each host it reports the DNS answer, whether TCP connects, and whether the TLS handshake and certificate verification succeed - twice: with the operating system's trust store
(what a browser and Python's ssl module use) and with the certifi bundle (what the `requests` library used by the application uses). Verification is ALWAYS on; nothing is
bypassed. If only the certifi test fails, a certificate authority that is trusted by the operating system but unknown to certifi (a corporate proxy, antivirus or school firewall that
re-signs HTTPS) is the likely cause. Standard library plus certifi; Python 3.8 compatible.
"""
import os
import socket
import ssl
import sys

TIMEOUT = 8


def category(error):
    """A fixed, key-free category for an exception raised while connecting."""
    if isinstance(error, ssl.SSLCertVerificationError):
        return "TLS certificate verification failed: %s" % (getattr(error, "verify_message", "") or "unknown reason")
    if isinstance(error, ssl.SSLError):
        return "TLS handshake failed (%s)" % type(error).__name__
    if isinstance(error, socket.gaierror):
        return "DNS failure"
    if isinstance(error, (socket.timeout, TimeoutError)):
        return "connection timed out"
    if isinstance(error, ConnectionRefusedError):
        return "connection refused"
    if isinstance(error, ConnectionResetError):
        return "connection reset by the peer"
    if isinstance(error, OSError):
        return "network error (%s)" % type(error).__name__
    return type(error).__name__


def certifi_context():
    import certifi
    return ssl.create_default_context(cafile=certifi.where())


def handshake(host, context, out):
    """TCP + TLS handshake with verification. Returns True when it worked. Nothing is written to the connection."""
    try:
        sock = socket.create_connection((host, 443), timeout=TIMEOUT)
    except Exception as error:
        out("    TCP connect: FAILED - %s" % category(error))
        return False
    out("    TCP connect: ok")
    try:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert()
            subject = dict(x[0] for x in cert.get("subject", ()))
            issuer = dict(x[0] for x in cert.get("issuer", ()))
            out("    TLS handshake: ok (%s, verified) | certificate for %s | issued by %s | valid until %s" % (tls.version(), subject.get("commonName", "?"), issuer.get("organizationName") or issuer.get("commonName", "?"), cert.get("notAfter")))
            return True
    except Exception as error:
        out("    TLS handshake: FAILED - %s" % category(error))
        try:
            sock.close()
        except OSError:
            pass
        return False


def diagnose(host, out=print):
    out("%s" % host)
    try:
        addresses = sorted(set(a[4][0] for a in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)))
    except Exception as error:
        out("  DNS: FAILED - %s" % category(error))
        return {"dns": False}
    out("  DNS: ok (%s)" % ", ".join(addresses[:3]))
    result = {"dns": True}
    out("  with the operating system's trust store (browser / Python ssl):")
    result["system"] = handshake(host, ssl.create_default_context(), out)
    out("  with the certifi bundle (the `requests` library used by the application):")
    try:
        result["certifi"] = handshake(host, certifi_context(), out)
    except ImportError:
        out("    certifi is not installed")
        result["certifi"] = False
    return result


def main(argv=None, out=print):
    hosts = list(argv if argv is not None else sys.argv[1:])
    if not hosts:
        out("usage: tls_diagnose.py HOST [HOST ...]")
        return 2
    proxies = sorted(k for k in os.environ if k.upper() in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE"))
    out("proxy / trust variables set in this environment (names only): %s" % (", ".join(proxies) or "none"))
    results = dict((h, diagnose(h, out)) for h in hosts)
    for host, r in results.items():
        if r.get("system") and not r.get("certifi"):
            out("%s: the OS trusts the certificate chain but certifi does not -> a re-signing proxy / antivirus / firewall CA is installed on this computer (certificate trust issue)." % host)
        elif not r.get("dns"):
            out("%s: DNS does not resolve." % host)
        elif not r.get("system") and not r.get("certifi"):
            out("%s: neither trust store accepts the connection (see the exact category above)." % host)
        else:
            out("%s: reachable with verification on, in both trust stores." % host)
    return 0 if all(r.get("system") and r.get("certifi") for r in results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
