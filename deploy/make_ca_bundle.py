"""Build a CA bundle = certifi + the root certificate(s) of a re-signing proxy / antivirus that THIS COMPUTER's operating system already trusts (Phase F3.26). Windows only.

    venv\\Scripts\\python.exe deploy\\make_ca_bundle.py "Avast Web/Mail Shield Root"         # writes data\\ca-bundle.pem and tells you the .env line to add

Why: security software such as Avast "Web/Mail Shield" re-signs HTTPS with its own root. Windows and browsers trust it, the `requests` library (certifi) does not, so lookups to some
providers fail with "unable to get local issuer certificate". Certificate verification stays ON: the application then trusts exactly what certifi trusts plus the named root, nothing
else. Only PUBLIC certificates are copied (never a private key). The alternative is to exclude the provider hosts from the antivirus's HTTPS scanning. Standard library plus certifi.
On Linux (the college server) this is not needed: do not use it there.
"""
import os
import ssl
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT = os.path.join(ROOT, "data", "ca-bundle.pem")


def subject_text(der):
    """The subject of a DER certificate as text, read with the standard library only."""
    import tempfile
    pem = ssl.DER_cert_to_PEM_cert(der)
    handle, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(handle, "w") as out:
            out.write(pem)
        decoded = ssl._ssl._test_decode_cert(path)
    finally:
        os.remove(path)
    return " ".join(value for group in decoded.get("subject", ()) for _, value in group)


def find_roots(name_part, stores=("ROOT", "CA")):
    found = []
    for store in stores:
        for der, encoding, trust in ssl.enum_certificates(store):
            if encoding == "x509_asn" and name_part.lower() in subject_text(der).lower():
                found.append(der)
    return found


def main(argv=None, out=print):
    args = list(argv if argv is not None else sys.argv[1:])
    if len(args) != 1 or not hasattr(ssl, "enum_certificates"):
        out("usage (Windows): make_ca_bundle.py \"Avast Web/Mail Shield Root\"")
        return 2
    import certifi
    roots = find_roots(args[0])
    if not roots:
        out("No certificate with '%s' in its subject is in the Windows Root/CA stores; nothing written." % args[0])
        return 1
    with open(certifi.where(), "r", encoding="ascii", errors="ignore") as handle:
        base = handle.read()
    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    seen, extra = set(), []
    for der in roots:
        if der not in seen:
            seen.add(der)
            extra.append(ssl.DER_cert_to_PEM_cert(der))
    with open(OUTPUT, "w", encoding="ascii") as handle:
        handle.write(base.rstrip("\n") + "\n\n# added from the Windows trust store: %s\n" % args[0] + "".join(extra))
    out("Wrote %s (certifi + %d certificate(s) named '%s'). Verification stays on." % (OUTPUT, len(extra), args[0]))
    out("Add this line to .env (then the application's requests trust that bundle):   REQUESTS_CA_BUNDLE=%s" % OUTPUT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
