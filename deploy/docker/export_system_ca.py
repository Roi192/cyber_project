"""OPTIONAL, Windows only: copy the PUBLIC root certificate of a proxy/antivirus that re-signs HTTPS on this PC into docker_test/extra-ca/, so that the test image can verify PyPI.

    python docker_test\\export_system_ca.py "Avast Web/Mail Shield Root"

Why: Docker traffic from this PC passes through the same HTTPS-scanning software as the PC itself, so pip inside the container fails with CERTIFICATE_VERIFY_FAILED. Windows trusts the
software's root; the container does not. This writes that one PUBLIC certificate (never a private key) as a .crt file; the Dockerfile adds it to the IMAGE's own certificate store
(update-ca-certificates). Certificate verification stays ON everywhere. Delete extra-ca/*.crt to go back to the stock Ubuntu trust store. Not needed on a network without such software.
"""
import os
import ssl
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "extra-ca")


def subject_text(der):
    import tempfile
    handle, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(handle, "w") as out:
            out.write(ssl.DER_cert_to_PEM_cert(der))
        decoded = ssl._ssl._test_decode_cert(path)
    finally:
        os.remove(path)
    return " ".join(value for group in decoded.get("subject", ()) for _, value in group)


def main(argv=None):
    args = list(argv if argv is not None else sys.argv[1:])
    if len(args) != 1 or not hasattr(ssl, "enum_certificates"):
        print("usage (Windows): export_system_ca.py \"Avast Web/Mail Shield Root\"")
        return 2
    found = []
    for store in ("ROOT", "CA"):
        for der, encoding, trust in ssl.enum_certificates(store):
            if encoding == "x509_asn" and args[0].lower() in subject_text(der).lower() and der not in found:
                found.append(der)
    if not found:
        print("No certificate with '%s' in its subject is in the Windows Root/CA stores; nothing written." % args[0])
        return 1
    os.makedirs(OUT, exist_ok=True)
    for index, der in enumerate(found):
        name = "system-ca-%d.crt" % (index + 1)
        with open(os.path.join(OUT, name), "w", encoding="ascii", newline="\n") as handle:
            handle.write(ssl.DER_cert_to_PEM_cert(der))
        print("Wrote extra-ca/%s (public certificate '%s')." % (name, args[0]))
    print("Build with the system store for pip:  $env:PIP_CERT_FILE='/etc/ssl/certs/ca-certificates.crt'; docker compose -f docker_test/docker-compose.college-test.yml build")
    return 0


if __name__ == "__main__":
    sys.exit(main())
