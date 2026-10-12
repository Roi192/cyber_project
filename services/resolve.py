"""Public IP addresses of a website name (Phase F3.22) - the only place in the application that asks the operating system's resolver anything.

AbuseIPDB reports on IP ADDRESSES, so the application first needs the address a website name resolves to. Only a PUBLIC (globally routable) address may ever be sent to a third party:
loopback, private (RFC 1918 / unique local), link-local, multicast, reserved, unspecified and carrier-grade-NAT addresses are dropped here and again in the provider. An IPv4 address
wrapped in IPv6 (::ffff:10.0.0.1) is judged as the IPv4 address it contains. The lookup is bounded by a timeout (the resolver itself has none) and never raises.
Standard library only; Python 3.8 compatible.
"""
import ipaddress
import socket
import threading

RESOLVE_TIMEOUT_SECONDS = 2.0
MAX_ADDRESSES = 4


def is_public(text):
    """True only for a syntactically valid, globally routable address."""
    if not isinstance(text, str):
        return False
    try:
        ip = ipaddress.ip_address(text.strip())
    except ValueError:
        return False
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return bool(ip.is_global) and not ip.is_multicast


def normalized(text):
    """The canonical text of a public address, or None."""
    if not is_public(text):
        return None
    ip = ipaddress.ip_address(text.strip())
    mapped = getattr(ip, "ipv4_mapped", None)
    return str(mapped if mapped is not None else ip)


def public_addresses(name, timeout=RESOLVE_TIMEOUT_SECONDS, limit=MAX_ADDRESSES):
    """[public address text, IPv4 first] for a website name (or the address itself when `name` is an address). [] when it does not resolve, resolves only to non-public
    addresses, or the resolver does not answer in time."""
    if not isinstance(name, str) or not name.strip():
        return []
    name = name.strip().rstrip(".")
    direct = normalized(name)
    if direct:
        return [direct]
    try:
        ipaddress.ip_address(name)
        return []                                          # an address, but not a public one
    except ValueError:
        pass
    found = []

    def work():
        try:
            for info in socket.getaddrinfo(name, None, type=socket.SOCK_STREAM):
                found.append(info[4][0])
        except (OSError, UnicodeError, ValueError):
            pass

    thread = threading.Thread(target=work)
    thread.daemon = True
    thread.start()
    thread.join(timeout)
    out = []
    for text in sorted(list(found), key=lambda t: (":" in t, t)):          # IPv4 first
        ip = normalized(text.split("%")[0])
        if ip and ip not in out:
            out.append(ip)
    return out[:limit]
