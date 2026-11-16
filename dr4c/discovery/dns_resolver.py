"""System resolver wrapper for A/AAAA intelligence and wildcard checks."""
from __future__ import annotations

import socket
from dataclasses import dataclass


@dataclass(slots=True)
class DNSResult:
    hostname: str
    addresses: list[str]
    error: str = ""


def resolve(hostname: str) -> DNSResult:
    try:
        values = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        addresses = sorted({record[4][0] for record in values})
        return DNSResult(hostname, addresses)
    except socket.gaierror as exc:
        return DNSResult(hostname, [], str(exc))


def detect_wildcard(domain: str) -> tuple[bool | None, list[str]]:
    """Compare two unpredictable labels; None means resolver failure is ambiguous."""
    import secrets
    found: list[set[str]] = []
    for _ in range(2):
        result = resolve(f"dr4c-{secrets.token_hex(8)}.{domain}")
        if result.addresses:
            found.append(set(result.addresses))
        elif "Name or service not known" not in result.error and "NXDOMAIN" not in result.error:
            return None, []
        else:
            found.append(set())
    if not found[0] and not found[1]:
        return False, []
    return found[0] == found[1] and bool(found[0]), sorted(found[0] & found[1])
