"""System resolver wrapper for A/AAAA intelligence and wildcard checks."""
from __future__ import annotations

import socket
from dataclasses import dataclass


@dataclass(slots=True)
class DNSResult:
    hostname: str
    addresses: list[str]
    error: str = ""
    nxdomain: bool = False


def resolve(hostname: str) -> DNSResult:
    try:
        values = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        addresses = sorted({record[4][0] for record in values})
        return DNSResult(hostname, addresses)
    except socket.gaierror as exc:
        return DNSResult(hostname, [], str(exc), nxdomain=_is_nxdomain(exc))


# getaddrinfo error codes meaning "name does not exist" on Linux, macOS and Windows.
_NXDOMAIN_CODES = {
    code for code in (
        getattr(socket, "EAI_NONAME", None),
        getattr(socket, "EAI_NODATA", None),
        11001,  # Windows WSAHOST_NOT_FOUND
        11004,  # Windows WSANO_DATA
    ) if code is not None
}


def _is_nxdomain(exc: socket.gaierror) -> bool:
    return exc.errno in _NXDOMAIN_CODES


def detect_wildcard(domain: str) -> tuple[bool | None, list[str]]:
    """Compare two unpredictable labels; None means resolver failure is ambiguous."""
    import secrets
    found: list[set[str]] = []
    for _ in range(2):
        result = resolve(f"dr4c-{secrets.token_hex(8)}.{domain}")
        if result.addresses:
            found.append(set(result.addresses))
        elif not result.nxdomain:
            return None, []
        else:
            found.append(set())
    if not found[0] and not found[1]:
        return False, []
    return found[0] == found[1] and bool(found[0]), sorted(found[0] & found[1])
