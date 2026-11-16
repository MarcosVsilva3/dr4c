"""Low-rate TCP connect checks for explicitly authorized, in-scope hosts."""
from __future__ import annotations

import socket

from dr4c.core.models import OpenPort
from dr4c.core.scope import Scope, ScopeError

MAX_PORT_PROBES = 500
PORT_TIMEOUT_SECONDS = 0.5


def scan_tcp_ports(hostname: str, scope: Scope, ports: list[int], scan_id: str,
                   max_probes: int = MAX_PORT_PROBES) -> tuple[list[OpenPort], int, bool]:
    if not scope.authorized or not scope.allow_port_scan:
        raise ScopeError("port scanning requires an authorized scope with allow_port_scan=true")
    if not ports:
        return [], 0, False
    if len(set(ports)) != len(ports) or len(ports) > 32:
        raise ScopeError("provide 1..32 unique TCP ports")
    for port in ports:
        if not 1 <= port <= 65535:
            raise ScopeError(f"invalid TCP port: {port}")
        if port not in scope.allowed_ports:
            raise ScopeError(f"TCP port {port} is not in allowed_ports")
    addresses = scope.resolve_host(hostname, ports[0])
    found: list[OpenPort] = []
    attempted = 0
    truncated = False
    for address in addresses:
        for port in ports:
            if attempted >= max_probes:
                truncated = True
                return found, attempted, truncated
            attempted += 1
            try:
                connection = socket.create_connection(
                    (address, port), timeout=PORT_TIMEOUT_SECONDS
                )
            except OSError:
                continue
            else:
                connection.close()
                found.append(OpenPort(hostname, address, port, "open", scan_id))
    return found, attempted, truncated
