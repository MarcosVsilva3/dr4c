"""Central authorization and destination validation for active requests."""
from __future__ import annotations

import ipaddress
import json
import socket
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


class ScopeError(ValueError):
    """Raised when a target falls outside the declared assessment scope."""


@dataclass(frozen=True, slots=True)
class Scope:
    domains: tuple[str, ...]
    ip_networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()
    allowed_ports: tuple[int, ...] = (80, 443)
    allow_private: bool = False
    authorized: bool = False
    allow_port_scan: bool = False

    @classmethod
    def for_domain(cls, domain: str) -> "Scope":
        """Build a narrow in-memory scope rooted at the operator-supplied domain."""
        return cls((normalize_domain(domain),), allowed_ports=(80, 443), authorized=True)

    @classmethod
    def load(cls, path: str | Path) -> "Scope":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ScopeError("scope file must contain a JSON object")
        if data.get("authorized") is not True:
            raise ScopeError("scope file must set authorized to true")
        domains = tuple(sorted({normalize_domain(x) for x in data.get("domains", [])}))
        networks = tuple(ipaddress.ip_network(x, strict=False) for x in data.get("ip_ranges", []))
        ports = tuple(sorted({int(x) for x in data.get("allowed_ports", [80, 443])}))
        if not domains and not networks:
            raise ScopeError("scope must contain at least one domain or IP range")
        if any(port < 1 or port > 65535 for port in ports):
            raise ScopeError("scope contains an invalid port")
        if not isinstance(data.get("allow_private", False), bool):
            raise ScopeError("allow_private must be a JSON boolean")
        if not isinstance(data.get("allow_port_scan", False), bool):
            raise ScopeError("allow_port_scan must be a JSON boolean")
        return cls(domains, networks, ports, data.get("allow_private", False), True,
                   data.get("allow_port_scan", False))

    def validate_domain(self, host: str) -> str:
        normalized = normalize_domain(host)
        try:
            address = ipaddress.ip_address(normalized)
        except ValueError:
            if not any(normalized == domain or normalized.endswith("." + domain) for domain in self.domains):
                raise ScopeError(f"host is outside authorized domains: {normalized}")
        else:
            if not any(address in network for network in self.ip_networks):
                raise ScopeError(f"IP address is outside authorized ranges: {address}")
            self._validate_ip(address)
        return normalized

    def validate_url(self, url: str, resolve: bool = True) -> str:
        if not self.authorized:
            raise ScopeError("active requests require an explicitly authorized scope")
        try:
            parsed = urlsplit(url)
            parsed_port = parsed.port
        except ValueError as exc:
            raise ScopeError("malformed URL or port") from exc
        if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
            raise ScopeError("only absolute HTTP(S) URLs are allowed")
        if parsed.username is not None or parsed.password is not None:
            raise ScopeError("URL user information is prohibited")
        host = self.validate_domain(parsed.hostname)
        port = parsed_port if parsed_port is not None else (443 if parsed.scheme.lower() == "https" else 80)
        if port not in self.allowed_ports:
            raise ScopeError(f"port {port} is not authorized")
        if resolve:
            self.resolve_host(host, port)
        return url

    def resolve_host(self, host: str, port: int) -> list[str]:
        """Resolve once, validate every answer, and return addresses to pin in transport."""
        normalized = self.validate_domain(host)
        try:
            address = ipaddress.ip_address(normalized)
        except ValueError:
            try:
                answers = socket.getaddrinfo(normalized, port, type=socket.SOCK_STREAM)
            except socket.gaierror as exc:
                raise ScopeError(f"could not resolve target safely: {normalized}") from exc
            addresses = sorted({ipaddress.ip_address(answer[4][0]).compressed for answer in answers})
        else:
            addresses = [address.compressed]
        if not addresses:
            raise ScopeError(f"no destination addresses for {normalized}")
        for raw in addresses:
            self._validate_ip(ipaddress.ip_address(raw))
        return addresses

    def _validate_ip(self, address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
        if not address.is_global and not (
            self.allow_private and any(address in network for network in self.ip_networks)
        ):
            raise ScopeError(f"destination IP is prohibited or not explicitly authorized: {address}")


def normalize_domain(value: str) -> str:
    host = value.strip().rstrip(".").lower()
    if not host or len(host) > 253 or ":" in host or "/" in host:
        raise ScopeError(f"invalid hostname: {value!r}")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        labels = host.split(".")
        if len(labels) < 2 or any(
            not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
            or not all(ch.isalnum() or ch == "-" for ch in label)
            for label in labels
        ):
            raise ScopeError(f"invalid hostname: {value!r}")
        return host
