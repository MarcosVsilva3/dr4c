"""Shared, JSON-serializable Core Recon records."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(slots=True)
class Asset:
    asset_type: str
    value: str
    source: str
    scan_id: str
    parent_asset: str | None = None
    scope_status: str = "in_scope"
    asset_id: str = field(default_factory=lambda: str(uuid4()))
    first_seen: str = field(default_factory=utc_now)
    last_seen: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class HTTPService:
    target: str
    status_code: int | None
    final_url: str
    content_type: str = ""
    response_size: int = 0
    duration_ms: int = 0
    redirected: bool = False
    redirect_location: str = ""
    title: str = ""
    fingerprint: str = ""
    content_length: int = 0
    server: str = ""
    protocol: str = ""
    redirect_chain: list[str] = field(default_factory=list)
    tls_subject: str = ""
    tls_issuer: str = ""
    tls_not_after: str = ""
    tls_version: str = ""
    tls_sans: list[str] = field(default_factory=list)
    classification: str = "inconclusive"
    confidence: str = "low"
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class DNSRecord:
    hostname: str
    record_type: str
    value: str
    source: str
    scan_id: str
    ttl: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class OpenPort:
    hostname: str
    address: str
    port: int
    state: str
    scan_id: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ScanResult:
    scan_id: str = field(default_factory=lambda: str(uuid4()))
    target: str = ""
    started_at: str = field(default_factory=utc_now)
    assets: list[Asset] = field(default_factory=list)
    dns_records: list[DNSRecord] = field(default_factory=list)
    open_ports: list[OpenPort] = field(default_factory=list)
    http_services: list[HTTPService] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "started_at": self.started_at,
            "assets": [asset.to_dict() for asset in self.assets],
            "dns_records": [record.to_dict() for record in self.dns_records],
            "open_ports": [record.to_dict() for record in self.open_ports],
            "http_services": [service.to_dict() for service in self.http_services],
            "errors": self.errors,
            "summary": self.summary,
        }
