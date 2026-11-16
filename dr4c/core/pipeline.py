"""Version 0.1.0 Core Recon orchestration."""
from __future__ import annotations

import secrets
import ipaddress
from pathlib import Path
from urllib.parse import urljoin

from dr4c.core.models import Asset, DNSRecord, HTTPService, ScanResult
from dr4c.core.scope import Scope, ScopeError, normalize_domain
from dr4c.discovery.dns_resolver import detect_wildcard, resolve
from dr4c.discovery.passive import crtsh
from dr4c.modules.http_probe import GoHTTPClient
from dr4c.modules.port_scan import MAX_PORT_PROBES, scan_tcp_ports

MAX_DISCOVERED_HOSTS = 50


def classify_200(candidate: HTTPService, baseline: HTTPService) -> tuple[str, str]:
    if candidate.redirect_location and any(
        marker in candidate.redirect_location.lower()
        for marker in ("/login", "/signin", "/auth")
    ):
        return "authentication_required", "medium"
    if len(candidate.redirect_chain) > 1 and any(
        marker in part.lower() for part in candidate.redirect_chain[1:]
        for marker in ("/login", "/signin", "/auth")
    ):
        return "authentication_required", "medium"
    if candidate.status_code in (301, 302, 307, 308):
        return "redirect", "high"
    if candidate.status_code == 401:
        return "authentication_required", "high"
    if candidate.status_code == 403:
        return "access_denied", "high"
    if candidate.status_code != 200 or baseline.status_code != 200:
        return "inconclusive", "low"
    if candidate.fingerprint and candidate.fingerprint == baseline.fingerprint:
        return "generic_fallback", "high"
    if candidate.title and candidate.title == baseline.title:
        denom = max(candidate.response_size, baseline.response_size, 1)
        if abs(candidate.response_size - baseline.response_size) / denom <= 0.05:
            return "likely_soft_404", "medium"
    return "valid_response", "medium"


def run_recon(domain: str, scope: Scope, root: Path, passive: bool = True,
              active: bool = True, timeout: int = 10, concurrency: int = 10,
              max_response_bytes: int = 1_048_576, max_requests: int = 500,
              ports: list[int] | None = None) -> ScanResult:
    target = normalize_domain(domain)
    if not scope.authorized:
        raise ScopeError("recon requires an explicitly authorized scope")
    if target not in scope.domains:
        raise ScopeError("recon root must be explicitly listed in the authorized domains")
    if ports and (not scope.allow_port_scan or not scope.authorized):
        raise ScopeError("port scanning requires allow_port_scan=true in an authorized scope file")
    if ports and any(port not in scope.allowed_ports for port in ports):
        raise ScopeError("every requested TCP port must also appear in scope allowed_ports")
    result = ScanResult(target=target)
    hosts: dict[str, str] = {target: "user_input"}
    asset_keys: set[tuple[str, str]] = set()

    def add_asset(asset: Asset) -> None:
        key = (asset.asset_type, asset.value)
        if key not in asset_keys:
            asset_keys.add(key)
            result.assets.append(asset)

    if passive:
        found, error = crtsh(target, timeout=min(timeout, 15))
        ordered_found = [host for host in found if host != target]
        passive_limit = MAX_DISCOVERED_HOSTS - 1
        if len(ordered_found) > passive_limit:
            result.errors.append(f"passive results capped at {MAX_DISCOVERED_HOSTS} hosts")
        for host in ordered_found[:passive_limit]:
            if host == target:
                continue
            hosts.setdefault(host, "crt.sh")
        if error:
            result.errors.append(error)
    wildcard, wildcard_addresses = detect_wildcard(target) if active else (None, [])
    result.summary["wildcard_detected"] = int(wildcard is True)
    result.summary["wildcard_checked"] = int(active)
    if active and wildcard is None:
        result.errors.append("wildcard DNS status is inconclusive")
    result.summary["wildcard_address_count"] = len(wildcard_addresses)
    if active:
        wordlist = root / "wordlists" / "subdomains.txt"
        candidates = [line.strip().lower() for line in wordlist.read_text(encoding="utf-8").splitlines()
                      if line.strip() and not line.lstrip().startswith("#")]
        for label in candidates:
            if len(hosts) >= MAX_DISCOVERED_HOSTS:
                result.errors.append(f"host inventory capped at {MAX_DISCOVERED_HOSTS} hosts")
                break
            host = f"{label}.{target}"
            dns = resolve(host)
            if dns.addresses and not (wildcard is True and set(dns.addresses) == set(wildcard_addresses)):
                hosts.setdefault(host, "active_dns")
    result.summary["passive_subdomains"] = sum(source == "crt.sh" for source in hosts.values())
    result.summary["unique_hosts"] = len(hosts)
    for host, source in sorted(hosts.items()):
        dns = resolve(host) if active else None
        add_asset(Asset("subdomain" if host != target else "domain", host, source,
                        result.scan_id, parent_asset=target))
        for address in (dns.addresses if dns else []):
            add_asset(Asset("IP", address, "system_resolver", result.scan_id,
                            parent_asset=host))
            record_type = "A" if ipaddress.ip_address(address).version == 4 else "AAAA"
            result.dns_records.append(DNSRecord(host, record_type, address, "system_resolver", result.scan_id))
        if active:
            result.summary["dns_resolved"] = result.summary.get("dns_resolved", 0) + bool(dns.addresses)
            result.summary["dns_unresolved"] = result.summary.get("dns_unresolved", 0) + (not bool(dns.addresses))
        if dns and dns.error and source != "user_input":
            result.errors.append(f"DNS {host}: {dns.error}")
    if ports:
        probes = 0
        ordered_hosts = [target] + sorted(host for host in hosts if host != target)
        for host in ordered_hosts:
            remaining = MAX_PORT_PROBES - probes
            if remaining <= 0:
                result.errors.append(f"port scan capped at {MAX_PORT_PROBES} TCP connection attempts")
                break
            try:
                found_ports, attempted, truncated = scan_tcp_ports(
                    host, scope, ports, result.scan_id, remaining
                )
            except ScopeError as exc:
                result.errors.append(f"port scan {host}: {exc}")
                continue
            result.open_ports.extend(found_ports)
            probes += attempted
            if truncated:
                result.errors.append(f"port scan capped at {MAX_PORT_PROBES} TCP connection attempts")
                break
        result.summary["port_probes"] = probes
        result.summary["open_ports"] = len(result.open_ports)
    if active:
        wordlist = root / "wordlists" / "common-paths.txt"
        paths = ["/"] + [
            "/" + line.strip().lstrip("/") for line in wordlist.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#") and line.strip() != "/"
        ]
        request_count = 0
        request_limit_reached = False
        ordered_hosts = [target] + sorted(host for host in hosts if host != target)
        with GoHTTPClient(root, timeout=timeout, concurrency=concurrency,
                          max_response_bytes=max_response_bytes) as client:
            for host in ordered_hosts:
                for scheme in ("https", "http"):
                    if request_count >= max_requests:
                        request_limit_reached = True
                        break
                    base = f"{scheme}://{host}/"
                    baseline_url = urljoin(base, f"dr4c-not-found-{secrets.token_hex(10)}")
                    batch_urls = [baseline_url] + [urljoin(base, path.lstrip("/")) for path in paths]
                    remaining = max_requests - request_count
                    scheduled_urls = batch_urls[:remaining]
                    services = client.probe_batch(scheduled_urls, scope)
                    request_count += len(scheduled_urls)
                    baseline = services[0]
                    scheduled_paths = paths[:max(0, len(services) - 1)]
                    for path, service in zip(scheduled_paths, services[1:], strict=True):
                        if path != "/":
                            service.classification, service.confidence = classify_200(service, baseline)
                        result.http_services.append(service)
                    if len(scheduled_urls) < len(batch_urls):
                        request_limit_reached = True
                        break
                if request_limit_reached:
                    break
        result.summary["http_requests"] = request_count
        if request_limit_reached:
            result.errors.append(f"HTTP request budget reached ({max_requests})")
    result.summary["http_targets"] = len(result.http_services)
    result.summary["http_active"] = sum(service.status_code is not None for service in result.http_services)
    result.summary["http_200"] = sum(service.status_code == 200 for service in result.http_services)
    from urllib.parse import urlsplit
    result.summary["path_observations"] = sum(urlsplit(service.target).path not in ("", "/")
                                                for service in result.http_services)
    return result
