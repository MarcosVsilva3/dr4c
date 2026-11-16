"""Python adapter for the bounded Go HTTP engine."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from dr4c.core.models import HTTPService
from dr4c.core.scope import Scope, ScopeError


class EngineError(RuntimeError):
    pass


class GoHTTPClient:
    def __init__(self, root: Path, timeout: int = 10, concurrency: int = 10,
                 max_response_bytes: int = 1_048_576):
        self.root = root
        self.timeout = timeout
        self.concurrency = concurrency
        self.max_response_bytes = max_response_bytes
        self.binary = root / "go-engine" / "dr4c-http"
        self.process: subprocess.Popen[str] | None = None

    def __enter__(self) -> "GoHTTPClient":
        if not self.binary.is_file():
            built = subprocess.run(
                ["sh", str(self.root / "scripts" / "go.sh"), "build", "-buildvcs=false",
                 "-o", str(self.binary), "./cmd/dr4c-http"],
                cwd=self.root / "go-engine", text=True, capture_output=True, check=False,
            )
            if built.returncode:
                raise EngineError(f"could not build Go HTTP engine: {built.stderr.strip()}")
        self.process = subprocess.Popen(
            [str(self.binary)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=1,
        )
        return self

    def __exit__(self, *_: object) -> None:
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
            if self.process.stdin:
                self.process.stdin.close()
            if self.process.stdout:
                self.process.stdout.close()
            if self.process.stderr:
                self.process.stderr.close()
            self.process = None

    def probe(self, url: str, scope: Scope, max_redirects: int = 5) -> HTTPService:
        current = url
        last: dict = {}
        original = url
        redirect_chain = [url]
        for hop in range(max_redirects + 1):
            try:
                scope.validate_url(current, resolve=False)
                host = urlsplit(current).hostname
                assert host
                parsed = urlsplit(current)
                port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
                addresses = scope.resolve_host(host, port)
                last = self._request(current, addresses)
            except ScopeError as exc:
                return HTTPService(
                    original, last.get("status_code"), current,
                    content_type=last.get("content_type", ""),
                    response_size=last.get("response_size", 0),
                    duration_ms=last.get("duration_ms", 0),
                    redirected=(current != original), title=last.get("title", ""),
            redirect_location=last.get("final_url", "") if last.get("redirected") else "",
                    fingerprint=last.get("fingerprint", ""),
                    content_length=last.get("content_length", 0), server=last.get("server", ""),
                    protocol=last.get("protocol", ""), redirect_chain=redirect_chain,
                    tls_subject=last.get("tls_subject", ""), tls_issuer=last.get("tls_issuer", ""),
                    tls_not_after=last.get("tls_not_after", ""), tls_version=last.get("tls_version", ""),
                    tls_sans=last.get("tls_sans", []), error=str(exc),
                )
            except (OSError, EngineError) as exc:
                return HTTPService(original, None, current, error=str(exc))
            if not last.get("redirected"):
                break
            location = last.get("final_url", "")
            if not location:
                break
            if hop == max_redirects:
                last["error"] = "redirect limit exceeded"
                break
            current = urljoin(current, location)
            redirect_chain.append(current)
        return HTTPService(
            target=original, status_code=last.get("status_code"), final_url=current,
            content_type=last.get("content_type", ""), response_size=last.get("response_size", 0),
            duration_ms=last.get("duration_ms", 0), redirected=(current != original),
            title=last.get("title", ""), fingerprint=last.get("fingerprint", ""),
            content_length=last.get("content_length", 0), server=last.get("server", ""),
            protocol=last.get("protocol", ""), redirect_chain=redirect_chain,
            tls_subject=last.get("tls_subject", ""), tls_issuer=last.get("tls_issuer", ""),
            tls_not_after=last.get("tls_not_after", ""), tls_version=last.get("tls_version", ""),
            tls_sans=last.get("tls_sans", []),
            error=last.get("error", ""),
        )

    def probe_batch(self, urls: list[str], scope: Scope) -> list[HTTPService]:
        """Probe one origin concurrently; record redirects without following them."""
        if not urls:
            return []
        try:
            parsed_urls = []
            for target in urls:
                scope.validate_url(target, resolve=False)
                parsed_urls.append(urlsplit(target))
            first = parsed_urls[0]
            origin = (first.scheme.lower(), (first.hostname or "").lower(), first.port)
            if any((item.scheme.lower(), (item.hostname or "").lower(), item.port) != origin
                   for item in parsed_urls[1:]):
                raise ScopeError("a probe batch must contain one origin")
            host = first.hostname
            assert host
            port = first.port if first.port is not None else (443 if first.scheme == "https" else 80)
            addresses = scope.resolve_host(host, port)
            response = self._request_batch(urls, addresses)
            rows = response.get("results")
            if not isinstance(rows, list) or len(rows) != len(urls):
                raise EngineError("Go engine returned an incomplete batch response")
            services = []
            for target, row in zip(urls, rows, strict=True):
                location = row.get("final_url", "") if row.get("redirected") else ""
                services.append(HTTPService(
                    target=target, status_code=row.get("status_code"), final_url=target,
                    content_type=row.get("content_type", ""),
                    response_size=row.get("response_size", 0),
                    duration_ms=row.get("duration_ms", 0),
                    redirected=bool(row.get("redirected")), redirect_location=location,
                    title=row.get("title", ""), fingerprint=row.get("fingerprint", ""),
                    content_length=row.get("content_length", 0), server=row.get("server", ""),
                    protocol=row.get("protocol", ""), redirect_chain=[target],
                    tls_subject=row.get("tls_subject", ""), tls_issuer=row.get("tls_issuer", ""),
                    tls_not_after=row.get("tls_not_after", ""), tls_version=row.get("tls_version", ""),
                    tls_sans=row.get("tls_sans", []), error=row.get("error", ""),
                ))
            return services
        except ScopeError as exc:
            return [HTTPService(target, None, target, error=str(exc)) for target in urls]

    def _request_batch(self, targets: list[str], addresses: list[str]) -> dict:
        return self._exchange({
            "operation": "probe_batch", "targets": targets, "resolved_ips": addresses,
            "timeout": self.timeout, "max_concurrency": self.concurrency,
            "max_response_bytes": self.max_response_bytes,
        })

    def _request(self, target: str, addresses: list[str]) -> dict:
        return self._exchange({
            "operation": "probe", "target": target, "resolved_ips": addresses,
            "timeout": self.timeout, "max_concurrency": self.concurrency,
            "max_response_bytes": self.max_response_bytes,
        })

    def _exchange(self, message: dict) -> dict:
        if not self.process or not self.process.stdin or not self.process.stdout:
            raise EngineError("Go engine is not running")
        try:
            self.process.stdin.write(json.dumps(message) + "\n")
            self.process.stdin.flush()
            line = self.process.stdout.readline()
        except OSError as exc:
            raise EngineError(f"Go engine communication failed: {exc}") from exc
        if not line:
            error = self.process.stderr.read() if self.process.stderr else ""
            raise EngineError(f"Go engine exited unexpectedly: {error.strip()}")
        try:
            result = json.loads(line)
        except json.JSONDecodeError as exc:
            raise EngineError("Go engine returned malformed JSON") from exc
        if result.get("error") and not result.get("target"):
            raise EngineError(result["error"])
        return result
