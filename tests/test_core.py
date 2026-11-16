import tempfile
import sqlite3
import unittest
from pathlib import Path
from unittest.mock import patch

from dr4c.core.models import Asset, OpenPort, ScanResult
from dr4c.core.scope import Scope, ScopeError, normalize_domain
from dr4c.storage.database import Database


class ScopeTests(unittest.TestCase):
    def test_normalizes_domain(self):
        self.assertEqual(normalize_domain("WWW.Example.COM."), "www.example.com")

    def test_scope_matches_label_boundary(self):
        scope = Scope(("example.com",), authorized=True)
        self.assertEqual(scope.validate_domain("api.example.com"), "api.example.com")
        with self.assertRaises(ScopeError):
            scope.validate_domain("notexample.com")

    def test_domain_argument_creates_narrow_default_scope(self):
        scope = Scope.for_domain("Example.com")
        self.assertEqual(scope.domains, ("example.com",))
        self.assertEqual(scope.allowed_ports, (80, 443))
        self.assertFalse(scope.allow_private)
        self.assertEqual(scope.validate_domain("api.example.com"), "api.example.com")

    def test_private_ip_is_blocked_even_when_explicitly_in_range(self):
        import ipaddress
        scope = Scope((), (ipaddress.ip_network("127.0.0.0/8"),), authorized=True)
        with self.assertRaises(ScopeError):
            scope.validate_url("http://127.0.0.1")

    def test_private_ip_requires_explicit_lab_setting(self):
        import ipaddress
        scope = Scope((), (ipaddress.ip_network("127.0.0.0/8"),), (80,), True, True)
        self.assertEqual(scope.validate_url("http://127.0.0.1", resolve=False), "http://127.0.0.1")

    def test_rejects_mixed_public_and_private_dns_answers(self):
        scope = Scope(("example.com",), authorized=True)
        answers = [
            (None, None, None, None, ("93.184.216.34", 80)),
            (None, None, None, None, ("127.0.0.1", 80)),
        ]
        with patch("dr4c.core.scope.socket.getaddrinfo", return_value=answers):
            with self.assertRaises(ScopeError):
                scope.resolve_host("example.com", 80)

    def test_rejects_non_global_shared_address_from_dns(self):
        scope = Scope(("example.com",), authorized=True)
        answers = [(None, None, None, None, ("100.64.0.1", 80))]
        with patch("dr4c.core.scope.socket.getaddrinfo", return_value=answers):
            with self.assertRaises(ScopeError):
                scope.resolve_host("example.com", 80)

    def test_rejects_non_http_url_and_credentials(self):
        scope = Scope(("example.com",), authorized=True)
        for url in ("file:///etc/passwd", "https://user:pass@example.com"):
            with self.subTest(url=url), self.assertRaises(ScopeError):
                scope.validate_url(url, resolve=False)


class StorageTests(unittest.TestCase):
    def test_saves_scan_and_asset(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = ScanResult(target="example.com")
            result.assets.append(Asset("domain", "example.com", "input", result.scan_id))
            result.open_ports.append(OpenPort("example.com", "93.184.216.34", 443, "open", result.scan_id))
            db = Database(Path(tmp) / "scan.sqlite3")
            db.save_scan(result)
            stored = db.get_scan(result.scan_id)
            self.assertEqual(stored["target"], "example.com")
            self.assertEqual(stored["assets"][0]["value"], "example.com")
            self.assertEqual(stored["open_ports"][0]["port"], 443)
            with sqlite3.connect(Path(tmp) / "scan.sqlite3") as connection:
                self.assertEqual(connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0], 2)
                self.assertEqual(connection.execute("SELECT port FROM open_ports").fetchone()[0], 443)


if __name__ == "__main__":
    unittest.main()
