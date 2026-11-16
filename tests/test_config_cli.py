import tempfile
import unittest
import json
import io
import contextlib
from pathlib import Path
from unittest.mock import patch

from dr4c.config import load_config
from dr4c.core.models import HTTPService
from dr4c.core.models import ScanResult
from dr4c.core.pipeline import run_recon
from dr4c.core.scope import Scope, ScopeError
from dr4c.discovery.dns_resolver import DNSResult


class ConfigTests(unittest.TestCase):
    def test_loads_default_yaml_subset(self):
        root = Path(__file__).resolve().parents[1]
        config = load_config(root / "configs" / "default.yaml")
        self.assertEqual(config.http_timeout_seconds, 10)
        self.assertEqual(config.http_max_concurrency, 10)
        self.assertEqual(config.http_max_requests, 500)

    def test_rejects_unsafe_or_unknown_configuration(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.yaml"
            path.write_text("http:\n  max_concurrency: 1000\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_config(path)

    def test_scope_requires_explicit_authorization(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scope.json"
            path.write_text('{"authorized": false, "domains": ["example.com"]}', encoding="utf-8")
            with self.assertRaises(ScopeError):
                Scope.load(path)

    def test_recon_does_not_require_a_scope_file_argument(self):
        from dr4c.cli import parser
        args = parser().parse_args(["recon", "-d", "example.com"])
        self.assertIsNone(args.scope_file)

    def test_passive_pipeline_keeps_source_attribution(self):
        root = Path(__file__).resolve().parents[1]
        scope = Scope(("example.com",), authorized=True)
        with patch("dr4c.core.pipeline.crtsh", return_value=(["www.example.com"], None)):
            result = run_recon("example.com", scope, root, passive=True, active=False)
        self.assertEqual(result.summary["unique_hosts"], 2)
        self.assertIn("crt.sh", {asset.source for asset in result.assets})
        self.assertEqual(result.http_services, [])

    def test_active_pipeline_stores_dns_and_http_observations(self):
        root = Path(__file__).resolve().parents[1]
        scope = Scope(("example.com",), authorized=True)

        class FakeHTTP:
            def __init__(self, *_args, **_kwargs): pass
            def __enter__(self): return self
            def __exit__(self, *_args): pass
            def probe(self, url, _scope):
                if "dr4c-not-found" in url:
                    return HTTPService(url, 404, url)
                return HTTPService(url, 200, url, fingerprint="fixture", title="Example")
            def probe_batch(self, urls, scope):
                return [self.probe(url, scope) for url in urls]

        def fake_resolve(host):
            return DNSResult(host, ["93.184.216.34"] if host == "example.com" else [])

        with patch("dr4c.core.pipeline.resolve", side_effect=fake_resolve), \
             patch("dr4c.core.pipeline.detect_wildcard", return_value=(False, [])), \
             patch("dr4c.core.pipeline.GoHTTPClient", FakeHTTP):
            result = run_recon("example.com", scope, root, passive=False, active=True,
                               max_requests=10)
        self.assertEqual(result.dns_records[0].record_type, "A")
        self.assertEqual(result.dns_records[0].value, "93.184.216.34")
        self.assertGreater(result.summary["http_targets"], 0)
        self.assertEqual(result.summary["http_requests"], 10)
        self.assertTrue(any("request budget reached" in error for error in result.errors))

    def test_cli_shows_results_without_saving_by_default(self):
        from dr4c.cli import main
        with tempfile.TemporaryDirectory() as tmp:
            result = ScanResult(target="example.com")
            args = ["dr4c", "recon", "-d", "example.com", "--passive",
                    "--config", str(Path(__file__).resolve().parents[1] / "configs" / "default.yaml")]
            stdout = io.StringIO()
            with patch("sys.argv", args), patch("dr4c.cli.ROOT", Path(tmp)), \
                    patch("dr4c.cli.run_recon", return_value=result), \
                    contextlib.redirect_stdout(stdout):
                self.assertEqual(main(), 0)
            self.assertIn("Resultado da varredura: example.com", stdout.getvalue())
            self.assertIn("nenhum arquivo foi salvo", stdout.getvalue())
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_cli_saves_only_explicit_json_and_refuses_overwrite(self):
        from dr4c.cli import main
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "report.json"
            result = ScanResult(target="example.com")
            args = ["dr4c", "recon", "-d", "example.com", "--output", str(output),
                    "--salve", "--passive"]
            with patch("sys.argv", args), patch("dr4c.cli.run_recon", return_value=result), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(), 0)
            self.assertTrue(output.is_file())
            self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["target"], "example.com")
            self.assertEqual(len(list(Path(tmp).iterdir())), 1)
            with patch("sys.argv", args), patch("dr4c.cli.run_recon") as scan, \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(), 1)
                scan.assert_not_called()

    def test_cli_saves_default_report_under_results_when_requested(self):
        from dr4c.cli import main
        with tempfile.TemporaryDirectory() as tmp:
            result = ScanResult(target="example.com")
            args = ["dr4c", "recon", "-d", "example.com", "--salve", "--passive",
                    "--config", str(Path(__file__).resolve().parents[1] / "configs" / "default.yaml")]
            with patch("sys.argv", args), patch("dr4c.cli.ROOT", Path(tmp)), \
                    patch("dr4c.cli.run_recon", return_value=result), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(), 0)
            saved = list((Path(tmp) / "results").glob("*.json"))
            self.assertEqual(len(saved), 1)
            self.assertEqual(json.loads(saved[0].read_text(encoding="utf-8"))["target"], "example.com")
            self.assertEqual(list((Path(tmp) / "results").iterdir()), saved)

    def test_cli_requires_salve_for_custom_output_path(self):
        from dr4c.cli import main
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "report.json"
            args = ["dr4c", "recon", "-d", "example.com", "--output", str(output)]
            with patch("sys.argv", args), patch("dr4c.cli.run_recon") as scan, \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    main()
            self.assertEqual(raised.exception.code, 2)
            scan.assert_not_called()
            self.assertFalse(output.exists())

    def test_cli_port_scan_requires_scope_opt_in(self):
        from dr4c.cli import main
        args = ["dr4c", "recon", "-d", "example.com", "--ports", "22"]
        with patch("sys.argv", args), patch("dr4c.cli.run_recon") as scan, \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(), 1)
            scan.assert_not_called()


if __name__ == "__main__":
    unittest.main()
