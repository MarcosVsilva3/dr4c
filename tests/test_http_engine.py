import http.server
import ipaddress
import json
import subprocess
import threading
import unittest
from pathlib import Path

from dr4c.core.pipeline import classify_200
from dr4c.core.scope import Scope, ScopeError
from dr4c.core.models import HTTPService
from dr4c.modules.http_probe import GoHTTPClient


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://outside.example.invalid/outside")
            self.end_headers()
            return
        body = b"<html><title>Local Fixture</title>hello</html>"
        self.send_response(200 if self.path == "/" else 404)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


class GoHTTPIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def scope(self):
        return Scope((), (ipaddress.ip_network("127.0.0.1/32"),),
                     (self.port,), allow_private=True, authorized=True)

    def test_probe_uses_jsonl_engine_and_collects_metadata(self):
        root = Path(__file__).resolve().parents[1]
        with GoHTTPClient(root, timeout=2, max_response_bytes=256) as engine:
            result = engine.probe(f"http://127.0.0.1:{self.port}/", self.scope())
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.title, "Local Fixture")
        self.assertTrue(result.fingerprint)
        self.assertEqual(result.classification, "inconclusive")

    def test_batch_probe_records_redirect_without_fetching_its_destination(self):
        root = Path(__file__).resolve().parents[1]
        urls = [
            f"http://127.0.0.1:{self.port}/",
            f"http://127.0.0.1:{self.port}/redirect",
        ]
        with GoHTTPClient(root, timeout=2, concurrency=2) as engine:
            results = engine.probe_batch(urls, self.scope())
        self.assertEqual([item.status_code for item in results], [200, 302])
        self.assertEqual(results[1].redirect_location, "http://outside.example.invalid/outside")
        self.assertEqual(results[1].final_url, urls[1])

    def test_redirect_outside_scope_is_not_followed(self):
        root = Path(__file__).resolve().parents[1]
        with GoHTTPClient(root, timeout=2) as engine:
            result = engine.probe(f"http://127.0.0.1:{self.port}/redirect", self.scope())
        self.assertEqual(result.status_code, 302)
        self.assertIn("outside authorized domains", result.error)

    def test_soft_404_comparison_uses_multiple_signals(self):
        candidate = HTTPService("/fake", 200, "/fake", response_size=10, title="Same", fingerprint="x")
        baseline = HTTPService("/missing", 200, "/missing", response_size=10, title="Same", fingerprint="x")
        self.assertEqual(classify_200(candidate, baseline), ("generic_fallback", "high"))
        candidate.fingerprint = "different"
        self.assertEqual(classify_200(candidate, baseline), ("likely_soft_404", "medium"))

    def test_malformed_json_and_unknown_operation_return_structured_errors(self):
        binary = Path(__file__).resolve().parents[1] / "go-engine" / "dr4c-http"
        completed = subprocess.run(
            [str(binary)], input='not-json\n{"operation":"unknown"}\n',
            text=True, capture_output=True, check=True,
        )
        rows = [json.loads(line) for line in completed.stdout.splitlines()]
        self.assertEqual(rows[0]["error"], "malformed JSON request")
        self.assertEqual(rows[1]["error"], "unsupported operation")


if __name__ == "__main__":
    unittest.main()
