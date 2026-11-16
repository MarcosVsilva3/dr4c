import socket
import unittest
from unittest.mock import patch

from dr4c.discovery.dns_resolver import detect_wildcard, resolve


def _raise(code, msg):
    def fake(*_args, **_kwargs):
        raise socket.gaierror(code, msg)
    return fake


class DNSResolverTests(unittest.TestCase):
    def test_nxdomain_detected_by_error_code_not_message(self):
        # macOS-style message must still be treated as NXDOMAIN.
        with patch("socket.getaddrinfo", _raise(socket.EAI_NONAME, "nodename nor servname provided, or not known")):
            self.assertTrue(resolve("x.example.com").nxdomain)
            self.assertEqual(detect_wildcard("example.com"), (False, []))

    def test_windows_host_not_found_code(self):
        with patch("socket.getaddrinfo", _raise(11001, "getaddrinfo failed")):
            self.assertTrue(resolve("x.example.com").nxdomain)

    def test_resolver_failure_is_inconclusive(self):
        with patch("socket.getaddrinfo", _raise(socket.EAI_AGAIN, "Temporary failure in name resolution")):
            self.assertFalse(resolve("x.example.com").nxdomain)
            self.assertEqual(detect_wildcard("example.com"), (None, []))


if __name__ == "__main__":
    unittest.main()
