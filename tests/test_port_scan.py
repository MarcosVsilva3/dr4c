import ipaddress
import socket
import unittest
from unittest.mock import MagicMock, patch

from dr4c.core.scope import Scope, ScopeError
from dr4c.cli import parse_ports
from dr4c.modules.port_scan import scan_tcp_ports


class PortScanTests(unittest.TestCase):
    def test_parse_ports_validates_count_range_and_duplicates(self):
        self.assertEqual(parse_ports("80, 443,8080"), [80, 443, 8080])
        for value in ("80,80", "0", "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_ports(value)

    def test_port_scan_requires_explicit_scope_opt_in(self):
        scope = Scope(("example.com",), allowed_ports=(80,), authorized=True)
        with self.assertRaises(ScopeError):
            scan_tcp_ports("example.com", scope, [80], "scan")

    def test_connect_scan_records_open_port_without_service_probing(self):
        scope = Scope(("example.com",), allowed_ports=(443,), authorized=True, allow_port_scan=True)
        connection = MagicMock()
        with patch("dr4c.modules.port_scan.Scope.resolve_host", return_value=["93.184.216.34"]), \
                patch("dr4c.modules.port_scan.socket.create_connection", return_value=connection) as connect:
            ports, attempts, truncated = scan_tcp_ports("example.com", scope, [443], "scan-1")
        self.assertEqual(attempts, 1)
        self.assertFalse(truncated)
        self.assertEqual((ports[0].hostname, ports[0].port, ports[0].state),
                         ("example.com", 443, "open"))
        connect.assert_called_once_with(("93.184.216.34", 443), timeout=0.5)
        connection.close.assert_called_once()

    def test_connect_scan_finds_a_real_local_listener(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        scope = Scope(
            (), (ipaddress.ip_network("127.0.0.1/32"),), (port,),
            allow_private=True, authorized=True, allow_port_scan=True,
        )
        try:
            ports, attempts, truncated = scan_tcp_ports("127.0.0.1", scope, [port], "local-scan")
            self.assertEqual(attempts, 1)
            self.assertFalse(truncated)
            self.assertEqual([(item.address, item.port, item.state) for item in ports],
                             [("127.0.0.1", port, "open")])
        finally:
            listener.close()


if __name__ == "__main__":
    unittest.main()
