"""Tests for netscan.py. Run with:  python -m unittest discover tests"""

import csv
import os
import socket
import sys
import tempfile
import threading
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import netscan  # noqa: E402


class TestPorts(unittest.TestCase):
    def test_parse_ports_sorts_and_dedupes(self):
        self.assertEqual(netscan.parse_ports("443, 22,22,80"), [22, 80, 443])

    def test_parse_ports_rejects_out_of_range(self):
        with self.assertRaises(Exception):
            netscan.parse_ports("70000")

    def test_port_open_detects_listening_port(self):
        # Open a real port on this machine, then check the scanner sees it.
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen()
        port = server.getsockname()[1]
        threading.Thread(target=lambda: server.accept()[0].close(), daemon=True).start()
        try:
            self.assertTrue(netscan.port_open("127.0.0.1", port))
        finally:
            server.close()


class TestPingCommand(unittest.TestCase):
    def test_windows_uses_milliseconds(self):
        with mock.patch("platform.system", return_value="Windows"):
            self.assertEqual(netscan.ping_command("10.0.0.1", 1), ["ping", "-n", "1", "-w", "1000", "10.0.0.1"])

    def test_linux_uses_seconds(self):
        with mock.patch("platform.system", return_value="Linux"):
            self.assertEqual(netscan.ping_command("10.0.0.1", 1), ["ping", "-c", "1", "-W", "1", "10.0.0.1"])


class TestScanHost(unittest.TestCase):
    def test_offline_host_returns_none(self):
        with mock.patch.object(netscan, "ping", return_value=None), \
             mock.patch.object(netscan, "port_open", return_value=False):
            self.assertIsNone(netscan.scan_host("10.0.0.5", [22], 1, 0.1, True))

    def test_ping_blocked_but_port_open_counts_as_online(self):
        with mock.patch.object(netscan, "ping", return_value=None), \
             mock.patch.object(netscan, "port_open", side_effect=lambda ip, p, t: p == 3389), \
             mock.patch.object(netscan, "reverse_dns", return_value="desk-01"):
            host = netscan.scan_host("10.0.0.5", [22, 3389], 1, 0.1, True)
        self.assertEqual(host.open_ports, [3389])
        self.assertEqual(host.risky_ports, [3389])


class TestReports(unittest.TestCase):
    def setUp(self):
        self.hosts = [netscan.Host("10.0.0.1", "router", [53, 443], 1.2),
                      netscan.Host("10.0.0.20", "", [445], None)]

    def test_csv_has_one_row_per_host(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "out.csv")
            netscan.write_csv(self.hosts, path)
            with open(path, newline="") as f:
                rows = list(csv.DictReader(f))
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[1]["risky_ports"], "445")

    def test_html_report_flags_risky_host(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "out.html")
            netscan.write_html(self.hosts, "10.0.0.0/24", 3.0, path)
            with open(path, encoding="utf-8") as f:
                page = f.read()
        self.assertIn("class='risk'", page)
        self.assertIn("10.0.0.20", page)


if __name__ == "__main__":
    unittest.main()
