"""
tests.py — Unit tests
Network Port Scanner | Feba J Allwin
"""

import unittest
import json
import os
import tempfile
from unittest.mock import patch, MagicMock
from scanner import PortScanner, PortResult, ScanResult, SERVICE_DB
from reporter import Reporter


class TestServiceDatabase(unittest.TestCase):

    def test_well_known_ports(self):
        self.assertEqual(SERVICE_DB[22][0], "SSH")
        self.assertEqual(SERVICE_DB[80][0], "HTTP")
        self.assertEqual(SERVICE_DB[443][0], "HTTPS")
        self.assertEqual(SERVICE_DB[3306][0], "MySQL")
        self.assertEqual(SERVICE_DB[27017][0], "MongoDB")

    def test_database_not_empty(self):
        self.assertGreater(len(SERVICE_DB), 50)

    def test_all_entries_have_name_and_desc(self):
        for port, (name, desc) in SERVICE_DB.items():
            self.assertIsInstance(port, int)
            self.assertIsInstance(name, str)
            self.assertIsInstance(desc, str)
            self.assertGreater(len(name), 0)
            self.assertGreater(len(desc), 0)


class TestPortResult(unittest.TestCase):

    def test_to_dict(self):
        r = PortResult(
            port=80, state="open", service="HTTP",
            description="HyperText Transfer Protocol",
            banner="HTTP/1.1 200 OK",
            latency_ms=12.5, severity="INFO"
        )
        d = r.to_dict()
        self.assertEqual(d["port"], 80)
        self.assertEqual(d["state"], "open")
        self.assertEqual(d["service"], "HTTP")
        self.assertEqual(d["severity"], "INFO")
        self.assertIn("timestamp", d)

    def test_banner_truncated(self):
        r = PortResult(port=80, state="open", service="HTTP",
                       description="", banner="A" * 500,
                       latency_ms=1.0, severity="INFO")
        d = r.to_dict()
        self.assertLessEqual(len(d["banner"]), 200)


class TestBannerFingerprint(unittest.TestCase):

    def setUp(self):
        self.scanner = self._make_scanner()

    @patch("socket.gethostbyname", return_value="127.0.0.1")
    @patch("socket.gethostbyaddr", return_value=("localhost", [], ["127.0.0.1"]))
    def _make_scanner(self, *_):
        with patch("socket.gethostbyname", return_value="127.0.0.1"), \
             patch("socket.gethostbyaddr", return_value=("localhost", [], ["127.0.0.1"])):
            return PortScanner("localhost", port_range=(80, 80))

    def test_ssh_banner(self):
        svc, desc = self.scanner._fingerprint_banner("SSH-2.0-OpenSSH_8.9")
        self.assertEqual(svc, "SSH")

    def test_http_banner(self):
        svc, desc = self.scanner._fingerprint_banner("HTTP/1.1 200 OK\r\nServer: nginx")
        self.assertEqual(svc, "HTTP")

    def test_mysql_banner(self):
        svc, desc = self.scanner._fingerprint_banner("5.7.36-MySQL Community Server")
        self.assertEqual(svc, "MySQL")

    def test_unknown_banner(self):
        svc, desc = self.scanner._fingerprint_banner("XYZPROTO/1.0 HELLO")
        self.assertEqual(svc, "Unknown")


class TestReporter(unittest.TestCase):

    def _make_result(self):
        open_ports = [
            PortResult(port=22, state="open", service="SSH",
                       description="Secure Shell", banner="SSH-2.0-OpenSSH",
                       latency_ms=5.2, severity="INFO"),
            PortResult(port=80, state="open", service="HTTP",
                       description="HyperText Transfer Protocol", banner="",
                       latency_ms=8.1, severity="INFO"),
            PortResult(port=2375, state="open", service="Docker",
                       description="Docker Daemon (unencrypted)", banner="",
                       latency_ms=3.0, severity="CRITICAL"),
        ]
        return ScanResult(
            target="192.168.1.1",
            ip="192.168.1.1",
            hostname="router.local",
            os_hint="Linux / macOS (TTL≈64)",
            start_time="2026-06-18T10:00:00",
            end_time="2026-06-18T10:00:45",
            duration_sec=45.3,
            total_ports=1024,
            open_ports=open_ports,
            closed_count=1000,
            filtered_count=21,
        )

    def test_json_report(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            Reporter.to_json(self._make_result(), path)
            with open(path) as f:
                data = json.load(f)
            self.assertIn("scan_metadata", data)
            self.assertIn("open_ports", data)
            self.assertEqual(len(data["open_ports"]), 3)
            self.assertEqual(data["summary"]["critical"], 1)
        finally:
            os.unlink(path)

    def test_csv_report(self):
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            path = f.name
        try:
            Reporter.to_csv(self._make_result(), path)
            with open(path) as f:
                content = f.read()
            self.assertIn("port", content)
            self.assertIn("severity", content)
            self.assertIn("22", content)
        finally:
            os.unlink(path)

    def test_txt_report(self):
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            path = f.name
        try:
            Reporter.to_txt(self._make_result(), path)
            with open(path) as f:
                content = f.read()
            self.assertIn("NETWORK PORT SCANNER", content)
            self.assertIn("192.168.1.1", content)
            self.assertIn("OPEN PORTS", content)
        finally:
            os.unlink(path)

    def test_html_report(self):
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            path = f.name
        try:
            Reporter.to_html(self._make_result(), path)
            with open(path) as f:
                content = f.read()
            self.assertIn("<!DOCTYPE html>", content)
            self.assertIn("192.168.1.1", content)
            self.assertIn("CRITICAL", content)
            self.assertIn("Docker", content)
        finally:
            os.unlink(path)


class TestScannerInit(unittest.TestCase):

    @patch("socket.gethostbyname", return_value="93.184.216.34")
    @patch("socket.gethostbyaddr", return_value=("example.com", [], ["93.184.216.34"]))
    def test_valid_host(self, *_):
        s = PortScanner("example.com", port_range=(80, 85))
        self.assertEqual(s.ip, "93.184.216.34")

    @patch("socket.gethostbyname", side_effect=Exception("Name or service not known"))
    def test_invalid_host(self, _):
        with self.assertRaises(ValueError):
            PortScanner("invalid.host.xyz.abc")

    @patch("socket.gethostbyname", return_value="127.0.0.1")
    @patch("socket.gethostbyaddr", return_value=("localhost", [], ["127.0.0.1"]))
    def test_port_range_stored(self, *_):
        s = PortScanner("localhost", port_range=(1, 100))
        self.assertEqual(s.port_range, (1, 100))


if __name__ == "__main__":
    print("Running Network Port Scanner tests...\n")
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTests(loader.loadTestsFromTestCase(TestServiceDatabase))
    suite.addTests(loader.loadTestsFromTestCase(TestPortResult))
    suite.addTests(loader.loadTestsFromTestCase(TestBannerFingerprint))
    suite.addTests(loader.loadTestsFromTestCase(TestReporter))
    suite.addTests(loader.loadTestsFromTestCase(TestScannerInit))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    exit(0 if result.wasSuccessful() else 1)