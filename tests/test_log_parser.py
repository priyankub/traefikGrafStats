"""Unit tests for src/log_parser.py focusing on secure proxy chain parsing."""

import os
import sys
import unittest

# Ensure the src/ directory is discoverable by the test runner
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from log_parser import parse_traefik_json_line


class TestLogParser(unittest.TestCase):
    def test_parse_valid_json_standard(self):
        line = (
            '{"ClientHost": "8.8.8.8", "RequestHost": "example.com", "DownstreamStatus": 200, '
            '"DownstreamContentSize": 1024, "ServiceAddr": "10.0.1.5:80", '
            '"StartUTC": "2026-06-15T17:13:50Z", "request_User-Agent": "Mozilla/5.0"}'
        )
        entry = parse_traefik_json_line(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.outside_ip, "8.8.8.8")
        self.assertEqual(entry.domain, "example.com")
        self.assertEqual(entry.status_code, 200)
        self.assertEqual(entry.length, 1024)
        self.assertEqual(entry.target_ip, "10.0.1.5")
        self.assertEqual(entry.timestamp, "2026-06-15T17:13:50Z")
        self.assertEqual(entry.user_agent, "Mozilla/5.0")

    def test_parse_malformed_json_graceful_fail(self):
        line = '{"ClientHost": "8.8.8.8", "RequestHost": "example.com", "status": '  # truncated
        entry = parse_traefik_json_line(line)
        self.assertIsNone(entry)

    def test_parse_proxy_chain_resolution(self):
        # Chain containing: Actual client IP, Cloudflare/Proxy IP, local loopback IP
        line = '{"ClientHost": "84.17.43.213, 172.16.0.5, 127.0.0.1", "RequestHost": "example.com"}'
        entry = parse_traefik_json_line(line)
        self.assertIsNotNone(entry)
        # Should walk backwards from right to left, discard loopback (127.0.0.1) and private (172.16.0.5), and find the origin client IP
        self.assertEqual(entry.outside_ip, "84.17.43.213")

    def test_parse_entirely_internal_proxy_chain_fallback(self):
        # If all IPs in the proxy chain are private networks, fallback to leftmost client entry
        line = '{"ClientHost": "10.0.1.25, 172.16.0.5, 127.0.0.1", "RequestHost": "example.com"}'
        entry = parse_traefik_json_line(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.outside_ip, "10.0.1.25")

    def test_parse_fallback_to_client_addr(self):
        # Test fallback when ClientHost is missing but ClientAddr is populated
        line = '{"ClientAddr": "9.9.9.9:4321", "RequestHost": "example.com"}'
        entry = parse_traefik_json_line(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.outside_ip, "9.9.9.9")


if __name__ == "__main__":
    unittest.main()