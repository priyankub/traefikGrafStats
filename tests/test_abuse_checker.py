"""Unit tests for src/abuse_checker.py neighbour inference and cache schema migration."""

import os
import sqlite3
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

import abuse_checker
from abuse_checker import AbuseChecker


class TestAbuseChecker(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        patches = {
            "DATA_DIR": self.tmp.name,
            "ABUSEIP_CACHE_DB": os.path.join(self.tmp.name, "abuseip_cache.db"),
            "ABUSEIP_CACHE_JSON": os.path.join(self.tmp.name, "abuseip_cache.json"),
        }
        for name, value in patches.items():
            p = mock.patch.object(abuse_checker, name, value)
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(self.tmp.cleanup)

    def _checker(self, scores):
        """Checker whose API answers from `scores` (ip -> score) and records each call."""
        checker = AbuseChecker("test-key")
        self.addCleanup(checker.close)
        self.calls = []

        def fake_api(ip):
            self.calls.append(ip)
            return {"abuseConfidenceScore": scores.get(ip, 0), "totalReports": 1}

        checker._execute_api_request = fake_api
        return checker

    def test_skips_lookup_when_subnet_neighbours_are_abusive(self):
        checker = self._checker({f"43.173.180.{i}": 70 for i in range(1, 4)})
        for i in range(1, 4):
            checker.check(f"43.173.180.{i}")
        self.assertEqual(checker.check("43.173.180.99"), (70, 0))
        self.assertNotIn("43.173.180.99", self.calls)

    def test_inferred_score_is_not_cached(self):
        checker = self._checker({f"43.173.180.{i}": 70 for i in range(1, 4)})
        for i in range(1, 4):
            checker.check(f"43.173.180.{i}")
        checker.check("43.173.180.99")
        row = checker._conn.execute("SELECT 1 FROM abuse_cache WHERE ip = '43.173.180.99'").fetchone()
        self.assertIsNone(row)

    def test_looks_up_when_too_few_abusive_neighbours(self):
        checker = self._checker({"43.173.180.1": 70, "43.173.180.2": 70})
        checker.check("43.173.180.1")
        checker.check("43.173.180.2")
        checker.check("43.173.180.99")
        self.assertIn("43.173.180.99", self.calls)

    def test_looks_up_when_subnet_is_mostly_clean(self):
        scores = {f"73.1.2.{i}": 70 for i in range(1, 4)}
        scores.update({f"73.1.2.{i}": 0 for i in range(10, 14)})
        checker = self._checker({})
        for ip, score in scores.items():
            checker._store(ip, {"abuseConfidenceScore": score, "totalReports": 1})
        checker.check("73.1.2.99")
        self.assertIn("73.1.2.99", self.calls)

    def test_other_subnet_is_not_affected(self):
        checker = self._checker({f"43.173.180.{i}": 70 for i in range(1, 4)})
        for i in range(1, 4):
            checker.check(f"43.173.180.{i}")
        checker.check("43.173.181.1")
        self.assertIn("43.173.181.1", self.calls)

    def test_ipv6_uses_slash_64(self):
        checker = self._checker({f"2001:db8:1:2::{i}": 90 for i in range(1, 4)})
        for i in range(1, 4):
            checker.check(f"2001:db8:1:2::{i}")
        self.assertEqual(checker.check("2001:db8:1:2:abcd::1")[0], 90)
        checker.check("2001:db8:1:3::1")
        self.assertEqual(self.calls[-1], "2001:db8:1:3::1")

    def test_existing_cache_gets_net_column_backfilled(self):
        db = abuse_checker.ABUSEIP_CACHE_DB
        conn = sqlite3.connect(db)
        conn.execute("CREATE TABLE abuse_cache (ip TEXT PRIMARY KEY, confidence_score INTEGER, "
                     "total_reports INTEGER, data_json TEXT, fetched_at REAL)")
        conn.executemany("INSERT INTO abuse_cache VALUES (?, 70, 1, '{}', ?)",
                         [(f"43.173.180.{i}", time.time()) for i in range(1, 4)])
        conn.commit()
        conn.close()

        checker = self._checker({})
        nets = {n for (n,) in checker._conn.execute("SELECT net FROM abuse_cache")}
        self.assertEqual(nets, {"43.173.180.0/24"})
        self.assertEqual(checker.check("43.173.180.50"), (70, 0))
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
