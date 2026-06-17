"""Unit tests for src/ip_classifier.py checking routing rules for various subnets."""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from ip_classifier import IPClassifier


class TestIPClassifier(unittest.TestCase):
    def setUp(self):
        # Instantiate a standard classifier mock configuration
        self.classifier = IPClassifier(external_ip="8.8.8.8", has_monitoring_file=False)

    def test_classify_private_ranges(self):
        # Standard RFC1918 addresses must be classified as internal
        self.assertEqual(self.classifier.classify("127.0.0.1"), "internal")
        self.assertEqual(self.classifier.classify("10.10.5.1"), "internal")
        self.assertEqual(self.classifier.classify("172.16.20.1"), "internal")
        self.assertEqual(self.classifier.classify("192.168.1.100"), "internal")
        self.assertEqual(self.classifier.classify("::1"), "internal")

    def test_classify_external_public_ip(self):
        # Public internet address must be classified as external
        self.assertEqual(self.classifier.classify("84.17.43.213"), "external")

    def test_classify_own_external_is_internal(self):
        # Request matching our declared WAN IP must be treated as internal to prevent looping
        self.assertEqual(self.classifier.classify("8.8.8.8"), "internal")

    def test_classify_invalid_ip_fails_safely(self):
        # Malformed strings should safely default to external so that they do not break log parsing
        self.assertEqual(self.classifier.classify("malformed_junk_string"), "external")


if __name__ == "__main__":
    unittest.main()