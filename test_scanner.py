"""
Unit tests for mishttpchecker.HTTPHeaderScanner

These tests mock out network calls (requests, socket/ssl, dns.resolver) so the
suite runs offline and deterministically — useful both for CI and for
demonstrating correctness during review.

Run with:  python -m pytest tests/ -v
"""
import sys
import os
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from mishttpchecker import HTTPHeaderScanner, ReportGenerator  # noqa: E402


def _mock_response(headers=None, status_code=200, url="https://example.com/", text=""):
    resp = MagicMock()
    resp.headers = headers or {}
    resp.status_code = status_code
    resp.url = url
    resp.history = []
    resp.text = text
    return resp


class TestHeaderChecks(unittest.TestCase):
    def setUp(self):
        self.scanner = HTTPHeaderScanner(timeout=5)

    def test_missing_hsts_flagged(self):
        result = self.scanner._check_hsts({}, "https://example.com")
        self.assertFalse(result["present"])
        self.assertIn("HSTS header missing", result["issues"])

    def test_hsts_short_max_age_flagged(self):
        headers = {"Strict-Transport-Security": "max-age=100; includeSubDomains"}
        result = self.scanner._check_hsts(headers, "https://example.com")
        self.assertEqual(result["max_age"], 100)
        self.assertIn("max-age too short", result["issues"])

    def test_good_hsts_no_issues(self):
        headers = {"Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload"}
        result = self.scanner._check_hsts(headers, "https://example.com")
        self.assertEqual(result["issues"], [])
        self.assertTrue(result["includes_subdomains"])
        self.assertTrue(result["preload"])

    def test_csp_unsafe_inline_flagged(self):
        headers = {"Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'"}
        result = self.scanner._check_csp(headers)
        self.assertIn("unsafe-inline directive found", result["issues"])

    def test_referrer_policy_no_typo_crash(self):
        # Regression test for the SVERITY_LOW -> SEVERITY_LOW typo that used
        # to raise AttributeError and abort the whole scan.
        result = self.scanner._check_referrer_policy({})
        self.assertIn("header missing", result["issues"])
        findings_titles = [f.title for f in self.scanner.findings]
        self.assertIn("Missing Referrer-Policy", findings_titles)

    def test_cross_origin_isolation_headers(self):
        result = self.scanner._check_cross_origin_isolation({})
        self.assertEqual(len(result["issues"]), 3)  # COOP, COEP, CORP all missing

    def test_x_frame_options_invalid_value(self):
        result = self.scanner._check_x_frame_options({"X-Frame-Options": "ALLOW-FROM https://evil.com"})
        self.assertIn("invalid value", result["issues"])


class TestRiskScoring(unittest.TestCase):
    def setUp(self):
        self.scanner = HTTPHeaderScanner(timeout=5)

    def test_no_findings_gives_grade_a(self):
        score, grade = self.scanner._calculate_risk_score()
        self.assertEqual(score, 0)
        self.assertEqual(grade, "A")

    def test_high_severity_findings_lower_grade(self):
        for _ in range(5):
            self.scanner._add_finding(self.scanner.SEVERITY_HIGH, "t", "d", "r")
        score, grade = self.scanner._calculate_risk_score()
        self.assertGreater(score, 0)
        self.assertIn(grade, ["D", "F"])


class TestFullScanIsolation(unittest.TestCase):
    """Verifies a failure in one stage doesn't zero out the whole scan."""

    @patch("mishttpchecker.HTTPHeaderScanner._get_network_info")
    @patch("mishttpchecker.HTTPHeaderScanner._check_ssl")
    @patch("mishttpchecker.HTTPHeaderScanner._make_request")
    def test_dns_failure_does_not_reset_score(self, mock_request, mock_ssl, mock_dns):
        mock_request.return_value = _mock_response(
            headers={"Strict-Transport-Security": "max-age=31536000"},
            url="https://example.com/",
        )
        mock_ssl.return_value = {}
        mock_dns.side_effect = RuntimeError("simulated DNS timeout")

        scanner = HTTPHeaderScanner(timeout=5)
        result = scanner.scan("https://example.com")

        # Even though DNS lookup blew up, header findings should still exist
        # and the risk score should be computed from them (not left at 0/F
        # by an aborted scan).
        self.assertTrue(any(f["title"] == "Missing CSP Header" for f in result["findings"]))
        self.assertIsInstance(result["risk_score"], int)


class TestReportGenerator(unittest.TestCase):
    def test_html_report_contains_grade_and_score(self):
        results = {
            "target_url": "https://example.com", "final_url": "https://example.com/",
            "scan_date": "2026-01-01T00:00:00", "scan_duration": 1.2, "status_code": 200,
            "risk_score": 42, "grade": "C", "findings": [], "headers": {"Server": "nginx"},
        }
        html = ReportGenerator.generate_html_report(results)
        self.assertIn("42/100", html)
        self.assertIn(">C<", html)
        self.assertIn("nginx", html)

    def test_json_report_is_valid_json(self):
        import json
        results = {"target_url": "https://example.com", "risk_score": 10, "grade": "A", "findings": []}
        report = ReportGenerator.generate_json_report(results)
        parsed = json.loads(report)
        self.assertEqual(parsed["risk_score"], 10)


if __name__ == "__main__":
    unittest.main()
