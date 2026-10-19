import json
import re
import unittest
from datetime import datetime, timezone
from pathlib import Path

from phishing_header_analyzer.findings import Finding
from phishing_header_analyzer.parser import parse_bytes, parse_file
from phishing_header_analyzer.report import build_report, defang, to_json, to_markdown
from phishing_header_analyzer.scoring import score
from test_checks import fixture_config

FIXTURES = Path(__file__).parent / "fixtures"


def f(sev, pts, cid="X"):
    return Finding(cid, "test", sev, pts, "t", "d")


class ScoringTests(unittest.TestCase):
    def test_empty_is_low(self):
        r = score([])
        self.assertEqual((r.score, r.level), (0, "low"))

    def test_thresholds(self):
        self.assertEqual(score([f("low", 19)]).level, "low")
        self.assertEqual(score([f("medium", 20)]).level, "medium")
        self.assertEqual(score([f("medium", 50)]).level, "high")

    def test_cap(self):
        r = score([f("high", 80), f("high", 80)])
        self.assertEqual((r.score, r.raw_points), (100, 160))

    def test_single_high_raises_low_to_medium(self):
        r = score([f("high", 10)])
        self.assertEqual(r.level, "medium")
        self.assertEqual(len(r.reasons), 2)

    def test_two_highs_raise_to_high(self):
        self.assertEqual(score([f("high", 10, "A"), f("high", 10, "B")]).level, "high")

    def test_info_findings_do_not_score(self):
        self.assertEqual(score([f("info", 0)]).level, "low")


class FixtureLevelTests(unittest.TestCase):
    def test_levels(self):
        expected = {
            "clean.eml": "low",
            "replyto_mismatch.eml": "high",
            "lookalike_domain.eml": "high",
            "headers_only.txt": "high",
            "spf_fail.eml": "high",
        }
        for name, level in expected.items():
            with self.subTest(fixture=name):
                report = build_report(parse_file(FIXTURES / name), fixture_config())
                self.assertEqual(report["risk"]["level"], level)


class ReportStructureTests(unittest.TestCase):
    def setUp(self):
        self.report = build_report(parse_file(FIXTURES / "spf_fail.eml"), fixture_config())

    def test_findings_sorted_by_severity_then_points(self):
        order = {"high": 0, "medium": 1, "low": 2, "info": 3}
        keys = [(order[x["severity"]], -x["points"]) for x in self.report["findings"]]
        self.assertEqual(keys, sorted(keys))

    def test_sections_present(self):
        for key in ("tool", "source", "risk", "summary", "authentication", "received_chain", "findings", "notes"):
            self.assertIn(key, self.report)
        self.assertFalse(self.report["authentication"]["dkim_verified_locally"])

    def test_json_round_trip_and_deterministic(self):
        parsed = parse_file(FIXTURES / "spf_fail.eml")
        a = to_json(build_report(parsed, fixture_config()))
        b = to_json(build_report(parsed, fixture_config()))
        self.assertEqual(a, b)
        self.assertEqual(json.loads(a)["risk"]["score"], 100)

    def test_analyzed_at_optional(self):
        self.assertIsNone(self.report["analyzed_at"])
        stamped = build_report(parse_file(FIXTURES / "clean.eml"), fixture_config(),
                               analyzed_at=datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc))
        self.assertEqual(stamped["analyzed_at"], "2026-10-19T12:00:00+00:00")


class MarkdownTests(unittest.TestCase):
    def test_clean_has_no_findings(self):
        md = to_markdown(build_report(parse_file(FIXTURES / "clean.eml"), fixture_config()))
        self.assertIn("**Header risk: LOW (0/100)**", md)
        self.assertIn("not whether its content is safe", md)  # caveat shown even when clean
        self.assertIn("No findings.", md)
        self.assertNotIn("## Recommended Actions", md)

    def test_recommended_actions_deduplicated(self):
        report = build_report(parse_file(FIXTURES / "spf_fail.eml"), fixture_config())
        actions = report["recommended_actions"]
        texts = [a["action"] for a in actions]
        self.assertEqual(len(texts), len(set(texts)))
        spoof = next(a for a in actions if "spoofed" in a["action"])
        self.assertEqual(spoof["because"], ["DMARC-FAIL", "SPF-FAIL"])

    def test_domains_and_ips_defanged(self):
        md = to_markdown(build_report(parse_file(FIXTURES / "spf_fail.eml"), fixture_config()))
        self.assertIn("contoso-bank[.]example", md)
        self.assertIn("203[.]0[.]113[.]45", md)
        self.assertNotIn("| 203.0.113.45 |", md)
        self.assertIn("header.from:", md)  # our own keys are not defanged

    def test_no_defang_option(self):
        md = to_markdown(build_report(parse_file(FIXTURES / "spf_fail.eml"), fixture_config()), do_defang=False)
        self.assertIn("203.0.113.45", md)

    def test_hostile_subject_cannot_break_tables(self):
        raw = (
            b"From: a@x.example\n"
            b"Subject: Pay now | <script>alert(1)</script> [click](http://evil.example) `x`\n\nbody\n"
        )
        md = to_markdown(build_report(parse_bytes(raw)))
        subject_line = next(line for line in md.splitlines() if line.startswith("| Subject |"))
        unescaped_pipes = len(re.findall(r"(?<!\\)\|", subject_line))
        self.assertEqual(unescaped_pipes, 3)   # still exactly two columns
        self.assertNotIn("<script>", md)
        self.assertIn("\\[click\\]", subject_line)       # link syntax neutralized
        self.assertNotIn("http://", subject_line)
        self.assertIn("hxxp://evil[.]example", subject_line)
        self.assertIn("\\`x\\`", subject_line)

    def test_defang_helper(self):
        self.assertEqual(defang("mail.contoso.example 10.0.0.1"), "mail[.]contoso[.]example 10[.]0[.]0[.]1")
        self.assertEqual(defang("e.g. this"), "e.g. this")
        self.assertEqual(defang("https://a.example/x"), "hxxps://a[.]example/x")
        self.assertEqual(defang("first.last@mail.contoso.example"), "first.last@mail[.]contoso[.]example")
        self.assertEqual(defang("<20261019.fe74@centraprise.example>"), "<20261019.fe74@centraprise[.]example>")


if __name__ == "__main__":
    unittest.main()
