import unittest
from pathlib import Path

from phishing_header_analyzer.checks import run_all
from phishing_header_analyzer.config import Config
from phishing_header_analyzer.parser import parse_bytes, parse_file

FIXTURES = Path(__file__).parent / "fixtures"


def fixture_config() -> Config:
    """Settings matching the fixture world described in tests/fixtures/README.md."""
    cfg = Config(
        protected_domains=["contoso-bank.example"],
        org_domains=["northwind.example"],
        trusted_authserv_ids=["mx1.northwind.example"],
    )
    cfg.freemail_domains.append("freemail.example")
    return cfg


def ids(findings):
    return {f.check_id for f in findings}


def score(findings):
    return sum(f.points for f in findings)


def run_fixture(name, config=None):
    return run_all(parse_file(FIXTURES / name), config or fixture_config())


def message(headers: str) -> bytes:
    return (headers.strip() + "\n\nbody\n").encode()


class FixtureExpectationTests(unittest.TestCase):
    """Each fixture should trigger exactly the findings it was built to demonstrate."""

    def test_clean(self):
        findings = run_fixture("clean.eml")
        self.assertEqual(score(findings), 0, ids(findings))

    def test_spf_fail(self):
        self.assertEqual(ids(run_fixture("spf_fail.eml")), {
            "SPF-FAIL", "DKIM-NONE", "DMARC-FAIL", "RETURN-PATH-MISMATCH",
            "MSGID-MISMATCH", "HOP-OUT-OF-ORDER", "DATE-SKEW",
        })

    def test_replyto_mismatch(self):
        findings = run_fixture("replyto_mismatch.eml")
        self.assertEqual(ids(findings), {"REPLYTO-MISMATCH", "DISPLAY-NAME-ADDRESS"})
        replyto = next(f for f in findings if f.check_id == "REPLYTO-MISMATCH")
        self.assertEqual(replyto.severity, "high")  # free mail domain bumps it up

    def test_lookalike_domain(self):
        self.assertEqual(ids(run_fixture("lookalike_domain.eml")),
                         {"LOOKALIKE-HOMOGLYPH", "DISPLAY-NAME-BRAND"})

    def test_headers_only(self):
        self.assertEqual(ids(run_fixture("headers_only.txt")),
                         {"AUTH-NO-RESULTS", "IDN-DOMAIN", "LOOKALIKE-HOMOGLYPH", "MSGID-MISMATCH"})

    def test_ordering_of_risk(self):
        scores = {n: score(run_fixture(n)) for n in
                  ("clean.eml", "replyto_mismatch.eml", "lookalike_domain.eml", "spf_fail.eml")}
        self.assertEqual(scores["clean.eml"], 0)
        self.assertTrue(all(s > 0 for n, s in scores.items() if n != "clean.eml"))


class AuthEdgeCaseTests(unittest.TestCase):
    def test_default_config_trusts_topmost_header_only(self):
        raw = message("""
Authentication-Results: mx.real.example; spf=fail smtp.mailfrom=a@x.example; dkim=none; dmarc=fail header.from=x.example
Authentication-Results: forged.example; spf=pass; dkim=pass header.d=x.example; dmarc=pass
From: a@x.example
""")
        found = ids(run_all(parse_bytes(raw), Config()))
        self.assertIn("SPF-FAIL", found)
        self.assertIn("DMARC-FAIL", found)
        self.assertIn("AUTH-EXTRA-HEADERS", found)

    def test_untrusted_only(self):
        raw = message("""
Authentication-Results: someone-else.example; spf=pass; dkim=pass header.d=x.example; dmarc=pass
From: a@x.example
""")
        cfg = Config(trusted_authserv_ids=["mx1.northwind.example"])
        self.assertIn("AUTH-UNTRUSTED-ONLY", ids(run_all(parse_bytes(raw), cfg)))

    def test_dkim_unaligned(self):
        raw = message("""
Authentication-Results: mx.example; spf=pass; dkim=pass header.d=mailer-service.example; dmarc=pass
From: news@shop.example
""")
        self.assertIn("DKIM-UNALIGNED", ids(run_all(parse_bytes(raw), Config())))

    def test_gmail_style_header_i_counts_as_aligned(self):
        # Gmail records the signer as header.i=@domain rather than header.d=domain.
        raw = message("""
Authentication-Results: mx.google.com; dkim=pass header.i=@recruiter.example header.s=mailo header.b=abc123; dkim=pass header.i=@bulk-esp.example header.s=mg header.b="x/y"; spf=pass smtp.mailfrom="bounce+1a2b@recruiter.example"
From: Recruiter <jobs@recruiter.example>
""")
        cfg = Config(trusted_authserv_ids=["mx.google.com"])
        self.assertNotIn("DKIM-UNALIGNED", ids(run_all(parse_bytes(raw), cfg)))

    def test_gmail_style_header_i_unaligned_still_flagged(self):
        raw = message("""
Authentication-Results: mx.google.com; dkim=pass header.i=@bulk-esp.example header.s=mg header.b=abc
From: Shop <news@shop.example>
""")
        cfg = Config(trusted_authserv_ids=["mx.google.com"])
        f = next(f for f in run_all(parse_bytes(raw), cfg) if f.check_id == "DKIM-UNALIGNED")
        self.assertEqual(f.evidence["signing_domains"], ["bulk-esp.example"])

    def test_spf_conflict(self):
        raw = message("""
Authentication-Results: mx.example; spf=pass; dkim=pass header.d=x.example; dmarc=pass
Received-SPF: fail (spoofed) client-ip=203.0.113.9;
From: a@x.example
""")
        self.assertIn("SPF-CONFLICT", ids(run_all(parse_bytes(raw), Config())))


class IdentityEdgeCaseTests(unittest.TestCase):
    def test_reply_to_non_freemail_is_medium(self):
        raw = message("""
From: a@x.example
Reply-To: b@other.example
""")
        f = next(f for f in run_all(parse_bytes(raw), Config()) if f.check_id == "REPLYTO-MISMATCH")
        self.assertEqual(f.severity, "medium")

    def test_reply_to_same_org_subdomain_ok(self):
        raw = message("""
From: a@x.example
Reply-To: support@help.x.example
""")
        self.assertNotIn("REPLYTO-MISMATCH", ids(run_all(parse_bytes(raw), Config())))

    def test_brand_in_display_name_with_default_list(self):
        raw = message('From: "PayPal Service" <alerts@account-notices.example>')
        self.assertIn("DISPLAY-NAME-BRAND", ids(run_all(parse_bytes(raw), Config())))

    def test_brand_from_real_domain_ok(self):
        raw = message('From: "PayPal" <service@mail.paypal.com>')
        self.assertNotIn("DISPLAY-NAME-BRAND", ids(run_all(parse_bytes(raw), Config())))


class LookalikeEdgeCaseTests(unittest.TestCase):
    def test_near_miss(self):
        raw = message("From: a@contso-bank.example")
        cfg = Config(protected_domains=["contoso-bank.example"])
        self.assertIn("LOOKALIKE-NEAR-MISS", ids(run_all(parse_bytes(raw), cfg)))

    def test_contains_brand(self):
        raw = message("From: a@paypal-secure-login.example")
        self.assertIn("LOOKALIKE-CONTAINS-BRAND", ids(run_all(parse_bytes(raw), Config())))

    def test_reply_to_lookalike_also_checked(self):
        raw = message("""
From: a@x.example
Reply-To: billing@paypa1.com
""")
        self.assertIn("LOOKALIKE-HOMOGLYPH", ids(run_all(parse_bytes(raw), Config())))


class HopEdgeCaseTests(unittest.TestCase):
    def test_nonroutable_boundary_ip(self):
        raw = message("""
Received: from evil (unknown [10.9.9.9]) by mx1.northwind.example; Mon, 19 Oct 2026 10:00:00 +0000
Authentication-Results: mx1.northwind.example; spf=pass; dkim=pass header.d=x.example; dmarc=pass
From: a@x.example
""")
        self.assertIn("BOUNDARY-IP-NONROUTABLE", ids(run_all(parse_bytes(raw), Config())))

    def test_large_delay(self):
        raw = message("""
Received: from b.example ([198.51.100.2]) by c.example; Mon, 19 Oct 2026 14:00:00 +0000
Received: from a.example ([198.51.100.1]) by b.example; Mon, 19 Oct 2026 10:00:00 +0000
From: a@x.example
""")
        self.assertIn("HOP-LARGE-DELAY", ids(run_all(parse_bytes(raw), Config())))

    def test_x_originating_ip_reported_as_info(self):
        raw = message("""
X-Originating-IP: [198.51.100.50]
From: a@x.example
""")
        f = next(f for f in run_all(parse_bytes(raw), Config()) if f.check_id == "X-ORIGINATING-IP")
        self.assertEqual(f.points, 0)
        self.assertEqual(f.evidence["ip"], "198.51.100.50")


class ConfigTests(unittest.TestCase):
    def test_from_file_rejects_unknown_keys(self):
        import json
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump({"protected_domain": ["typo.example"]}, fh)
        with self.assertRaises(ValueError):
            Config.from_file(fh.name)

    def test_from_file_overrides(self):
        import json
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump({"org_domains": ["Northwind.Example"]}, fh)
        cfg = Config.from_file(fh.name)
        self.assertEqual(cfg.org_domains, ["northwind.example"])
        self.assertIn("paypal.com", cfg.protected_domains)  # default kept


if __name__ == "__main__":
    unittest.main()
