import unittest
from pathlib import Path

from phishing_header_analyzer.parser import parse_authentication_results, parse_file

FIXTURES = Path(__file__).parent / "fixtures"


def auth(parsed, method):
    return next((r for r in parsed.auth_results if r.method == method), None)


class CleanFixtureTests(unittest.TestCase):
    def setUp(self):
        self.p = parse_file(FIXTURES / "clean.eml")

    def test_identity_fields(self):
        self.assertEqual(self.p.from_.display_name, "Contoso Bank")
        self.assertEqual(self.p.from_.domain, "contoso-bank.example")
        self.assertEqual(self.p.return_path.domain, "contoso-bank.example")
        self.assertEqual(self.p.message_id_domain, "contoso-bank.example")
        self.assertEqual(self.p.reply_to, [])

    def test_auth_results(self):
        self.assertEqual(auth(self.p, "spf").result, "pass")
        self.assertEqual(auth(self.p, "dkim").properties["header.d"], "contoso-bank.example")
        dmarc = auth(self.p, "dmarc")
        self.assertEqual(dmarc.result, "pass")
        self.assertEqual(dmarc.policy, "reject")
        self.assertEqual(dmarc.authserv_id, "mx1.northwind.example")

    def test_hops(self):
        self.assertEqual(len(self.p.hops), 3)
        self.assertEqual(self.p.hops[0].from_ip, "10.20.30.7")
        self.assertEqual(self.p.hops[1].from_ip, "198.51.100.20")
        self.assertTrue(all(h.delay_seconds >= 0 for h in self.p.hops[1:]))
        self.assertEqual(self.p.parse_notes, [])


class SpfFailFixtureTests(unittest.TestCase):
    def setUp(self):
        self.p = parse_file(FIXTURES / "spf_fail.eml")

    def test_verdicts(self):
        self.assertEqual(auth(self.p, "spf").result, "fail")
        self.assertEqual(auth(self.p, "dkim").result, "none")
        self.assertEqual(auth(self.p, "dmarc").result, "fail")
        self.assertEqual(self.p.received_spf[0].result, "fail")
        self.assertEqual(self.p.received_spf[0].client_ip, "203.0.113.45")

    def test_domains_differ(self):
        self.assertEqual(self.p.from_.domain, "contoso-bank.example")
        self.assertEqual(self.p.return_path.domain, "bulk-sender.example")
        self.assertEqual(self.p.message_id_domain, "vps-4471.hosting.example")

    def test_out_of_order_hop(self):
        self.assertLess(self.p.hops[1].delay_seconds, 0)


class ReplyToFixtureTests(unittest.TestCase):
    def test_display_name_and_reply_to(self):
        p = parse_file(FIXTURES / "replyto_mismatch.eml")
        self.assertEqual(p.from_.display_name, "billing@fabrikam.example")
        self.assertEqual(p.from_.domain, "fabrikam-invoicing.example")
        self.assertEqual(p.reply_to[0].domain, "freemail.example")


class HeadersOnlyFixtureTests(unittest.TestCase):
    def test_no_auth_and_idn_domain(self):
        p = parse_file(FIXTURES / "headers_only.txt")
        self.assertEqual(p.auth_results, [])
        self.assertIsNone(p.return_path)
        self.assertEqual(p.from_.domain, "xn--nrthwind-nbh.example")
        self.assertEqual(len(p.hops), 1)


class AuthResultsParsingTests(unittest.TestCase):
    def test_multiple_headers_keep_order(self):
        results = parse_authentication_results([
            "mx.trusted.example; spf=pass smtp.mailfrom=a@x.example",
            "forged.example; spf=pass smtp.mailfrom=a@x.example",
        ])
        self.assertEqual([r.header_index for r in results], [0, 1])
        self.assertEqual(results[1].authserv_id, "forged.example")

    def test_arc_and_unknown_tokens(self):
        results = parse_authentication_results(["mx.example; arc=pass; garbage; dkim=fail header.d=x.example"])
        self.assertEqual([(r.method, r.result) for r in results], [("arc", "pass"), ("dkim", "fail")])


if __name__ == "__main__":
    unittest.main()
