import unittest

from phishing_header_analyzer.util import (
    classify_ip, compact, decode_domain, is_within, levenshtein, org_domain, same_org, skeleton,
)


class DomainTests(unittest.TestCase):
    def test_org_domain(self):
        self.assertEqual(org_domain("mail.contoso.example"), "contoso.example")
        self.assertEqual(org_domain("a.b.contoso.co.uk"), "contoso.co.uk")
        self.assertEqual(org_domain("contoso.example"), "contoso.example")
        self.assertIsNone(org_domain(None))

    def test_same_org_and_within(self):
        self.assertTrue(same_org("bounces.contoso.example", "contoso.example"))
        self.assertFalse(same_org("contoso.example", "contoso-mail.example"))
        self.assertTrue(is_within("mail.contoso.example", "contoso.example"))
        self.assertFalse(is_within("evilcontoso.example", "contoso.example"))

    def test_decode_domain(self):
        self.assertEqual(decode_domain("xn--nrthwind-nbh.example"), "nоrthwind.example")
        self.assertEqual(decode_domain("xn--invalid!!.example"), "xn--invalid!!.example")


class IpTests(unittest.TestCase):
    def test_classification(self):
        self.assertEqual(classify_ip("10.1.2.3"), "private")
        self.assertEqual(classify_ip("127.0.0.1"), "loopback")
        self.assertEqual(classify_ip("100.64.1.1"), "cgnat")
        self.assertEqual(classify_ip("203.0.113.5"), "documentation")
        self.assertEqual(classify_ip("8.8.8.8"), "public")
        self.assertEqual(classify_ip("fe80::1"), "link-local")
        self.assertIsNone(classify_ip("not-an-ip"))


class MatchingTests(unittest.TestCase):
    def test_skeleton_catches_common_swaps(self):
        self.assertEqual(skeleton("c0ntoso"), skeleton("contoso"))
        self.assertEqual(skeleton("paypa1"), skeleton("paypal"))
        self.assertEqual(skeleton("rnicrosoft"), skeleton("microsoft"))
        self.assertEqual(skeleton("xn--nrthwind-nbh"), skeleton("northwind"))
        self.assertNotEqual(skeleton("fabrikam"), skeleton("contoso"))

    def test_levenshtein(self):
        self.assertEqual(levenshtein("contoso", "contso"), 1)
        self.assertEqual(levenshtein("contoso", "contoso"), 0)
        self.assertEqual(levenshtein("abc", "xyz"), 3)

    def test_compact(self):
        self.assertEqual(compact("Contoso-Bank Inc."), "contosobankinc")


if __name__ == "__main__":
    unittest.main()
