"""Sanity checks that every fixture is well-formed before analyzer tests rely on it."""

import unittest
from email import policy
from email.parser import BytesParser
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"
REQUIRED = ("From", "To", "Subject", "Date", "Message-ID", "Received")


def load(name):
    with open(FIXTURES / name, "rb") as f:
        return BytesParser(policy=policy.default).parse(f)


class FixtureSanityTests(unittest.TestCase):
    def test_all_fixtures_parse_with_required_headers(self):
        files = sorted(p.name for p in FIXTURES.iterdir() if p.suffix in (".eml", ".txt"))
        self.assertEqual(len(files), 5)
        for name in files:
            with self.subTest(fixture=name):
                msg = load(name)
                for header in REQUIRED:
                    self.assertIsNotNone(msg[header], f"{name} missing {header}")
                self.assertFalse(msg.defects, f"{name} has parse defects: {msg.defects}")

    def test_eml_fixtures_have_auth_results(self):
        for p in FIXTURES.glob("*.eml"):
            with self.subTest(fixture=p.name):
                self.assertIsNotNone(load(p.name)["Authentication-Results"])

    def test_headers_only_has_no_auth_results(self):
        self.assertIsNone(load("headers_only.txt")["Authentication-Results"])

    def test_idn_fixture_domain_decodes(self):
        decoded = b"xn--nrthwind-nbh".decode("idna")
        self.assertNotEqual(decoded, "northwind")
        self.assertEqual(decoded.replace("о", "o"), "northwind")


if __name__ == "__main__":
    unittest.main()
