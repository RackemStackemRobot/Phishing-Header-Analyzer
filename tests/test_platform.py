"""Trusted-service abuse: authentic platform notifications triggered by an attacker.

The Google Groups test reproduces the header shape of a real invite lure: every
authentication check passes because Google genuinely sent it.
"""

import json
import tempfile
import unittest

from phishing_header_analyzer.checks import run_all
from phishing_header_analyzer.checks.platform import match_platform
from phishing_header_analyzer.config import DEFAULT_PLATFORM_SENDERS, Config
from phishing_header_analyzer.parser import parse_bytes
from phishing_header_analyzer.report import build_report, to_markdown

GOOGLE_GROUPS_INVITE = b"""\
Return-Path: <noreply@groups.google.com>
Received: from mail-sor-f69.google.com (mail-sor-f69.google.com. [209.85.220.69])
        by mx.google.com with SMTPS id abc123
        for <victim@gmail.com>; Mon, 19 Oct 2026 10:06:46 -0700 (PDT)
Authentication-Results: mx.google.com;
       dkim=pass header.i=@google.com header.s=20251104 header.b=PqVQeT2y;
       spf=pass (google.com: domain of noreply@groups.google.com designates 209.85.220.69 as permitted sender) smtp.mailfrom=noreply@groups.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@gmail.com
From: Google Groups <noreply@groups.google.com>
To: victim@gmail.com
Subject: Invitation to join Start Connecting
Date: Mon, 19 Oct 2026 10:06:45 -0700
Message-ID: <groups-invite-0001@notifications.google.com>

body
"""

GMAIL = Config(trusted_authserv_ids=["mx.google.com"])


def ids(findings):
    return {f.check_id for f in findings}


class PlatformMatchTests(unittest.TestCase):
    def test_patterns(self):
        p = DEFAULT_PLATFORM_SENDERS
        self.assertEqual(match_platform("noreply@groups.google.com", p), "Google Groups")
        self.assertEqual(match_platform("Drive-Shares-DM-NoReply@google.com", p), "Google Drive sharing")
        self.assertEqual(match_platform("dse_na4@docusign.net", p), "DocuSign")
        self.assertEqual(match_platform("dse@eumail.docusign.net", p), "DocuSign")
        self.assertIsNone(match_platform("no-reply@accounts.google.com", p))
        self.assertIsNone(match_platform(None, p))


class GoogleGroupsLureTests(unittest.TestCase):
    def setUp(self):
        self.parsed = parse_bytes(GOOGLE_GROUPS_INVITE, source="invite.eml")

    def test_flagged_despite_perfect_authentication(self):
        found = run_all(self.parsed, GMAIL)
        self.assertEqual(ids(found), {"PLATFORM-NOTIFICATION"})
        self.assertEqual(found[0].evidence["platform"], "Google Groups")

    def test_report_is_actionable(self):
        report = build_report(self.parsed, GMAIL)
        self.assertEqual(report["risk"]["level"], "medium")
        self.assertEqual(report["recommended_actions"][0]["because"], ["PLATFORM-NOTIFICATION"])
        md = to_markdown(report)
        self.assertIn("**Header risk: MEDIUM (20/100)**", md)
        self.assertIn("## Recommended Actions", md)
        self.assertIn("verify it through a channel you already trust", md)

    def test_spoofed_platform_address_left_to_auth_checks(self):
        spoofed = GOOGLE_GROUPS_INVITE.replace(b"dmarc=pass", b"dmarc=fail")
        found = ids(run_all(parse_bytes(spoofed), GMAIL))
        self.assertNotIn("PLATFORM-NOTIFICATION", found)
        self.assertIn("DMARC-FAIL", found)

    def test_platform_list_can_be_replaced(self):
        cfg = Config(trusted_authserv_ids=["mx.google.com"], platform_senders={})
        self.assertEqual(ids(run_all(self.parsed, cfg)), set())


class PlatformConfigTests(unittest.TestCase):
    def _load(self, data):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(data, fh)
        return Config.from_file(fh.name)

    def test_from_file(self):
        cfg = self._load({"platform_senders": {"*@Notify.Example": "Example Notify"}})
        self.assertEqual(cfg.platform_senders, {"*@notify.example": "Example Notify"})

    def test_wrong_types_rejected(self):
        with self.assertRaises(ValueError):
            self._load({"platform_senders": ["*@groups.google.com"]})
        with self.assertRaises(ValueError):
            self._load({"org_domains": "northwind.example"})


if __name__ == "__main__":
    unittest.main()
