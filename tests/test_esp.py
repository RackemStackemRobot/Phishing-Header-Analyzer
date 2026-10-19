"""Bulk mail service identification. Header patterns modeled on real SendGrid and
Mailgun mail, with every address and domain replaced by .example placeholders."""

import unittest

from phishing_header_analyzer.checks import run_all
from phishing_header_analyzer.checks.esp import identify
from phishing_header_analyzer.config import Config
from phishing_header_analyzer.parser import parse_bytes
from phishing_header_analyzer.report import build_report, to_markdown

GMAIL = Config(trusted_authserv_ids=["mx.google.com"])

SENDGRID = b"""\
Received: from o137.ptr1956.sender.example (o137.ptr1956.sender.example. [159.183.199.221])
        by mx.google.com with ESMTPS id abc for <victim@gmail.example>; Mon, 19 Oct 2026 08:19:12 -0700 (PDT)
Authentication-Results: mx.google.com;
       dkim=pass header.i=@mail.sender.example header.s=ip1 header.b="h/WeC0SR";
       dkim=pass header.i=@sendgrid.info header.s=smtpapi header.b=CPDKx0dB;
       spf=pass smtp.mailfrom="bounces+1-aef2-victim=gmail.example@em9941.mail.sender.example";
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=mail.sender.example
Received: by recvd-569578f769-sxm2n with SMTP id recvd-1
        2026-10-19 15:19:12.122905 +0000 UTC m=+1721900.718560597
Received: from mail.sender.example (unknown)
        by geopod-ismtpd-10 (SG) with ESMTP id 9-1X for <victim@gmail.example>; Mon, 19 Oct 2026 15:19:12.105 +0000 (UTC)
From: "Benefit Info" <info@mail.sender.example>
To: victim@gmail.example
Subject: confirm your email to proceed
Date: Mon, 19 Oct 2026 15:19:12 +0000 (UTC)
Message-ID: <mid-1@mail.sender.example>
X-SES-MESSAGE-TAGS:
X-IB-Callback-Data:
X-SG-EID: u001.abc
X-SG-ID: u001.def
"""

PERSONAL_GMAIL = b"""\
Authentication-Results: mx.google.com; dkim=pass header.i=@gmail.example; spf=pass smtp.mailfrom=a@gmail.example; dmarc=pass header.from=gmail.example
From: A Person <a@gmail.example>
Subject: hi
"""

MAILGUN_BY_RELAY = b"""\
Received: from a21.a57a0aae.use4.send.mailgun.net (a21.a57a0aae.use4.send.mailgun.net [198.244.51.21])
        by mx.google.com with UTF8SMTPS id x; Mon, 19 Oct 2026 10:19:11 -0700 (PDT)
From: Recruiter <jobs@agency.example>
Subject: Opening
"""


def ids(findings):
    return {f.check_id for f in findings}


class IdentifyTests(unittest.TestCase):
    def test_sendgrid(self):
        found = identify(parse_bytes(SENDGRID))
        self.assertEqual([svc.name for svc, _ in found], ["SendGrid (Twilio)"])
        evidence = found[0][1]
        self.assertIn("DKIM signature by sendgrid.info", evidence)
        self.assertIn("x-sg-eid header present", evidence)

    def test_empty_headers_from_other_services_ignored(self):
        # This message carries an EMPTY X-SES-MESSAGE-TAGS header; it must not be read as Amazon SES.
        names = [svc.name for svc, _ in identify(parse_bytes(SENDGRID))]
        self.assertNotIn("Amazon SES", names)

    def test_empty_service_header_alone_does_not_count(self):
        raw = b"From: a@x.example\nX-SG-EID: \nSubject: s\n"
        self.assertEqual(identify(parse_bytes(raw)), [])

    def test_personal_mail_has_no_service(self):
        self.assertEqual(identify(parse_bytes(PERSONAL_GMAIL)), [])

    def test_mailgun_by_relay_hostname(self):
        found = identify(parse_bytes(MAILGUN_BY_RELAY))
        self.assertEqual([svc.name for svc, _ in found], ["Mailgun"])


class ReportTests(unittest.TestCase):
    def test_finding_is_informational(self):
        findings = run_all(parse_bytes(SENDGRID), GMAIL)
        f = next(f for f in findings if f.check_id == "BULK-MAIL-SERVICE")
        self.assertEqual((f.severity, f.points), ("info", 0))
        self.assertEqual(f.evidence["abuse_contact"], "abuse@sendgrid.com")

    def test_action_names_the_service_and_is_conditional(self):
        report = build_report(parse_bytes(SENDGRID), GMAIL)
        self.assertEqual(report["risk"]["score"], 0)
        action = next(a for a in report["recommended_actions"] if a["because"] == ["BULK-MAIL-SERVICE"])
        self.assertTrue(action["action"].startswith("If this message is unwanted or malicious"))
        self.assertEqual(action["subjects"], ["SendGrid (Twilio): abuse@sendgrid.com"])
        self.assertIn("SendGrid (Twilio)", to_markdown(report))

    def test_no_action_for_personal_mail(self):
        report = build_report(parse_bytes(PERSONAL_GMAIL), GMAIL)
        self.assertEqual(report["recommended_actions"], [])


if __name__ == "__main__":
    unittest.main()
