"""Forwarded mail. Structures copied from real Gmail, Outlook, and Apple Mail
forwards, with every name and address replaced by .example placeholders."""

import base64
import unittest

from phishing_header_analyzer.checks import run_all
from phishing_header_analyzer.config import Config
from phishing_header_analyzer.forwarding import resolve
from phishing_header_analyzer.fwdparse import (
    looks_forwarded, parse_address, parse_inline_forward, references_root_domain,
)
from phishing_header_analyzer.parser import parse_bytes
from phishing_header_analyzer.report import build_report, to_markdown

GMAIL = Config(trusted_authserv_ids=["mx.google.com"], protected_domains=["paypal.com"])

ORIGINAL = b"""\
Received: from o1.ptr1.scam-sender.example (o1.ptr1.scam-sender.example. [159.183.199.221])
        by mx.google.com with ESMTPS id a for <victim@gmail.example>; Mon, 19 Oct 2026 08:19:12 -0700 (PDT)
Authentication-Results: mx.google.com;
       dkim=pass header.i=@mail.scam-sender.example header.s=ip1 header.b=abc;
       dkim=pass header.i=@sendgrid.info header.s=smtpapi header.b=def;
       spf=pass smtp.mailfrom="bounces+1-victim=gmail.example@em1.mail.scam-sender.example";
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=mail.scam-sender.example
From: "Benefit Info" <info@mail.scam-sender.example>
To: Victim <victim@gmail.example>
Subject: Victim, confirm your email to proceed
Date: Mon, 19 Oct 2026 15:19:12 +0000
Message-ID: <mid-1@mail.scam-sender.example>
X-SG-EID: u001.abc
MIME-Version: 1.0
Content-Type: text/html; charset=us-ascii

<a href="http://url1.mail.scam-sender.example/ls/click?upn=TOKEN">Confirm Email</a>
"""

WRAPPER_HEADERS = b"""\
Authentication-Results: mx.google.com; dkim=pass header.i=@gmail.example; spf=pass smtp.mailfrom=victim@gmail.example; dmarc=pass (p=NONE) header.from=gmail.example
From: Victim <victim@gmail.example>
To: analyst@gmail.example
Subject: Fwd: Victim, confirm your email to proceed
Date: Mon, 19 Oct 2026 15:00:00 -0500
Message-ID: <wrap@mail.gmail.example>
MIME-Version: 1.0
"""


def attach_as_rfc822(inner: bytes, headers: bytes = WRAPPER_HEADERS, boundary: bytes = b"W") -> bytes:
    # Each layer needs its own MIME boundary, as real mail clients generate.
    b = boundary
    return (headers + b'Content-Type: multipart/mixed; boundary="' + b + b'"\n\n--' + b + b"\n"
            b"Content-Type: text/plain\n\nhere it is\n--" + b + b"\nContent-Type: message/rfc822\n"
            b'Content-Disposition: attachment; filename="original.eml"\n\n' + inner + b"\n--" + b + b"--\n")


def attach_as_file(inner: bytes) -> bytes:
    encoded = base64.encodebytes(inner)
    return (WRAPPER_HEADERS + b'Content-Type: multipart/mixed; boundary="W"\n\n--W\n'
            b"Content-Type: text/plain\n\nsee attached\n--W\nContent-Type: application/octet-stream\n"
            b'Content-Disposition: attachment; filename="phish.eml"\nContent-Transfer-Encoding: base64\n\n'
            + encoded + b"--W--\n")


# Gmail's double inline forward, including the address wrapped across two lines and
# the narrow no-break space Gmail puts before AM/PM (=E2=80=AF in quoted-printable).
GMAIL_DOUBLE_INLINE = WRAPPER_HEADERS.replace(b"Message-ID: <wrap@", b"References: <mid-1@mail.scam-sender.example> <first@mail.gmail.example>\nMessage-ID: <wrap@") + b"""\
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

---------- Forwarded message ---------
From: Victim <victim@gmail.example>
Date: Mon, Oct 19, 2026, 2:28=E2=80=AFPM
Subject: Fwd: Victim, confirm your email to proceed
To: <analyst@gmail.example>



---------- Forwarded message ---------
From: Benefit Info from mail.scam-sender.example <
info@mail.scam-sender.example>
Date: Mon, Oct 19, 2026, 10:19=E2=80=AFAM
Subject: Victim, confirm your email to proceed
To: Victim <victim@gmail.example>


Confirm your email
<http://url1.mail.scam-sender.example/ls/click?upn=3DTOKEN>
"""

INLINE_LOOKALIKE = WRAPPER_HEADERS + b"""\
Content-Type: text/plain

---------- Forwarded message ---------
From: PayPal Service <service@paypa1.com>
Date: Mon, Oct 19, 2026, 9:00 AM
Subject: Your account is limited
To: <victim@gmail.example>

Restore access: https://paypa1.com/restore
"""


def ids(findings):
    return {f.check_id for f in findings}


class ParseHelperTests(unittest.TestCase):
    def test_parse_address(self):
        self.assertEqual(parse_address("Loki X <a@b.example>"), ("Loki X", "a@b.example"))
        self.assertEqual(parse_address("Doe, Jane [mailto:Jane@V.example]"), ("Doe, Jane", "jane@v.example"))
        self.assertEqual(parse_address('"Doe, Jane" <j@v.example>'), ("Doe, Jane", "j@v.example"))
        self.assertEqual(parse_address("j@v.example"), ("", "j@v.example"))
        self.assertEqual(parse_address("nobody"), ("", ""))

    def test_looks_forwarded(self):
        for s in ("Fwd: x", "FW: x", "Fw: Fwd: x", "fwd:x"):
            self.assertTrue(looks_forwarded(s), s)
        for s in ("Forward planning", "Re: x", "", None):
            self.assertFalse(looks_forwarded(s), s)

    def test_references_root(self):
        self.assertEqual(references_root_domain("<a@Orig.example> <b@x.example>"), "orig.example")
        self.assertEqual(references_root_domain(""), "")

    def test_outlook_and_apple_and_thunderbird(self):
        outlook = ("See below\n\n-----Original Message-----\nFrom: Doe, Jane [mailto:jane@vendor.example]\n"
                   "Sent: Monday, October 19, 2026 9:12 AM\nTo: AP <ap@corp.example>\nSubject: New bank details\n\nbody")
        apple = ("fyi\n\nBegin forwarded message:\n\n> From: IT Desk <it@helpdesk.example>\n> Subject: Password expires\n"
                 "> Date: October 19, 2026 at 9:00:00 AM CDT\n> To: me@corp.example\n\nbody")
        tbird = ("-------- Forwarded Message --------\nSubject: Invoice\nDate: Mon, 19 Oct 2026 09:00:00 -0500\n"
                 "From: Billing <billing@vendor.example>\nTo: me@corp.example\n\nbody")
        self.assertEqual(parse_inline_forward(outlook).from_address, "jane@vendor.example")
        self.assertEqual(parse_inline_forward(outlook).date_text, "Monday, October 19, 2026 9:12 AM")
        self.assertEqual(parse_inline_forward(apple).from_address, "it@helpdesk.example")
        self.assertEqual(parse_inline_forward(tbird).subject, "Invoice")
        self.assertIsNone(parse_inline_forward("just a normal message\nFrom: me\n"))


class AttachedOriginalTests(unittest.TestCase):
    def test_original_becomes_the_report(self):
        report = build_report(parse_bytes(attach_as_rfc822(ORIGINAL)), GMAIL)
        self.assertEqual(report["summary"]["from"]["address"], "info@mail.scam-sender.example")
        self.assertEqual(report["forward"]["kind"], "attached")
        self.assertEqual(report["forward"]["forwarded_by"], "victim@gmail.example")
        found = {f["check_id"] for f in report["findings"]}
        self.assertIn("FORWARD-ATTACHED", found)
        self.assertIn("BULK-MAIL-SERVICE", found)   # the original's headers were really analyzed

    def test_works_in_headers_only_mode(self):
        report = build_report(parse_bytes(attach_as_rfc822(ORIGINAL), inspect_body=False), GMAIL)
        self.assertEqual(report["forward"]["kind"], "attached")
        self.assertFalse(report["body"]["inspected"])
        self.assertEqual(len(report["received_chain"]), 1)

    def test_eml_attached_as_generic_file(self):
        report = build_report(parse_bytes(attach_as_file(ORIGINAL)), GMAIL)
        self.assertEqual(report["summary"]["from"]["address"], "info@mail.scam-sender.example")

    def test_nested_forward_as_attachment(self):
        once = attach_as_rfc822(ORIGINAL)
        twice = attach_as_rfc822(once, WRAPPER_HEADERS.replace(b"victim@gmail.example>\nTo", b"third@gmail.example>\nTo"),
                                 boundary=b"OUTER")
        report = build_report(parse_bytes(twice), GMAIL)
        self.assertEqual(report["summary"]["from"]["address"], "info@mail.scam-sender.example")
        self.assertEqual(report["forward"]["depth"], 2)

    def test_wrapper_body_no_longer_reads_into_the_attached_email(self):
        wrapper = parse_bytes(attach_as_rfc822(ORIGINAL), inspect_body=True)
        self.assertEqual(wrapper.body.attached_messages, 1)
        self.assertEqual(wrapper.body.link_domains, {})   # the original's link isn't mixed in
        report = build_report(parse_bytes(attach_as_rfc822(ORIGINAL), inspect_body=True), GMAIL)
        self.assertIn("url1.mail.scam-sender.example", [d["domain"] for d in report["body"]["link_domains"]])

    def test_markdown_section(self):
        md = to_markdown(build_report(parse_bytes(attach_as_rfc822(ORIGINAL)), GMAIL))
        self.assertIn("This report covers the original email that was forwarded as an attachment.", md)
        self.assertIn("| How | As an attachment (original headers preserved) |", md)


class InlineForwardTests(unittest.TestCase):
    def test_gmail_double_forward(self):
        parsed = resolve(parse_bytes(GMAIL_DOUBLE_INLINE, inspect_body=True))
        self.assertTrue(parsed.headers_lost)
        self.assertEqual(parsed.from_.address, "info@mail.scam-sender.example")   # innermost, despite the wrap
        self.assertEqual(parsed.from_.display_name, "Benefit Info from mail.scam-sender.example")
        self.assertEqual(parsed.forward.depth, 2)
        self.assertEqual(parsed.forward.original_date_text, "Mon, Oct 19, 2026, 10:19 AM")
        self.assertEqual(parsed.forward.references_domain, "mail.scam-sender.example")

    def test_no_misleading_auth_or_hop_findings(self):
        found = ids(run_all(resolve(parse_bytes(GMAIL_DOUBLE_INLINE, inspect_body=True)), GMAIL))
        self.assertEqual(found, {"FORWARD-INLINE"})   # no AUTH-NO-RESULTS or HOPS-NONE about lost data

    def test_checks_run_against_the_original_sender(self):
        found = ids(run_all(resolve(parse_bytes(INLINE_LOOKALIKE, inspect_body=True)), GMAIL))
        self.assertIn("LOOKALIKE-HOMOGLYPH", found)         # paypa1.com sender
        self.assertIn("DISPLAY-NAME-BRAND", found)
        self.assertIn("LINK-LOOKALIKE-HOMOGLYPH", found)    # paypa1.com link

    def test_report_tells_you_how_to_get_the_original(self):
        report = build_report(parse_bytes(GMAIL_DOUBLE_INLINE, inspect_body=True), GMAIL)
        md = to_markdown(report)
        self.assertIn("forwarded inline, so the original's authentication and delivery path were lost", md)
        self.assertIn("Forward as attachment", md)
        self.assertIn("(as written in the forward)", md)
        self.assertIn("| Times forwarded | 2 |", md)

    def test_headers_only_is_flagged_as_suspected(self):
        report = build_report(parse_bytes(GMAIL_DOUBLE_INLINE), GMAIL)
        self.assertEqual(report["forward"]["kind"], "suspected")
        self.assertEqual(report["summary"]["from"]["address"], "victim@gmail.example")
        self.assertIn("FORWARD-SUSPECTED", {f["check_id"] for f in report["findings"]})


class NotAForwardTests(unittest.TestCase):
    def test_ordinary_mail_untouched(self):
        report = build_report(parse_bytes(ORIGINAL, inspect_body=True), GMAIL)
        self.assertIsNone(report["forward"])
        self.assertIsNone(report["forward_note"])
        self.assertNotIn("## Forwarded By", to_markdown(report))


if __name__ == "__main__":
    unittest.main()
