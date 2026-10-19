"""--live RDAP lookups, tested with responses shaped like real Verisign (domain)
and ARIN (IP) RDAP data. No real network access: every fetch goes to a fake."""

import email
import io
import json
import socket
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from phishing_header_analyzer import live as live_mod
from phishing_header_analyzer.abuse import write_drafts
from phishing_header_analyzer.config import Config
from phishing_header_analyzer.live import LiveError, Rdap, https_json, parse_domain, parse_ip, targets
from phishing_header_analyzer.main import EXIT_OK, main
from phishing_header_analyzer.parser import parse_bytes
from phishing_header_analyzer.report import analyze_message, build_report, to_markdown

NOW = datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc)
GMAIL = Config(trusted_authserv_ids=["mx.google.com"])

MESSAGE = b"""\
Received: from o1.ptr1.scam-sender.example (o1.ptr1.scam-sender.example. [159.183.199.221])
        by mx.google.com with ESMTPS id a for <victim@gmail.example>; Mon, 19 Oct 2026 08:19:12 -0700 (PDT)
Authentication-Results: mx.google.com; dkim=pass header.i=@mail.scam-sender.example; dkim=pass header.i=@sendgrid.info; spf=pass smtp.mailfrom=bounce@em1.mail.scam-sender.example; dmarc=pass (p=REJECT) header.from=mail.scam-sender.example
Return-Path: <bounce@em1.mail.scam-sender.example>
From: "Benefit Info" <info@mail.scam-sender.example>
To: victim@gmail.example
Subject: confirm your email to proceed
Date: Mon, 19 Oct 2026 15:19:12 +0000
Message-ID: <mid-1@mail.scam-sender.example>
MIME-Version: 1.0
Content-Type: text/html

<a href="http://url1.mail.scam-sender.example/ls/click?upn=TOKEN">Confirm</a>
<a href="https://www.paypal.com/help">Help</a>
"""


def vcard(*props):
    return ["vcard", [["version", {}, "text", "4.0"], *props]]


DNS_BOOTSTRAP = {"services": [[["com", "net"], ["https://rdap.verisign.test/com/v1/"]],
                              [["example"], ["http://insecure.test/", "https://rdap.example-registry.test/"]]]}
IPV4_BOOTSTRAP = {"services": [[["159.0.0.0/8"], ["https://rdap.arin.test/registry/"]],
                               [["159.183.0.0/16"], ["https://rdap.more-specific.test/"]]]}

DOMAIN_RESPONSE = {   # shape of a thin-registry (Verisign) domain response
    "objectClassName": "domain", "ldhName": "SCAM-SENDER.EXAMPLE",
    "events": [{"eventAction": "registration", "eventDate": (NOW - timedelta(days=12)).strftime("%Y-%m-%dT%H:%M:%SZ")},
               {"eventAction": "expiration", "eventDate": "2027-10-07T00:00:00Z"}],
    "entities": [{
        "objectClassName": "entity", "roles": ["registrar"],
        "publicIds": [{"type": "IANA Registrar ID", "identifier": "9999"}],
        "vcardArray": vcard(["fn", {}, "text", "Example Registrar, LLC"]),
        "entities": [{"objectClassName": "entity", "roles": ["abuse"],
                      "vcardArray": vcard(["fn", {}, "text", ""],
                                          ["tel", {"type": "voice"}, "uri", "tel:+1.5555550100"],
                                          ["email", {}, "text", "Abuse@Registrar.example"])}],
    }],
}
IP_RESPONSE = {   # shape of an ARIN ip network response
    "objectClassName": "ip network", "handle": "NET-159-183-0-0-1", "name": "SENDGRID",
    "startAddress": "159.183.0.0", "endAddress": "159.183.255.255", "ipVersion": "v4",
    "entities": [{"roles": ["registrant"], "vcardArray": vcard(["fn", {}, "text", "SendGrid, Inc."]),
                  "entities": [{"roles": ["abuse"],
                                "vcardArray": vcard(["fn", {}, "text", "Abuse"],
                                                    ["email", {}, "text", "abuse@sendgrid.example"])}]}],
}


class FakeFetch:
    def __init__(self, responses):
        self.responses, self.calls = responses, []

    def __call__(self, url):
        self.calls.append(url)
        if url not in self.responses:
            raise LiveError("HTTP 404 (not found)")
        r = self.responses[url]
        if isinstance(r, Exception):
            raise r
        return r


def fake_rdap(**overrides):
    responses = {
        live_mod.BOOTSTRAP["dns"]: DNS_BOOTSTRAP,
        live_mod.BOOTSTRAP["ipv4"]: IPV4_BOOTSTRAP,
        "https://rdap.example-registry.test/domain/scam-sender.example": DOMAIN_RESPONSE,
        "https://rdap.more-specific.test/ip/159.183.199.221": IP_RESPONSE,
    }
    responses.update(overrides)
    return Rdap(fetch=FakeFetch(responses))


class ParsingTests(unittest.TestCase):
    def test_domain(self):
        d = parse_domain("scam-sender.example", DOMAIN_RESPONSE, NOW)
        self.assertEqual((d.age_days, d.registrar), (12, "Example Registrar, LLC"))
        self.assertEqual((d.abuse_email, d.abuse_phone), ("abuse@registrar.example", "+1.5555550100"))

    def test_ip(self):
        i = parse_ip("159.183.199.221", IP_RESPONSE)
        self.assertEqual((i.network, i.org, i.abuse_email), ("SENDGRID", "SendGrid, Inc.", "abuse@sendgrid.example"))

    def test_garbage_does_not_crash(self):
        self.assertIsNone(parse_domain("x.example", {"events": "nope", "entities": [1, None]}, NOW).age_days)


class RdapClientTests(unittest.TestCase):
    def test_uses_https_base_and_most_specific_network(self):
        rdap = fake_rdap()
        self.assertEqual(rdap.domain_url("scam-sender.example"),
                         "https://rdap.example-registry.test/domain/scam-sender.example")
        self.assertEqual(rdap.ip_url("159.183.199.221"), "https://rdap.more-specific.test/ip/159.183.199.221")

    def test_unknown_tld_is_a_note_not_a_crash(self):
        info = fake_rdap().domain("thing.zz", NOW)
        self.assertIn("no RDAP service for .zz", info.error)

    def test_bootstrap_failure_is_cached(self):
        fetch = FakeFetch({live_mod.BOOTSTRAP["dns"]: LiveError("could not connect: offline")})
        rdap = Rdap(fetch=fetch)
        for d in ("a.com", "b.com", "c.com"):
            self.assertIn("IANA bootstrap unavailable", rdap.domain(d, NOW).error)
        self.assertEqual(fetch.calls.count(live_mod.BOOTSTRAP["dns"]), 1)   # no repeated timeouts

    def test_malformed_response_is_a_note(self):
        rdap = fake_rdap(**{"https://rdap.example-registry.test/domain/scam-sender.example": ["not", "a", "dict"]})
        self.assertIn("unexpected RDAP response", rdap.domain("scam-sender.example", NOW).error)

    def test_https_only(self):
        with self.assertRaises(LiveError):
            https_json("http://data.iana.org/rdap/dns.json")


class TargetTests(unittest.TestCase):
    def test_targets_skip_well_known_domains(self):
        domains, ips = targets(parse_bytes(MESSAGE, inspect_body=True), GMAIL)
        self.assertEqual(domains, ["scam-sender.example"])   # deduped to the registrable domain
        self.assertNotIn("paypal.com", domains)              # protected brand: not looked up
        self.assertEqual(ips, ["159.183.199.221"])

    def test_private_ips_never_looked_up(self):
        raw = MESSAGE.replace(b"[159.183.199.221]", b"[10.1.2.3]")
        self.assertEqual(targets(parse_bytes(raw), GMAIL)[1], [])


class LiveReportTests(unittest.TestCase):
    def run_live(self, raw=MESSAGE, rdap=None):
        with mock.patch.object(live_mod, "datetime", wraps=datetime) as dt:
            dt.now.return_value = NOW
            return build_report(parse_bytes(raw, inspect_body=True), GMAIL, live=True, rdap=rdap or fake_rdap())

    def test_new_domain_flagged_high(self):
        report = self.run_live()
        f = next(f for f in report["findings"] if f["check_id"] == "DOMAIN-NEWLY-REGISTERED")
        self.assertEqual((f["severity"], f["evidence"]["age_days"]), ("high", 12))
        self.assertEqual(report["risk"]["level"], "medium")

    def test_abuse_contacts_become_actions(self):
        report = self.run_live()
        subjects = [s for a in report["recommended_actions"] for s in a["subjects"]]
        self.assertIn("scam-sender.example: Example Registrar, LLC <abuse@registrar.example>", subjects)
        self.assertIn("159.183.199.221: SendGrid, Inc. <abuse@sendgrid.example>", subjects)

    def test_markdown_section(self):
        md = to_markdown(self.run_live())
        self.assertIn("## Live Lookups (RDAP)", md)
        self.assertIn("Example Registrar, LLC", md)

    def test_failures_reported_not_raised(self):
        rdap = Rdap(fetch=FakeFetch({}))   # every request fails
        report = self.run_live(rdap=rdap)
        self.assertIn("LIVE-LOOKUP-NOTES", {f["check_id"] for f in report["findings"]})

    def test_default_runs_make_no_network_calls(self):
        def tripwire(*a, **k):
            raise AssertionError("network access without --live")
        with mock.patch.object(socket, "socket", tripwire), mock.patch.object(socket, "create_connection", tripwire):
            report = build_report(parse_bytes(MESSAGE, inspect_body=True), GMAIL)
        self.assertIsNone(report["live"])
        self.assertIn("Not run. Pass `--live`", to_markdown(report))


class AbuseReportTests(unittest.TestCase):
    def setUp(self):
        with mock.patch.object(live_mod, "datetime", wraps=datetime) as dt:
            dt.now.return_value = NOW
            self.report, self.primary = analyze_message(parse_bytes(MESSAGE, inspect_body=True), GMAIL,
                                                        live=True, rdap=fake_rdap())
        self.dir = tempfile.mkdtemp()

    def test_one_draft_per_party(self):
        write_drafts(self.report, self.primary, self.dir)
        readme = (Path(self.dir) / "README.txt").read_text(encoding="utf-8")
        for contact in ("abuse@sendgrid.com", "abuse@registrar.example", "abuse@sendgrid.example",
                        "reportphishing@apwg.org"):
            self.assertIn(contact, readme)
        self.assertTrue((Path(self.dir) / "original.eml").read_bytes().startswith(b"Received:"))

    def test_eml_is_arf_with_original_attached(self):
        written = write_drafts(self.report, self.primary, self.dir)
        eml = next(p for p in written if p.name.startswith("01-") and p.suffix == ".eml")
        msg = email.message_from_bytes(eml.read_bytes())
        self.assertEqual(msg.get_content_type(), "multipart/report")
        self.assertEqual(msg.get_param("report-type"), "feedback-report")
        self.assertEqual(msg["X-Unsent"], "1")
        parts = [p.get_content_type() for p in msg.get_payload()]
        self.assertEqual(parts, ["text/plain", "message/feedback-report", "message/rfc822"])
        raw = eml.read_bytes()
        self.assertIn(b"Feedback-Type: fraud", raw)
        self.assertIn(b"Source-IP: 159.183.199.221", raw)

    def test_original_attached_byte_for_byte(self):
        # The attachment is evidence: re-wrapped headers can break DKIM verification.
        long_header = b"X-Long: " + b"word " * 40 + b"\n"
        raw = MESSAGE.replace(b"MIME-Version: 1.0\n", long_header + b"MIME-Version: 1.0\n", 1)
        report, primary = analyze_message(parse_bytes(raw, inspect_body=True), GMAIL)
        for eml in (p for p in write_drafts(report, primary, self.dir) if p.name.startswith("0") and p.suffix == ".eml"):
            self.assertIn(raw, eml.read_bytes())

    def test_explanation_is_readable_without_decoding(self):
        written = write_drafts(self.report, self.primary, self.dir)
        eml = next(p for p in written if p.name.startswith("01-") and p.suffix == ".eml").read_bytes()
        self.assertIn(b"Content-Transfer-Encoding: 7bit", eml)
        self.assertNotIn(b"Content-Transfer-Encoding: base64", eml.split(b"message/rfc822")[0])
        self.assertIn(b"Requested action", eml)

    def test_apwg_greeting(self):
        write_drafts(self.report, self.primary, self.dir)
        apwg = next(Path(self.dir).glob("*apwg*.txt")).read_text(encoding="utf-8")
        self.assertIn("To the Anti-Phishing Working Group,\n", apwg)

    def test_drafts_are_neutral_and_never_sent(self):
        write_drafts(self.report, self.primary, self.dir)
        for txt in Path(self.dir).glob("0*.txt"):
            text = txt.read_text(encoding="utf-8")
            self.assertNotRegex(text, r"\bI\b|\bI'm\b|\bmy\b")
            self.assertIn("[Your name]", text)
        import phishing_header_analyzer.abuse as abuse_mod
        source = Path(abuse_mod.__file__).read_text(encoding="utf-8")
        self.assertNotIn("smtplib", source)

    def test_without_live_still_drafts_bulk_mail_and_apwg(self):
        report, primary = analyze_message(parse_bytes(MESSAGE, inspect_body=True), GMAIL)
        write_drafts(report, primary, self.dir)
        readme = (Path(self.dir) / "README.txt").read_text(encoding="utf-8")
        self.assertIn("reportphishing@apwg.org", readme)
        self.assertNotIn("abuse@registrar.example", readme)

    def test_cli_flags(self):
        out, err = io.BytesIO(), io.StringIO()
        with tempfile.NamedTemporaryFile("wb", suffix=".eml", delete=False) as fh:
            fh.write(MESSAGE)
        code = main([fh.name, "--live", "--abuse-reports", self.dir, "--inspect-body"],
                    stdout=out, stderr=err, interactive=False, rdap=fake_rdap())
        self.assertEqual(code, EXIT_OK)
        self.assertIn("nothing was sent", err.getvalue())
        self.assertIsNotNone(json.loads(out.getvalue())["live"])


if __name__ == "__main__":
    unittest.main()
