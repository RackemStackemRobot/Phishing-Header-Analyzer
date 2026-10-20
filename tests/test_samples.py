"""Regression tests from the 0.2.2 sample run: real recruiter, vendor, and agency mail
that 0.2.1 misjudged. Header shapes match the real messages; every person, address,
and company-specific value is a placeholder. Platform domains (JobDiva, Workday,
Salesforce, Microsoft) are kept because the checks recognize them by name."""

import unittest

from phishing_header_analyzer.checks import run_all
from phishing_header_analyzer.checks.hops import clock_offset
from phishing_header_analyzer.checks.lookalike import restricted_domain
from phishing_header_analyzer.config import Config
from phishing_header_analyzer.findings import Finding
from phishing_header_analyzer.forwarding import resolve
from phishing_header_analyzer.fwdparse import parse_address
from phishing_header_analyzer.live import DomainInfo, LiveResults, targets
from phishing_header_analyzer.parser import parse_bytes
from phishing_header_analyzer.report import _REPORTING_IF_NEEDED, build_report, recommended_actions

GMAIL = Config(trusted_authserv_ids=["mx.google.com"])


def ids(findings):
    return {f.check_id for f in findings}


def points(findings):
    return sum(f.points for f in findings)


def html(headers: bytes, body: str) -> bytes:
    return headers + b"MIME-Version: 1.0\nContent-Type: text/html; charset=utf-8\n\n" + body.encode()


# Staffing firm on its own mail server with the time zone set 4 hours wrong. The server
# stamps its Received line and the Date header together, so both are off by exactly 4h.
CLOCK_OFFSET = b"""\
Received: from mail.staffing.example (mail.staffing.example. [198.51.100.130])
        by mx.google.com with ESMTPS id abc for <candidate@gmail.example>; Tue, 20 Oct 2026 06:28:28 -0700 (PDT)
Authentication-Results: mx.google.com;
       dkim=pass header.i=@staffing.example header.s=selector2026 header.b=testsig1;
       spf=pass smtp.mailfrom=recruiter@staffing.example;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=staffing.example
Received: from [127.0.0.1] (127.0.0.1) by mail.staffing.example (127.0.0.1)
        with MICROSOFT SMTP Server id 1; Tue, 20 Oct 2026 17:27:11 +0000
From: "Recruiter" <recruiter@staffing.example>
To: candidate@gmail.example
Subject: Principal Systems Architect - Immediate Hire
Date: Tue, 20 Oct 2026 13:27:11 +0000
Message-ID: <abc@staffing.example>

body
"""

# A U.S. agency reply sent from Microsoft 365 through the agency's Proofpoint filter.
AGENCY = b"""\
Received: from mx0f-00376703.gpphosted.com (mx0f-00376703.gpphosted.com. [192.0.2.98])
        by mx.google.com with ESMTPS id abc for <candidate@gmail.example>; Fri, 02 Oct 2026 06:18:16 -0700 (PDT)
Authentication-Results: mx.google.com;
       dkim=pass header.i=@cisa.dhs.gov header.s=select1 header.b=testsig1;
       arc=pass;
       spf=pass smtp.mailfrom=jane.doe@cisa.dhs.gov;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=cisa.dhs.gov
From: "Doe, Jane" <jane.doe@cisa.dhs.gov>
To: candidate@gmail.example
Subject: RE: Application Status Inquiry
Date: Fri, 02 Oct 2026 13:18:08 +0000
Message-ID: <LVWPR09MB0000@LVWPR09MB0000.namprd09.prod.outlook.com>

body
"""

# Staffing firm sending through JobDiva's mail merge with the platform's default DKIM.
JOBDIVA = b"""\
Received: from smtp.jobdivabk.com (smtp.jobdivabk.com. [192.0.2.118])
        by mx.google.com with ESMTPS id abc for <candidate@gmail.example>; Thu, 01 Oct 2026 14:13:55 -0700 (PDT)
Authentication-Results: mx.google.com;
       dkim=pass header.i=@jobdivabk.com header.s=jd1 header.b=testsig1;
       dkim=pass header.i=@jobopportunityforyou.com header.s=jd1 header.b=testsig1;
       spf=pass smtp.mailfrom=recruiter@staffing.example
From: "A Recruiter" <recruiter@staffing.example>
To: candidate@gmail.example
Subject: Now Hiring: Senior Data Center Technician
Date: Thu, 01 Oct 2026 21:05:33 +0000
Message-ID: <100000001.1.1700000000000@emailmerger126-24>
"""

# A member newsletter through Salesforce Marketing Cloud with unbranded click tracking.
SFMC = b"""\
Received: from mta.connect.brand.example (mta.connect.brand.example. [192.0.2.64])
        by mx.google.com with ESMTPS id abc for <member@gmail.example>; Tue, 20 Oct 2026 06:05:38 -0700 (PDT)
Authentication-Results: mx.google.com;
       dkim=pass header.i=@connect.brand.example header.s=12dkim1 header.b=testsig1;
       dkim=pass header.i=@s12.y.mc.salesforce.com header.s=fbldkim12 header.b=testsig1;
       spf=pass smtp.mailfrom=bounce-1@bounce.connect.brand.example;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=connect.brand.example
From: "Brand" <info@connect.brand.example>
To: member@gmail.example
Subject: Continuing Education News
Date: Tue, 20 Oct 2026 13:01:50 +0000
Message-ID: <00000000-0000-0000-0000-000000000001@iad4s12mta2210.xt.local>
"""

# An employer recruiting through Workday, which sends as the platform with replies to the employer.
WORKDAY = b"""\
Received: from a11-128.smtp-out.amazonses.com (a11-128.smtp-out.amazonses.com. [54.240.11.128])
        by mx.google.com with ESMTPS id abc for <candidate@gmail.example>; Tue, 20 Oct 2026 00:00:24 -0700 (PDT)
Authentication-Results: mx.google.com;
       dkim=pass header.i=@myworkday.com header.s=testsel header.b=testsig1;
       dkim=pass header.i=@amazonses.com header.s=testsel header.b=testsig1;
       spf=pass smtp.mailfrom=0100@us-east-1.bounce.myworkday.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=myworkday.com
From: employer@myworkday.com
Reply-To: careers@employer.example
To: candidate@gmail.example
Subject: Application Status Update
Date: Tue, 20 Oct 2026 07:00:23 +0000
Message-ID: <0100000000000001-test@email.amazonses.com>
X-SES-Outgoing: 2026.10.20-54.240.11.128

body
"""

# An AI hiring assistant sending under a big brand's name from the vendor's own domain.
PARADOX = b"""\
Received: from o3.ptr1002.paradox.ai (o3.ptr1002.paradox.ai. [159.183.164.215])
        by mx.google.com with ESMTPS id abc for <candidate@gmail.example>; Fri, 16 Oct 2026 09:33:48 -0700 (PDT)
Authentication-Results: mx.google.com;
       dkim=pass header.i=@paradox.ai header.s=s1 header.b=testsig1;
       dkim=pass header.i=@sendgrid.info header.s=smtpapi header.b=testsig1;
       spf=pass smtp.mailfrom=bounces+1@em3250.paradox.ai;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=paradox.ai
Received: from olivia-api-worker-communication-queue-74fc976f56-f6x5r (unknown)
        by geopod-ismtpd-51 (SG) with ESMTP id 1; Fri, 16 Oct 2026 16:33:46.000 +0000 (UTC)
From: "Olivia from FedEx" <fedex@paradox.ai>
To: candidate@gmail.example
Subject: Complete Your Application
Date: Fri, 16 Oct 2026 16:33:46 +0000
Message-ID: <100000000000.1@olivia-api-worker-communication-queue-74fc976f56-f6x5r>
X-SG-EID: u001.abc

body
"""

# A plain sender with aligned authentication, for link tests. {d} is the sending domain.
SENDER = """\
Authentication-Results: mx.google.com;
       dkim=pass header.i=@{d} header.s=s1 header.b=testsig1;
       spf=pass smtp.mailfrom=news@{d};
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from={d}
From: <news@{d}>
To: reader@gmail.example
Subject: News
"""


def sender(domain: str) -> bytes:
    return SENDER.replace("{d}", domain).encode()


# A recruiter's reply quoting an Outlook thread, which 0.2.1 mistook for an inline forward.
REPLY_BODY = """\
Hi, following up on your application.

________________________________
From: Pat Candidate <candidate@gmail.example<mailto:candidate@gmail.example>>
Sent: Monday, September 14, 2026 5:07 PM
To: recruiter@agency.example
Subject: Network Engineer Application

I'm applying for the role.
"""

REPLY = (b"""\
Received: from mail.agency.example (mail.agency.example. [192.0.2.1])
        by mx.google.com with ESMTPS id abc for <candidate@gmail.example>; Mon, 19 Oct 2026 07:06:04 -0700 (PDT)
Authentication-Results: mx.google.com;
       spf=pass smtp.mailfrom=recruiter@agency.example;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=agency.example
From: "A Recruiter" <recruiter@agency.example>
To: candidate@gmail.example
Subject: Re: Network Engineer Application
Date: Mon, 19 Oct 2026 14:05:58 +0000
Message-ID: <reply-1@agency.example>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

""" + REPLY_BODY.encode())


class ClockOffsetTests(unittest.TestCase):
    def test_whole_hour_offset_is_a_bad_clock_not_forgery(self):
        parsed = parse_bytes(CLOCK_OFFSET)
        self.assertEqual(clock_offset(parsed), 4 * 3600)
        found = ids(run_all(parsed, GMAIL))
        self.assertIn("HOP-CLOCK-OFFSET", found)
        self.assertNotIn("HOP-OUT-OF-ORDER", found)
        self.assertNotIn("DATE-SKEW", found)

    def test_offset_without_matching_date_is_still_out_of_order(self):
        # Same backwards hop, but a Date that doesn't line up with it: no clock excuse.
        raw = CLOCK_OFFSET.replace(b"Date: Tue, 20 Oct 2026 13:27:11 +0000",
                                   b"Date: Tue, 20 Oct 2026 13:20:00 +0000")
        found = ids(run_all(parse_bytes(raw), GMAIL))
        self.assertIn("HOP-OUT-OF-ORDER", found)
        self.assertNotIn("HOP-CLOCK-OFFSET", found)


class RestrictedDomainTests(unittest.TestCase):
    def test_restricted(self):
        self.assertTrue(restricted_domain("cisa.dhs.gov"))
        self.assertTrue(restricted_domain("army.mil"))
        self.assertTrue(restricted_domain("hmrc.gov.uk"))
        self.assertFalse(restricted_domain("dhl.com"))
        self.assertFalse(restricted_domain("gov.example"))

    def test_agency_mail_is_not_a_lookalike(self):
        findings = run_all(parse_bytes(AGENCY), GMAIL)
        self.assertFalse(any("LOOKALIKE" in f.check_id for f in findings), ids(findings))
        self.assertIn("MSGID-PLATFORM", ids(findings))   # Microsoft 365 Message-ID
        self.assertEqual(points(findings), 0)

    def test_filter_relay_ip_is_not_looked_up(self):
        _, ips = targets(parse_bytes(AGENCY), GMAIL)
        self.assertEqual(ips, [])

    def test_established_domain_near_miss_is_downgraded(self):
        raw = (b"Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=a@dhk.example; "
               b"dmarc=pass header.from=dhk.example\nFrom: a@dhk.example\nSubject: hi\n\nbody\n")
        parsed = parse_bytes(raw)
        parsed.live = LiveResults(domains=[DomainInfo("dhk.example", age_days=4000)])
        f = next(f for f in run_all(parsed, GMAIL) if f.check_id == "LOOKALIKE-NEAR-MISS")
        self.assertEqual((f.severity, f.points), ("low", 5))
        parsed.live = LiveResults(domains=[DomainInfo("dhk.example", age_days=20)])
        f = next(f for f in run_all(parsed, GMAIL) if f.check_id == "LOOKALIKE-NEAR-MISS")
        self.assertEqual(f.severity, "high")


class PlatformTests(unittest.TestCase):
    def test_jobdiva_mail_merge(self):
        findings = run_all(parse_bytes(JOBDIVA), GMAIL)
        found = ids(findings)
        self.assertTrue({"HIRING-PLATFORM", "DKIM-PLATFORM-ONLY", "MSGID-PLATFORM", "DMARC-NONE"} <= found)
        self.assertNotIn("DKIM-UNALIGNED", found)
        self.assertNotIn("MSGID-MISMATCH", found)
        self.assertEqual(points(findings), 10)   # only the real gap: no DMARC policy
        platform = next(f for f in findings if f.check_id == "HIRING-PLATFORM")
        self.assertEqual(platform.evidence["platform"], "JobDiva")

    def test_workday_reply_to_employer_is_not_a_mismatch(self):
        findings = run_all(parse_bytes(WORKDAY), GMAIL)
        found = ids(findings)
        self.assertIn("REPLYTO-EMPLOYER", found)
        self.assertNotIn("REPLYTO-MISMATCH", found)
        self.assertIn("MSGID-PLATFORM", found)
        self.assertEqual(points(findings), 0)

    def test_reply_to_freemail_is_still_flagged_on_a_platform(self):
        raw = WORKDAY.replace(b"careers@employer.example", b"hr.dept@gmail.com")
        self.assertIn("REPLYTO-MISMATCH", ids(run_all(parse_bytes(raw), GMAIL)))

    def test_brand_name_on_hiring_platform_explains_itself(self):
        findings = run_all(parse_bytes(PARADOX), GMAIL)
        brand = next(f for f in findings if f.check_id == "DISPLAY-NAME-BRAND")
        self.assertEqual(brand.evidence["platform"], "Paradox")
        self.assertIn("careers site", brand.detail)
        self.assertIn("MSGID-PLATFORM", ids(findings))   # Kubernetes pod name as Message-ID host

    def test_monitor_only_dmarc_is_reported(self):
        raw = JOBDIVA.replace(b"spf=pass smtp.mailfrom=recruiter@staffing.example",
                              b"spf=pass smtp.mailfrom=recruiter@staffing.example;\n"
                              b"       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=staffing.example")
        f = next(f for f in run_all(parse_bytes(raw), GMAIL) if f.check_id == "DMARC-MONITOR-ONLY")
        self.assertEqual(f.points, 0)

    def test_spf_none_says_there_is_no_record(self):
        raw = JOBDIVA.replace(b"spf=pass", b"spf=none")
        f = next(f for f in run_all(parse_bytes(raw), GMAIL) if f.check_id == "SPF-NONE")
        self.assertIn("no SPF record", f.detail)


class LinkTests(unittest.TestCase):
    def test_sfmc_click_tracking_is_not_a_disguise(self):
        raw = html(SFMC, '<a href="https://cl.s12.exct.net/?qs=1">www.brand.example</a>')
        findings = run_all(parse_bytes(raw, inspect_body=True), GMAIL)
        found = ids(findings)
        self.assertIn("LINK-TRACKED", found)
        self.assertNotIn("LINK-TEXT-MISMATCH", found)
        bulk = next(f for f in findings if f.check_id == "BULK-MAIL-SERVICE")
        self.assertEqual(bulk.evidence["service"], "Salesforce Marketing Cloud")
        self.assertIn("MSGID-PLATFORM", found)

    def test_tracker_showing_someone_elses_site_is_still_a_disguise(self):
        raw = html(SFMC, '<a href="https://cl.s12.exct.net/?qs=1">www.paypal.com</a>')
        found = ids(run_all(parse_bytes(raw, inspect_body=True), GMAIL))
        self.assertIn("LINK-TEXT-MISMATCH", found)
        self.assertNotIn("LINK-TRACKED", found)

    def test_link_to_senders_own_domain_under_old_name(self):
        raw = html(sender("globalit.example"),
                   '<a href="https://us.globalit.example/careers">globalitservices.example</a>')
        found = ids(run_all(parse_bytes(raw, inspect_body=True), GMAIL))
        self.assertIn("LINK-TEXT-OWN-DOMAIN", found)
        self.assertNotIn("LINK-TEXT-MISMATCH", found)

    def test_brand_text_pointing_at_sender_is_still_a_disguise(self):
        raw = html(sender("evil.example"),
                   '<a href="https://evil.example/login">www.paypal.com</a>')
        found = ids(run_all(parse_bytes(raw, inspect_body=True), GMAIL))
        self.assertIn("LINK-TEXT-MISMATCH", found)

    def test_social_footer_links_are_not_looked_up(self):
        raw = html(SFMC, '<a href="https://www.facebook.com/brand">f</a>'
                         '<a href="https://www.linkedin.com/company/brand">in</a>')
        domains, _ = targets(parse_bytes(raw, inspect_body=True), GMAIL)
        self.assertNotIn("facebook.com", domains)
        self.assertNotIn("linkedin.com", domains)


class ReplyChainTests(unittest.TestCase):
    def test_quoted_reply_is_not_a_forward(self):
        parsed = resolve(parse_bytes(REPLY, inspect_body=True))
        self.assertIsNone(parsed.forward)
        self.assertEqual(parsed.from_.address, "recruiter@agency.example")
        self.assertFalse(parsed.headers_lost)

    def test_same_blocks_under_fw_subject_are_a_forward(self):
        raw = REPLY.replace(b"Subject: Re: Network", b"Subject: FW: Network")
        parsed = resolve(parse_bytes(raw, inspect_body=True))
        self.assertEqual(parsed.forward.kind, "inline")
        self.assertEqual(parsed.from_.address, "candidate@gmail.example")
        self.assertEqual(parsed.from_.display_name, "Pat Candidate")

    def test_outlook_mailto_address(self):
        self.assertEqual(parse_address("Pat Candidate <pat@a.example<mailto:pat@a.example>>"),
                         ("Pat Candidate", "pat@a.example"))
        self.assertEqual(parse_address("pat@a.example<mailto:pat@a.example>"), ("", "pat@a.example"))


class ActionTests(unittest.TestCase):
    CONTACTS = [
        Finding("DOMAIN-REGISTRAR-ABUSE", "registration", "info", 0, "t", "d",
                {"contacts": ["employer.example: Registrar <abuse@registrar.example>"]}),
        Finding("NETWORK-ABUSE", "registration", "info", 0, "t", "d",
                {"contacts": ["192.0.2.1: Network <abuse@network.example>"]}),
    ]

    def test_low_risk_folds_reporting_into_one_line(self):
        actions = recommended_actions(self.CONTACTS, "low")
        self.assertEqual([a["action"] for a in actions], [_REPORTING_IF_NEEDED])
        self.assertEqual(actions[0]["because"], ["DOMAIN-REGISTRAR-ABUSE", "NETWORK-ABUSE"])

    def test_medium_risk_lists_contacts(self):
        actions = recommended_actions(self.CONTACTS, "medium")
        self.assertEqual(len(actions), 2)
        self.assertTrue(all(a["subjects"] for a in actions))

    def test_clean_platform_mail_has_no_actions(self):
        report = build_report(parse_bytes(WORKDAY), GMAIL)
        self.assertEqual(report["recommended_actions"][0]["because"], ["BULK-MAIL-SERVICE"])
        self.assertEqual(len(report["recommended_actions"]), 1)


if __name__ == "__main__":
    unittest.main()
