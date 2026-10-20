"""Identify the bulk email service, marketing platform, or hiring platform that
delivered a message.

Sending through SendGrid, Mailgun, Amazon SES and the like is normal for
legitimate newsletters and receipts, so this is informational (0 points). Its
value is knowing who can shut the sending account down: reporting the account
to the service is usually more effective than blocking one domain.

Only strong fingerprints count: a DKIM signature by the service, a relay
hostname belonging to it, or a service-specific header that actually has a
value. Real-world mail sometimes carries EMPTY headers named after other
services (left over from bulk-mailing templates), so empty headers are ignored.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..config import Config
from ..findings import Finding
from ..parser import ParsedHeaders
from ..util import classify_ip, is_within
from .auth import dkim_signing_domain

CATEGORY = "delivery"


BULK = "bulk email service"
MARKETING = "marketing email platform"
HIRING = "hiring platform"


@dataclass(frozen=True)
class Service:
    name: str
    dkim_domains: tuple[str, ...]     # domains the service signs with
    relay_domains: tuple[str, ...]    # domains of its sending servers
    headers: tuple[str, ...]          # service-specific header names (lowercase)
    abuse: str                        # where to report an abusive account; verify before sending
    kind: str = BULK
    msgid_patterns: tuple[str, ...] = ()   # regexes matched against the Message-ID's right side
    sender_domains: tuple[str, ...] = ()   # domains the platform puts in From for its customers
    tracking_domains: tuple[str, ...] = () # click-tracking domains its links are rewritten through


SERVICES = (
    Service("SendGrid (Twilio)", ("sendgrid.info", "sendgrid.net"), ("sendgrid.net",),
            ("x-sg-eid", "x-sg-id"), "abuse@sendgrid.com", tracking_domains=("sendgrid.net",)),
    Service("Mailgun", ("mailgun.org", "mailgun.net"), ("mailgun.net", "mailgun.org"),
            ("x-mailgun-sid", "x-mailgun-tag", "x-mailgun-variables"), "abuse@mailgun.com"),
    Service("Amazon SES", ("amazonses.com",), ("amazonses.com",),
            ("x-ses-outgoing",), "abuse@amazonaws.com",
            msgid_patterns=(r"(^|\.)amazonses\.com$",), tracking_domains=("awstrack.me",)),
    Service("Mailchimp / Mandrill", ("mcsv.net", "mandrillapp.com", "mailchimpapp.net"),
            ("mcsv.net", "mandrillapp.com", "rsgsv.net"),
            ("x-mc-user", "x-mandrill-user"), "abuse@mailchimp.com",
            tracking_domains=("list-manage.com", "mandrillapp.com")),
    Service("Postmark", ("pm.mtasv.net",), ("mtasv.net",), ("x-pm-message-id",), "abuse@postmarkapp.com"),
    Service("SparkPost", ("sparkpostmail.com",), ("sparkpostmail.com",), (), "abuse@sparkpost.com"),
    Service("Brevo (Sendinblue)", ("sendinblue.com", "brevo.com"), ("sendinblue.com", "brevo.com"),
            ("x-mailin-eid", "x-mailin-client"), "abuse@brevo.com"),
    Service("Constant Contact", ("ccsend.com",), ("ccsend.com", "constantcontact.com"),
            (), "abuse@constantcontact.com", tracking_domains=("rs6.net",)),
    Service("Salesforce Marketing Cloud", ("mc.salesforce.com", "exacttarget.com"),
            ("exacttarget.com", "exct.net"), (), "abuse@salesforce.com", kind=MARKETING,
            msgid_patterns=(r"\.xt\.local$",), tracking_domains=("exct.net",)),
    # Hiring platforms: applicant tracking systems that send job postings and application
    # updates on an employer's behalf. Abuse goes to the employer or the platform's support.
    Service("JobDiva", ("jobdivabk.com", "jobopportunityforyou.com"),
            ("jobdivabk.com", "jobopportunityforyou.com"), (), "", kind=HIRING,
            msgid_patterns=(r"^emailmerger?[\d-]*$",)),
    Service("Oracle Taleo", (), ("taleo.net",), (), "", kind=HIRING),
    Service("Workday", ("myworkday.com",), (), (), "", kind=HIRING,
            sender_domains=("myworkday.com",)),
    Service("Paradox", ("paradox.ai",), (), (), "", kind=HIRING,
            sender_domains=("paradox.ai",)),
    Service("Newton", (), ("newtonsoftware.com",), (), "", kind=HIRING),
)

# Message-ID hosts that are normal for the mail system that generated them.
EXPECTED_MSGID_HOSTS = (
    (r"\.prod\.outlook\.com$", "Microsoft 365"),
    (r"(^|\.)mail\.gmail\.com$", "Gmail"),
)

TRACKING_DOMAINS = {d: s.name for s in SERVICES for d in s.tracking_domains}
HIRING_SENDER_DOMAINS = {d: s.name for s in SERVICES if s.kind == HIRING for d in s.sender_domains}


def identify(parsed: ParsedHeaders) -> list[tuple[Service, list[str]]]:
    """Each service detected, with the fingerprints that identified it."""
    signers = [d for r in parsed.auth_results if r.method == "dkim" and (d := dkim_signing_domain(r))]
    relay_hosts = [h for hop in parsed.hops for h in (hop.from_host, hop.by_host) if h]
    found = []
    for svc in SERVICES:
        evidence = []
        for d in signers:
            if any(is_within(d, s) for s in svc.dkim_domains):
                evidence.append(f"DKIM signature by {d}")
        for h in relay_hosts:
            if any(is_within(h, r) for r in svc.relay_domains):
                evidence.append(f"relayed by {h}")
        for name in svc.headers:
            if any(v.strip() for v in parsed.raw_headers.get(name, [])):
                evidence.append(f"{name} header present")
        mid = parsed.message_id_domain or ""
        if mid and any(re.search(p, mid, re.IGNORECASE) for p in svc.msgid_patterns):
            evidence.append(f"Message-ID generated by {svc.name} ({mid})")
        frm = parsed.from_.domain if parsed.from_ else None
        if frm and any(is_within(frm, d) for d in svc.sender_domains):
            evidence.append(f"sent from {svc.name}'s domain {frm}")
        if evidence:
            found.append((svc, sorted(set(evidence))))
    return found


def expected_msgid(parsed: ParsedHeaders, services=None) -> str | None:
    """Name of the platform that normally generates this Message-ID host, if any."""
    mid = parsed.message_id_domain or ""
    if not mid:
        return None
    for pattern, name in EXPECTED_MSGID_HOSTS:
        if re.search(pattern, mid, re.IGNORECASE):
            return name
    services = identify(parsed) if services is None else services
    for svc, _ in services:
        if any(re.search(p, mid, re.IGNORECASE) for p in svc.msgid_patterns):
            return svc.name
        if any(is_within(mid, r) for r in svc.relay_domains):
            return svc.name
    # Internal hostnames and loopback addresses ("worker-pod-7f9c", "127.0.0.1") carry no
    # domain to compare; when a known platform delivered the message, they're its own.
    if services and ("." not in mid or classify_ip(mid)):
        # The application that wrote the message (a hiring or marketing platform) names its
        # own hosts; a bulk service further down the line only relays it.
        ranked = sorted(services, key=lambda item: item[0].kind == BULK)
        return ranked[0][0].name
    return None


def known_signer(domain: str | None) -> str | None:
    """Service name if this DKIM signing domain belongs to a known sending platform."""
    if not domain:
        return None
    for svc in SERVICES:
        if any(is_within(domain, d) for d in svc.dkim_domains):
            return svc.name
    return None


def hiring_sender(domain: str | None) -> str | None:
    """Hiring platform name if the From domain is a platform sending for its customers."""
    if not domain:
        return None
    for d, name in HIRING_SENDER_DOMAINS.items():
        if is_within(domain, d):
            return name
    return None


def run(parsed: ParsedHeaders, config: Config) -> list[Finding]:
    out = []
    for svc, evidence in identify(parsed):
        if svc.kind == HIRING:
            out.append(Finding(
                "HIRING-PLATFORM", CATEGORY, "info", 0, f"Sent through {svc.name}",
                f"{svc.name} is a hiring platform. Employers use it to send job postings and "
                "application updates, often to large lists through a mail merge. Mail from a "
                "hiring platform proves the platform sent it, not which employer or recruiter "
                "is behind it.",
                {"platform": svc.name, "fingerprints": evidence},
            ))
            continue
        out.append(Finding(
            "BULK-MAIL-SERVICE", CATEGORY, "info", 0, f"Delivered through {svc.name}",
            f"The message was sent through {svc.name}, a {svc.kind}. That's normal for "
            "newsletters and receipts, and it's also how many scam campaigns are sent. If this "
            f"message is unwanted or malicious, {svc.name} can suspend the sending account.",
            {"service": svc.name, "abuse_contact": svc.abuse, "fingerprints": evidence},
        ))
    return out
