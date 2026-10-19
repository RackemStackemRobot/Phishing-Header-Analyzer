"""Identify the bulk email service that delivered a message.

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

from dataclasses import dataclass

from ..config import Config
from ..findings import Finding
from ..parser import ParsedHeaders
from ..util import is_within
from .auth import dkim_signing_domain

CATEGORY = "delivery"


@dataclass(frozen=True)
class Service:
    name: str
    dkim_domains: tuple[str, ...]     # domains the service signs with
    relay_domains: tuple[str, ...]    # domains of its sending servers
    headers: tuple[str, ...]          # service-specific header names (lowercase)
    abuse: str                        # where to report an abusive account; verify before sending


SERVICES = (
    Service("SendGrid (Twilio)", ("sendgrid.info", "sendgrid.net"), ("sendgrid.net",),
            ("x-sg-eid", "x-sg-id"), "abuse@sendgrid.com"),
    Service("Mailgun", ("mailgun.org", "mailgun.net"), ("mailgun.net", "mailgun.org"),
            ("x-mailgun-sid", "x-mailgun-tag", "x-mailgun-variables"), "abuse@mailgun.com"),
    Service("Amazon SES", ("amazonses.com",), ("amazonses.com",),
            ("x-ses-outgoing",), "abuse@amazonaws.com"),
    Service("Mailchimp / Mandrill", ("mcsv.net", "mandrillapp.com", "mailchimpapp.net"),
            ("mcsv.net", "mandrillapp.com", "rsgsv.net"),
            ("x-mc-user", "x-mandrill-user"), "abuse@mailchimp.com"),
    Service("Postmark", ("pm.mtasv.net",), ("mtasv.net",), ("x-pm-message-id",), "abuse@postmarkapp.com"),
    Service("SparkPost", ("sparkpostmail.com",), ("sparkpostmail.com",), (), "abuse@sparkpost.com"),
    Service("Brevo (Sendinblue)", ("sendinblue.com", "brevo.com"), ("sendinblue.com", "brevo.com"),
            ("x-mailin-eid", "x-mailin-client"), "abuse@brevo.com"),
    Service("Constant Contact", ("ccsend.com",), ("ccsend.com", "constantcontact.com"),
            (), "abuse@constantcontact.com"),
)


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
        if evidence:
            found.append((svc, sorted(set(evidence))))
    return found


def run(parsed: ParsedHeaders, config: Config) -> list[Finding]:
    out = []
    for svc, evidence in identify(parsed):
        out.append(Finding(
            "BULK-MAIL-SERVICE", CATEGORY, "info", 0, f"Delivered through {svc.name}",
            f"The message was sent through {svc.name}, a bulk email service. That's normal for "
            "newsletters and receipts, and it's also how many scam campaigns are sent. If this "
            f"message is unwanted or malicious, {svc.name} can suspend the sending account.",
            {"service": svc.name, "abuse_contact": svc.abuse, "fingerprints": evidence},
        ))
    return out
