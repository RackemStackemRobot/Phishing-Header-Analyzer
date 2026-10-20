"""Checks on what the message body links to. Only runs when the body was inspected.

All of these work from link DOMAINS gathered by body.py. No link is ever visited.
"""

from __future__ import annotations

from ..config import Config
from ..findings import Finding
from ..parser import ParsedHeaders
from ..util import NON_ROUTABLE, classify_ip, is_within, org_domain, same_org
from .esp import TRACKING_DOMAINS
from .lookalike import assess_domain
from .platform import authentic_platform

CATEGORY = "links"
MAX_LISTED = 10


def _platform_checks(parsed: ParsedHeaders, config: Config, name: str) -> list[Finding]:
    out: list[Finding] = []
    body, frm = parsed.body, parsed.from_
    sender_org = org_domain(frm.domain)
    allowed = {sender_org, *config.platform_link_domains.get(sender_org, [])}

    off = sorted(d for d in body.link_domains
                 if not classify_ip(d) and org_domain(d) not in allowed)
    if off:
        out.append(Finding(
            "LINK-OFF-PLATFORM", CATEGORY, "high", 25,
            f"{name} notification links outside {name}",
            f"A genuine {name} notification links back to {name}. Links to other sites "
            "usually mean the attacker put their own landing page in the group description, "
            "file name, or message the platform delivered.",
            {"platform": name, "domains": off[:MAX_LISTED], "allowed": sorted(allowed)},
        ))

    recipients = {a.address for a in parsed.recipients}
    accounts = [a for a in body.addresses
                if a not in recipients and not same_org(a.rsplit("@", 1)[1], frm.domain)]
    if accounts:
        out.append(Finding(
            "PLATFORM-ACCOUNTS", CATEGORY, "info", 0,
            f"Accounts named in the {name} notification",
            "These addresses appear in the notification and are likely the account that "
            "triggered it or the group, file, or envelope it points to. They are the "
            "indicators to verify, report to the platform, or block.",
            {"platform": name, "accounts": accounts[:MAX_LISTED]},
        ))
    return out


def run(parsed: ParsedHeaders, config: Config) -> list[Finding]:
    body = parsed.body
    if body is None:
        return []
    out: list[Finding] = []

    sender = parsed.from_.domain if parsed.from_ else None
    disguised, own, tracked = [], [], {}
    for m in body.mismatches:
        shows_brand = any(is_within(m.shown, w) for w in config.watched_domains)
        if sender and same_org(m.actual, sender) and not shows_brand:
            own.append(m)    # the sender's own site under an old or alternate name
            continue
        service = next((name for d, name in TRACKING_DOMAINS.items() if is_within(m.actual, d)), None)
        if service and sender and same_org(m.shown, sender):
            # The sender's own site, rewritten through its mail platform's click tracker.
            # Text naming anyone else's site stays a disguise, tracker or not.
            tracked.setdefault(service, []).append(m)
        else:
            disguised.append(m)

    if disguised:
        out.append(Finding(
            "LINK-TEXT-MISMATCH", CATEGORY, "high", 20,
            "Link text shows one site but goes to another",
            "The visible text of a link names one domain while the link itself points "
            "somewhere else. Legitimate mail almost never does this; it's a classic "
            "credential-phishing disguise.",
            {"links": [{"shown": m.shown, "goes_to": m.actual} for m in disguised[:MAX_LISTED]]},
        ))
    if own:
        out.append(Finding(
            "LINK-TEXT-OWN-DOMAIN", CATEGORY, "low", 5,
            "Link text names a different site, but the link goes to the sender's own domain",
            "The visible text shows another domain, often an old brand name or a sister site, "
            "while the link goes to the sending domain itself. Usually an outdated template, not "
            "a disguise, but it's the same pattern phishing uses, so it's worth fixing.",
            {"links": [{"shown": m.shown, "goes_to": m.actual} for m in own[:MAX_LISTED]]},
        ))
    for service, items in tracked.items():
        shown = sorted({m.shown for m in items})
        out.append(Finding(
            "LINK-TRACKED", CATEGORY, "low", 5,
            f"Links labeled {', '.join(shown[:3])} run through {service} click tracking",
            f"The link text names one site, but the links go to {service}'s tracking servers "
            "first, which then redirect. Common in marketing email, but the real destination "
            "can't be checked from the email, and it trains readers to ignore the 'hover before "
            "you click' test. A branded tracking domain (a subdomain of the sender's own) fixes it.",
            {"service": service, "shown": shown[:MAX_LISTED],
             "tracking_domains": sorted({m.actual for m in items})[:MAX_LISTED]},
        ))

    ip_links = sorted(d for d in body.link_domains
                      if classify_ip(d) and classify_ip(d) not in NON_ROUTABLE)
    if ip_links:
        out.append(Finding(
            "LINK-IP-LITERAL", CATEGORY, "medium", 15, "Links point to a bare IP address",
            "Legitimate senders link to named domains. Links straight to an IP address "
            "are common in phishing kits and malware delivery.",
            {"ips": ip_links[:MAX_LISTED]},
        ))

    for domain, count in sorted(body.link_domains.items()):
        if classify_ip(domain):
            continue
        out.extend(assess_domain(domain, config.watched_domains, id_prefix="LINK-",
                                 context={"links": count}, category=CATEGORY))

    name = authentic_platform(parsed, config)
    if name:
        out.extend(_platform_checks(parsed, config, name))

    if body.truncated or body.notes:
        out.append(Finding(
            "BODY-PARTIAL", CATEGORY, "info", 0, "Body was only partly inspected",
            "Some of the body was skipped (size cap or unreadable parts). Link findings "
            "may be incomplete.",
            {"notes": body.notes},
        ))
    return out
