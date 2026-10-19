"""Findings from --live registration lookups. Nothing here runs unless --live did."""

from __future__ import annotations

from ..config import Config
from ..findings import Finding
from ..parser import ParsedHeaders

CATEGORY = "registration"
NEW_HIGH_DAYS = 30
NEW_MEDIUM_DAYS = 180


def run(parsed: ParsedHeaders, config: Config) -> list[Finding]:
    live = parsed.live
    if live is None:
        return []
    out: list[Finding] = []

    for d in live.domains:
        if d.age_days is None:
            continue
        if d.age_days < NEW_HIGH_DAYS:
            sev, pts = "high", 25
        elif d.age_days < NEW_MEDIUM_DAYS:
            sev, pts = "medium", 10
        else:
            continue
        out.append(Finding(
            "DOMAIN-NEWLY-REGISTERED", CATEGORY, sev, pts,
            f"{d.domain} was registered {d.age_days} days ago",
            "Scam and phishing campaigns usually run from freshly registered domains that get "
            "abandoned once they're blocked. Established organizations rarely send from a "
            "domain only weeks or months old.",
            {"domain": d.domain, "registered": d.registered, "age_days": d.age_days, "registrar": d.registrar},
        ))

    registrars = [f"{d.domain}: {d.registrar or 'registrar'} <{d.abuse_email}>"
                  for d in live.domains if d.abuse_email]
    if registrars:
        out.append(Finding(
            "DOMAIN-REGISTRAR-ABUSE", CATEGORY, "info", 0, "Registrar abuse contacts found",
            "From public registration data. A registrar can suspend a domain used for "
            "phishing or fraud, which takes down every campaign using it.",
            {"contacts": registrars},
        ))

    networks = [f"{i.ip}: {i.org or i.network or 'network'} <{i.abuse_email}>"
                for i in live.ips if i.abuse_email]
    if networks:
        out.append(Finding(
            "NETWORK-ABUSE", CATEGORY, "info", 0, "Network abuse contacts found",
            "From public IP registration data. The network operator can act on the server "
            "that sent or hosts this message's content.",
            {"contacts": networks},
        ))

    errors = [f"{d.domain}: {d.error}" for d in live.domains if d.error]
    errors += [f"{i.ip}: {i.error}" for i in live.ips if i.error]
    if errors or live.notes:
        out.append(Finding(
            "LIVE-LOOKUP-NOTES", CATEGORY, "info", 0, "Some live lookups didn't complete",
            "Results for these may be missing. Registries vary in what they publish, and "
            "some country-code domains have no RDAP service.",
            {"notes": live.notes + errors},
        ))
    return out
