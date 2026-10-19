"""Lookalike domain checks: punycode, homoglyphs, and near-miss spellings."""

from __future__ import annotations

from ..config import Config
from ..findings import Finding
from ..parser import ParsedHeaders
from ..util import decode_domain, decode_idna, is_within, levenshtein, org_label, skeleton

CATEGORY = "lookalike"


def _sender_domains(parsed: ParsedHeaders) -> dict[str, list[str]]:
    """Map each sender-side domain to the headers it appeared in."""
    seen: dict[str, list[str]] = {}
    pairs = [("From", parsed.from_), ("Return-Path", parsed.return_path), ("Sender", parsed.sender)]
    pairs += [("Reply-To", a) for a in parsed.reply_to]
    for header, addr in pairs:
        if addr and addr.domain:
            seen.setdefault(addr.domain, []).append(header)
    return seen


def run(parsed: ParsedHeaders, config: Config) -> list[Finding]:
    out: list[Finding] = []
    watched = config.watched_domains

    for domain, headers in _sender_domains(parsed).items():
        if any(is_within(domain, w) for w in watched):
            continue  # it IS a protected domain; authentication checks handle spoofing

        if any(lbl.startswith("xn--") for lbl in domain.split(".")):
            out.append(Finding(
                "IDN-DOMAIN", CATEGORY, "medium", 10, "Internationalized (punycode) domain",
                "The domain contains non-Latin characters encoded as punycode. Legitimate "
                "for many languages, but also used to build visually identical fakes.",
                {"domain": domain, "displays_as": decode_domain(domain), "headers": headers},
            ))

        label = decode_idna(org_label(domain) or "")
        if not label:
            continue
        sk = skeleton(label)

        for w in watched:
            wlabel = org_label(w) or ""
            if not wlabel or label == wlabel:
                continue
            ev = {"domain": domain, "displays_as": decode_domain(domain), "resembles": w, "headers": headers}
            if sk == skeleton(wlabel):
                out.append(Finding(
                    "LOOKALIKE-HOMOGLYPH", CATEGORY, "high", 30, f"Domain is a homoglyph of {w}",
                    "Characters were swapped for ones that look the same (for example 0 for o, "
                    "or a Cyrillic letter for a Latin one). Almost never legitimate.",
                    ev,
                ))
                break
            limit = 1 if len(wlabel) < 8 else 2
            if levenshtein(label.lower(), wlabel) <= limit:
                out.append(Finding(
                    "LOOKALIKE-NEAR-MISS", CATEGORY, "high", 25, f"Domain is one typo away from {w}",
                    "The domain differs from a protected domain by a character or two. "
                    "Typosquatted domains are registered specifically to be misread.",
                    ev,
                ))
                break
            if len(wlabel) >= 5 and wlabel in label.lower():
                out.append(Finding(
                    "LOOKALIKE-CONTAINS-BRAND", CATEGORY, "medium", 15, f"Domain contains the brand name {wlabel}",
                    "The domain wraps a protected brand in extra words (for example "
                    "brand-secure-login). Brands rarely send from domains like this.",
                    ev,
                ))
                break

    return out
