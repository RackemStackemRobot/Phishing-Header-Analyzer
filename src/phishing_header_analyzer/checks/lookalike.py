"""Lookalike domain checks: punycode, homoglyphs, and near-miss spellings.

assess_domain() is shared with the link checks so sender domains and link
domains are judged by exactly the same rules.
"""

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


def assess_domain(domain: str, watched: list[str], id_prefix: str = "",
                  context: dict | None = None, category: str = CATEGORY) -> list[Finding]:
    """Lookalike findings for one domain. id_prefix distinguishes link findings ("LINK-")."""
    out: list[Finding] = []
    if any(is_within(domain, w) for w in watched):
        return out  # it IS a protected domain; authentication checks handle spoofing
    context = context or {}

    if any(lbl.startswith("xn--") for lbl in domain.split(".")):
        out.append(Finding(
            f"{id_prefix}IDN-DOMAIN", category, "medium", 10, "Internationalized (punycode) domain",
            "The domain contains non-Latin characters encoded as punycode. Legitimate "
            "for many languages, but also used to build visually identical fakes.",
            {"domain": domain, "displays_as": decode_domain(domain), **context},
        ))

    label = decode_idna(org_label(domain) or "")
    if not label:
        return out
    sk = skeleton(label)

    for w in watched:
        wlabel = org_label(w) or ""
        if not wlabel or label == wlabel:
            continue
        ev = {"domain": domain, "displays_as": decode_domain(domain), "resembles": w, **context}
        if sk == skeleton(wlabel):
            out.append(Finding(
                f"{id_prefix}LOOKALIKE-HOMOGLYPH", category, "high", 30, f"Domain is a homoglyph of {w}",
                "Characters were swapped for ones that look the same (for example 0 for o, "
                "or a Cyrillic letter for a Latin one). Almost never legitimate.",
                ev,
            ))
            break
        limit = 1 if len(wlabel) < 8 else 2
        if levenshtein(label.lower(), wlabel) <= limit:
            out.append(Finding(
                f"{id_prefix}LOOKALIKE-NEAR-MISS", category, "high", 25, f"Domain is one typo away from {w}",
                "The domain differs from a protected domain by a character or two. "
                "Typosquatted domains are registered specifically to be misread.",
                ev,
            ))
            break
        if len(wlabel) >= 5 and wlabel in label.lower():
            out.append(Finding(
                f"{id_prefix}LOOKALIKE-CONTAINS-BRAND", category, "medium", 15,
                f"Domain contains the brand name {wlabel}",
                "The domain wraps a protected brand in extra words (for example "
                "brand-secure-login). Brands rarely use domains like this.",
                ev,
            ))
            break
    return out


def run(parsed: ParsedHeaders, config: Config) -> list[Finding]:
    out: list[Finding] = []
    for domain, headers in _sender_domains(parsed).items():
        out.extend(assess_domain(domain, config.watched_domains, context={"headers": headers}))
    return out
