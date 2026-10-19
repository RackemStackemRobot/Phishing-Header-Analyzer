"""Trusted-service abuse: authentic notifications sent on someone else's behalf.

Attackers create a real Google Group, share a real file, or send a real DocuSign
envelope or PayPal invoice, and the platform delivers the lure for them. Every
header is genuine, so spoofing checks find nothing. Authentication proves the
platform sent it, not that the account behind it is trustworthy.
"""

from __future__ import annotations

from fnmatch import fnmatchcase

from ..config import Config
from ..findings import Finding
from ..parser import ParsedHeaders
from .auth import trusted_results

CATEGORY = "platform"


def match_platform(address: str | None, patterns: dict[str, str]) -> str | None:
    if not address:
        return None
    address = address.lower()
    for pattern, name in patterns.items():
        if fnmatchcase(address, pattern.lower()):
            return name
    return None


def authentic_platform(parsed: ParsedHeaders, config: Config) -> str | None:
    """Platform name if this is a genuine (DMARC-passing) platform notification, else None.

    A spoofed platform address fails DMARC and is already flagged by the
    authentication checks, so it doesn't count here.
    """
    frm = parsed.from_
    name = match_platform(frm.address if frm else None, config.platform_senders)
    if not name:
        return None
    results, _ = trusted_results(parsed, config)
    dmarc = next((r for r in results if r.method == "dmarc"), None)
    return name if dmarc and dmarc.result == "pass" else None


def run(parsed: ParsedHeaders, config: Config) -> list[Finding]:
    name = authentic_platform(parsed, config)
    if not name:
        return []
    return [Finding(
        "PLATFORM-NOTIFICATION", CATEGORY, "medium", 20,
        f"Authentic {name} notification sent on behalf of another account",
        f"This message really came from {name}, which is why SPF, DKIM, and DMARC pass. "
        "That authenticates the platform, not the account that triggered the notification. "
        "Attackers create real groups, shares, envelopes, and invoices so the platform "
        "delivers their lure for them.",
        {"platform": name, "from": parsed.from_.address},
    )]
