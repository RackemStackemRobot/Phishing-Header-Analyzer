"""Run every check against a parsed message."""

from __future__ import annotations

from ..config import Config
from ..findings import Finding
from ..parser import ParsedHeaders
from ..util import org_domain
from . import auth, esp, forward, hops, identity, links, lookalike, platform, rdap

CHECK_MODULES = (forward, auth, identity, hops, lookalike, platform, links, esp, rdap)

ESTABLISHED_DAYS = 5 * 365
_SPELLING = ("LOOKALIKE-NEAR-MISS", "LOOKALIKE-CONTAINS-BRAND")


def _weigh_established(parsed: ParsedHeaders, findings: list[Finding]) -> None:
    """Spelling-based lookalike flags on long-established domains are usually coincidence
    (dhs vs dhl). Typosquats are registered for a campaign and dropped within months, so
    when --live shows the domain is years old, keep the flag but stop scoring it high."""
    if parsed.live is None:
        return
    ages = {d.domain: d.age_days for d in parsed.live.domains if d.age_days is not None}
    for f in findings:
        if not f.check_id.endswith(_SPELLING):
            continue
        age = ages.get(org_domain(f.evidence.get("domain")) or "")
        if age is not None and age >= ESTABLISHED_DAYS:
            f.severity, f.points = "low", 5
            f.evidence["registered_days_ago"] = age
            f.detail += (f" This domain has been registered for {age // 365} years, which makes a "
                         "deliberate typosquat unlikely.")


def run_all(parsed: ParsedHeaders, config: Config | None = None) -> list[Finding]:
    config = config or Config()
    findings: list[Finding] = []
    for module in CHECK_MODULES:
        findings.extend(module.run(parsed, config))
    _weigh_established(parsed, findings)
    return findings
