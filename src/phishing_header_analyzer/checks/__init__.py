"""Run every check against a parsed message."""

from __future__ import annotations

from ..config import Config
from ..findings import Finding
from ..parser import ParsedHeaders
from . import auth, hops, identity, lookalike, platform

CHECK_MODULES = (auth, identity, hops, lookalike, platform)


def run_all(parsed: ParsedHeaders, config: Config | None = None) -> list[Finding]:
    config = config or Config()
    findings: list[Finding] = []
    for module in CHECK_MODULES:
        findings.extend(module.run(parsed, config))
    return findings
