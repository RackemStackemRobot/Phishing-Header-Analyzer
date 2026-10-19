"""The Finding record every check returns."""

from __future__ import annotations

from dataclasses import dataclass, field

SEVERITIES = ("info", "low", "medium", "high")


@dataclass
class Finding:
    check_id: str          # stable ID, e.g. "SPF-FAIL"
    category: str          # authentication, identity, received, lookalike
    severity: str          # info, low, medium, high
    points: int            # contribution to the risk score (0 for info)
    title: str             # one-line summary
    detail: str            # why it matters, in plain language
    evidence: dict = field(default_factory=dict)

    def __post_init__(self):
        if self.severity not in SEVERITIES:
            raise ValueError(f"unknown severity: {self.severity}")
