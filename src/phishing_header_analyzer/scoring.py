"""Turn findings into a 0-100 risk score and a risk level.

The score is a plain sum of each finding's points, capped at 100, so every
point in the score can be traced back to a stated reason.
"""

from __future__ import annotations

from dataclasses import dataclass

from .findings import Finding

MAX_SCORE = 100
MEDIUM_AT = 20
HIGH_AT = 50
LEVELS = ("low", "medium", "high")


@dataclass
class Risk:
    score: int          # 0-100
    raw_points: int     # uncapped sum
    level: str          # low, medium, high
    reasons: list[str]  # why the level is what it is


def score(findings: list[Finding]) -> Risk:
    raw = sum(f.points for f in findings)
    capped = min(raw, MAX_SCORE)
    highs = [f for f in findings if f.severity == "high"]

    if capped >= HIGH_AT:
        level, reasons = "high", [f"score {capped} is at or above {HIGH_AT}"]
    elif capped >= MEDIUM_AT:
        level, reasons = "medium", [f"score {capped} is between {MEDIUM_AT} and {HIGH_AT - 1}"]
    else:
        level, reasons = "low", [f"score {capped} is below {MEDIUM_AT}"]

    # Overrides: strong individual signals shouldn't be diluted by a low total.
    if len(highs) >= 2 and level != "high":
        level = "high"
        reasons.append(f"{len(highs)} high-severity findings raise the level to high")
    elif len(highs) == 1 and level == "low":
        level = "medium"
        reasons.append("a high-severity finding raises the level to at least medium")

    return Risk(score=capped, raw_points=raw, level=level, reasons=reasons)
