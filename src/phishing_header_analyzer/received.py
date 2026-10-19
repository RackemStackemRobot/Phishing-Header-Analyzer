"""Parse Received headers into structured hops.

Received headers are prepended by each server that handles a message, so the
topmost header is the most recent hop. This module returns hops in delivery
order (origin first) to make the path easier to read.

Anything below your own organization's trusted gateway can be forged by the
sender. This module only extracts; it does not decide what to trust.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

_FROM_RE = re.compile(r"\bfrom\s+(\S+)", re.IGNORECASE)
_BY_RE = re.compile(r"\bby\s+(\S+)", re.IGNORECASE)
_WITH_RE = re.compile(r"\bwith\s+(\S+)", re.IGNORECASE)
_IP_RE = re.compile(r"\[(?:IPv6:)?([0-9A-Fa-f:.]+)\]")
_FRACTION_RE = re.compile(r"(\d{1,2}:\d{2}:\d{2})\.\d+")
_ISO_TS_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:\.\d+)?\s*(?:([+-]\d{2}):?(\d{2})|Z\b|UTC\b)?")


def _parse_iso(m: re.Match) -> datetime | None:
    try:
        ts = datetime.strptime(f"{m.group(1)} {m.group(2)}", "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
    if m.group(3):
        sign = -1 if m.group(3).startswith("-") else 1
        offset = timedelta(hours=int(m.group(3)[1:]), minutes=int(m.group(4)))
        ts = (ts - sign * offset)
    return ts.replace(tzinfo=timezone.utc)


@dataclass
class Hop:
    index: int                      # 1 = origin, ascending toward recipient
    raw: str
    from_host: str | None = None
    from_ip: str | None = None
    by_host: str | None = None
    protocol: str | None = None
    timestamp: datetime | None = None   # always UTC when present
    timestamp_had_tz: bool = True
    delay_seconds: float | None = None  # time since previous hop; negative = out of order
    parse_notes: list[str] = field(default_factory=list)


def _valid_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def parse_received(value: str) -> Hop:
    """Parse one unfolded Received header value. Index is set by parse_chain."""
    raw = " ".join(value.split())
    hop = Hop(index=0, raw=raw)

    # The timestamp follows the last semicolon (RFC 5321 section 4.4).
    clauses, sep, date_part = raw.rpartition(";")
    if not sep:
        clauses, date_part = raw, ""
        # Some internal relays (SendGrid's, for one) skip the semicolon and write
        # an ISO-style time instead: "2026-10-19 15:19:12.122905 +0000 UTC".
        if m := _ISO_TS_RE.search(raw):
            hop.timestamp = _parse_iso(m)
        if hop.timestamp is None:
            hop.parse_notes.append("no timestamp found")

    # Only look for the sending IP inside the "from" clause, not the "by" clause.
    by_match = _BY_RE.search(clauses)
    from_clause = clauses[: by_match.start()] if by_match else clauses

    if m := _FROM_RE.search(from_clause):
        hop.from_host = m.group(1).lower().rstrip(".")
    if m := _IP_RE.search(from_clause):
        hop.from_ip = _valid_ip(m.group(1))
        if hop.from_ip is None:
            hop.parse_notes.append(f"unparseable IP: {m.group(1)}")
    if by_match:
        hop.by_host = by_match.group(1).lower().rstrip(".")
    if m := _WITH_RE.search(clauses):
        hop.protocol = m.group(1).upper()

    if date_part.strip():
        try:
            # Drop fractional seconds ("15:19:12.105"); the RFC 5322 parser rejects them.
            ts = parsedate_to_datetime(_FRACTION_RE.sub(r"\1", date_part.strip()))
            if ts.tzinfo is None:
                hop.timestamp_had_tz = False
                ts = ts.replace(tzinfo=timezone.utc)
            hop.timestamp = ts.astimezone(timezone.utc)
        except (TypeError, ValueError):
            hop.parse_notes.append(f"unparseable timestamp: {date_part.strip()}")

    return hop


def parse_chain(received_values: list[str]) -> list[Hop]:
    """Parse Received headers as they appear in the message (topmost first).

    Returns hops in delivery order, origin first, with delays filled in.
    """
    hops = [parse_received(v) for v in reversed(received_values)]
    previous: datetime | None = None
    for i, hop in enumerate(hops, start=1):
        hop.index = i
        if hop.timestamp and previous:
            hop.delay_seconds = (hop.timestamp - previous).total_seconds()
        if hop.timestamp:
            previous = hop.timestamp
    return hops
