"""Received chain checks: timing anomalies and suspicious handoff addresses."""

from __future__ import annotations

from ..config import Config
from ..findings import Finding
from ..parser import ParsedHeaders
from ..received import Hop
from ..util import NON_ROUTABLE, classify_ip, is_within
from .auth import trusted_results

CATEGORY = "received"

CLOCK_SKEW_SECONDS = 60          # ignore small negative delays from clock drift
LARGE_DELAY_SECONDS = 3600       # one hour between hops
DATE_BEFORE_ORIGIN_SECONDS = 3600
DATE_AFTER_DELIVERY_SECONDS = 900
TZ_STEP_SECONDS = 1800           # whole and half-hour time zones (4h, 5h30m, ...)
TZ_MAX_SECONDS = 14 * 3600
DATE_TZ_TOLERANCE = 60           # the server writes Date and its own Received stamp together
HOP_TZ_TOLERANCE = 180           # plus a few minutes of real delivery time to the next hop


def tz_offset(seconds: float | None, tolerance: float) -> int | None:
    """If a gap is a whole time-zone step, the step in seconds, else None."""
    if seconds is None:
        return None
    gap = abs(seconds)
    step = round(gap / TZ_STEP_SECONDS) * TZ_STEP_SECONDS
    if TZ_STEP_SECONDS <= step <= TZ_MAX_SECONDS and abs(gap - step) <= tolerance:
        return int(step)
    return None


def clock_offset(parsed: ParsedHeaders) -> int | None:
    """Time-zone error of the originating server, if its first Received stamp is off from
    the Date header by an exact time-zone step.

    A server with its zone set wrong stamps every message off by exactly that amount,
    and since the same server usually writes the Date header, the two line up to the
    second. Forged hops almost never line up this neatly.
    """
    stamped = [h for h in parsed.hops if h.timestamp]
    if not parsed.date or not stamped:
        return None
    return tz_offset((stamped[0].timestamp - parsed.date).total_seconds(), DATE_TZ_TOLERANCE)


def _hours(seconds: int) -> str:
    h, m = divmod(seconds // 60, 60)
    return f"{h}h{m:02d}m" if m else f"{h} hours"


def boundary_hop(parsed: ParsedHeaders, config: Config) -> Hop | None:
    """The hop where the message entered your organization: received by your gateway."""
    gateways = set(config.trusted_authserv_ids)
    if not gateways:
        results, _ = trusted_results(parsed, config)
        gateways = {r.authserv_id for r in results if r.authserv_id}
    for hop in parsed.hops:
        if hop.by_host and any(is_within(hop.by_host, g) for g in gateways):
            return hop
    return None


def run(parsed: ParsedHeaders, config: Config) -> list[Finding]:
    if parsed.headers_lost:
        return []  # inline-forwarded original: the delivery path wasn't preserved
    out: list[Finding] = []
    hops = parsed.hops

    if parsed.x_originating_ip:
        out.append(Finding(
            "X-ORIGINATING-IP", CATEGORY, "info", 0, "Sender's client IP recorded",
            "Some webmail services record the IP of the person who wrote the message. "
            "Useful as a pivot for further investigation.",
            {"ip": parsed.x_originating_ip, "type": classify_ip(parsed.x_originating_ip)},
        ))

    if not hops:
        out.append(Finding("HOPS-NONE", CATEGORY, "low", 5, "No Received headers",
                           "The delivery path can't be traced. Expected with some pasted header snippets."))
        return out

    backwards = [h for h in hops if h.delay_seconds is not None and h.delay_seconds < -CLOCK_SKEW_SECONDS]
    offset = clock_offset(parsed)
    clock = [h for h in backwards if offset and tz_offset(h.delay_seconds, HOP_TZ_TOLERANCE) == offset]
    backwards = [h for h in backwards if h not in clock]
    if clock:
        out.append(Finding(
            "HOP-CLOCK-OFFSET", CATEGORY, "info", 0,
            f"The sending server's clock is off by {_hours(offset)}",
            "A hop is stamped earlier than the one before it by a whole time-zone step. That's the "
            "signature of a server with its time zone set wrong, not of forged headers. It points "
            "to a poorly maintained mail server, nothing more.",
            {"offset_seconds": offset,
             "hops": [{"index": h.index, "from_host": h.from_host, "delay_seconds": h.delay_seconds}
                      for h in clock]},
        ))
    if backwards:
        out.append(Finding(
            "HOP-OUT-OF-ORDER", CATEGORY, "medium", 15, "Received timestamps go backwards",
            "A later hop is stamped earlier than the one before it. Usually means the "
            "earlier hops were fabricated by the sender.",
            {"hops": [{"index": h.index, "from_host": h.from_host, "delay_seconds": h.delay_seconds}
                      for h in backwards]},
        ))

    slow = [h for h in hops if h.delay_seconds is not None and h.delay_seconds > LARGE_DELAY_SECONDS]
    if slow:
        out.append(Finding(
            "HOP-LARGE-DELAY", CATEGORY, "low", 5, "Long delay between hops",
            "More than an hour passed between servers. Can be normal queueing, also "
            "seen when mail is held and released in bulk campaigns.",
            {"hops": [{"index": h.index, "from_host": h.from_host, "delay_seconds": h.delay_seconds}
                      for h in slow]},
        ))

    stamped = [h for h in hops if h.timestamp]
    if parsed.date and stamped:
        origin, delivered = stamped[0].timestamp, stamped[-1].timestamp
        before = (origin - parsed.date).total_seconds()
        after = (parsed.date - delivered).total_seconds()
        # A first hop off by the same time-zone step as a bad clock isn't a skewed Date.
        if clock and before > DATE_BEFORE_ORIGIN_SECONDS:
            before = 0
        if before > DATE_BEFORE_ORIGIN_SECONDS or after > DATE_AFTER_DELIVERY_SECONDS:
            out.append(Finding(
                "DATE-SKEW", CATEGORY, "medium", 10, "Date header doesn't match the delivery timeline",
                "The Date the sender wrote is far from when servers actually handled the "
                "message. Senders control the Date header; servers control Received.",
                {"date_header": parsed.date.isoformat(), "first_hop": origin.isoformat(),
                 "last_hop": delivered.isoformat()},
            ))

    boundary = boundary_hop(parsed, config)
    if boundary and boundary.from_ip:
        kind = classify_ip(boundary.from_ip)
        if kind in NON_ROUTABLE:
            out.append(Finding(
                "BOUNDARY-IP-NONROUTABLE", CATEGORY, "medium", 15,
                f"Gateway received the message from a {kind} address",
                "Your gateway is the first server you trust. The hop it recorded should "
                "come from a public internet address, not an internal or loopback one.",
                {"hop": boundary.index, "from_ip": boundary.from_ip, "by_host": boundary.by_host},
            ))

    notes = [n for h in hops for n in h.parse_notes]
    if notes:
        out.append(Finding("HOPS-PARSE-NOTES", CATEGORY, "info", 0, "Some Received headers were malformed",
                           "These could not be fully parsed. Malformed hops are sometimes hand-written.",
                           {"notes": notes}))

    return out
