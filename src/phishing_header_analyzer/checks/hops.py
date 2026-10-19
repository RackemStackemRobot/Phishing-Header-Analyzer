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
