"""Load an .eml file or raw header text and extract the fields the checks need.

Uses only the standard library. Nothing here makes network requests, and the
message body and attachments are never opened or rendered.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from pathlib import Path

from .body import BodyInfo, extract
from .received import Hop, parse_chain


@dataclass
class Address:
    display_name: str
    address: str
    domain: str | None


@dataclass
class AuthResult:
    method: str                     # spf, dkim, dmarc, arc, ...
    result: str                     # pass, fail, softfail, none, neutral, ...
    authserv_id: str | None         # server that recorded the verdict
    header_index: int               # 0 = topmost Authentication-Results header
    properties: dict[str, str] = field(default_factory=dict)  # header.d, smtp.mailfrom, ...
    policy: str | None = None       # DMARC p= value from the comment, if present


@dataclass
class ReceivedSPF:
    result: str
    client_ip: str | None


@dataclass
class ParsedHeaders:
    source: str
    subject: str | None
    date: datetime | None
    from_: Address | None
    reply_to: list[Address]
    return_path: Address | None
    sender: Address | None
    message_id: str | None
    message_id_domain: str | None
    auth_results: list[AuthResult]
    received_spf: list[ReceivedSPF]
    hops: list[Hop]
    x_originating_ip: str | None
    parse_notes: list[str] = field(default_factory=list)
    recipients: list[Address] = field(default_factory=list)   # To, Cc, Delivered-To
    raw_headers: dict[str, list[str]] = field(default_factory=dict)  # lowercase name -> values
    body: BodyInfo | None = None                              # None = body not inspected


# ---------- helpers ----------

def domain_of(address: str | None) -> str | None:
    if not address or "@" not in address:
        return None
    return address.rsplit("@", 1)[1].strip().strip("<>").rstrip(".").lower() or None


def _addresses(values: list[str] | None) -> list[Address]:
    if not values:
        return []
    out = []
    for name, addr in getaddresses([str(v) for v in values]):
        if addr:
            out.append(Address(display_name=name.strip(), address=addr.lower(), domain=domain_of(addr)))
    return out


def _first_address(msg: EmailMessage, header: str) -> Address | None:
    found = _addresses(msg.get_all(header))
    return found[0] if found else None


_METHOD_RE = re.compile(r"^\s*([a-z][a-z0-9-]*)\s*=\s*([a-z]+)", re.IGNORECASE)
_PROP_RE = re.compile(r"\b([a-z]+\.[a-z-]+)\s*=\s*([^\s;()]+)", re.IGNORECASE)
_POLICY_RE = re.compile(r"\bp=([a-z]+)", re.IGNORECASE)


def parse_authentication_results(values: list[str]) -> list[AuthResult]:
    """Parse Authentication-Results headers (RFC 8601). Topmost header is index 0."""
    results = []
    for idx, value in enumerate(values):
        text = " ".join(str(value).split())
        parts = [p.strip() for p in text.split(";")]
        authserv_id = parts[0].split()[0] if parts and parts[0] else None
        for part in parts[1:]:
            m = _METHOD_RE.match(part)
            if not m:
                continue
            # Some servers (Gmail, for one) wrap values in quotes: smtp.mailfrom="a@b.example"
            props = {k.lower(): v.strip('"').strip("<>") for k, v in _PROP_RE.findall(part)}
            pol = None
            if m.group(1).lower() == "dmarc" and (pm := _POLICY_RE.search(part)):
                pol = pm.group(1).lower()
            results.append(AuthResult(
                method=m.group(1).lower(),
                result=m.group(2).lower(),
                authserv_id=authserv_id,
                header_index=idx,
                properties=props,
                policy=pol,
            ))
    return results


_CLIENT_IP_RE = re.compile(r"client-ip=([0-9A-Fa-f:.]+)")


def parse_received_spf(values: list[str]) -> list[ReceivedSPF]:
    out = []
    for value in values:
        text = " ".join(str(value).split())
        result = text.split()[0].lower() if text else "none"
        m = _CLIENT_IP_RE.search(text)
        out.append(ReceivedSPF(result=result, client_ip=m.group(1) if m else None))
    return out


def _message_id_domain(message_id: str | None) -> str | None:
    if not message_id or "@" not in message_id:
        return None
    return message_id.strip().strip("<>").rsplit("@", 1)[1].rstrip(".").lower() or None


def _raw_headers(msg: EmailMessage) -> dict[str, list[str]]:
    """Every header as plain unfolded text, keyed by lowercase name."""
    out: dict[str, list[str]] = {}
    for name, value in msg.raw_items():
        try:
            text = str(value)
        except Exception:  # a malformed header shouldn't stop analysis
            continue
        out.setdefault(name.lower(), []).append(" ".join(text.split()))
    return out


# ---------- public API ----------

def parse_bytes(data: bytes, source: str = "<bytes>", inspect_body: bool = False) -> ParsedHeaders:
    """Parse headers. With inspect_body=True, also extract link domains and addresses
    from the text parts (see body.py for the safety model)."""
    msg: EmailMessage = BytesParser(policy=policy.default).parsebytes(data, headersonly=True)
    notes = [f"parser defect: {type(d).__name__}" for d in msg.defects]

    def all_str(name: str) -> list[str]:
        return [str(v) for v in (msg.get_all(name) or [])]

    date = None
    if msg["Date"]:
        try:
            date = parsedate_to_datetime(str(msg["Date"]))
            if date.tzinfo is None:
                date = date.replace(tzinfo=timezone.utc)
            date = date.astimezone(timezone.utc)
        except (TypeError, ValueError):
            notes.append(f"unparseable Date header: {msg['Date']}")

    message_id = str(msg["Message-ID"]).strip() if msg["Message-ID"] else None
    x_orig = str(msg["X-Originating-IP"]).strip().strip("[]") if msg["X-Originating-IP"] else None

    return ParsedHeaders(
        source=source,
        subject=str(msg["Subject"]) if msg["Subject"] else None,
        date=date,
        from_=_first_address(msg, "From"),
        reply_to=_addresses(msg.get_all("Reply-To")),
        return_path=_first_address(msg, "Return-Path"),
        sender=_first_address(msg, "Sender"),
        message_id=message_id,
        message_id_domain=_message_id_domain(message_id),
        auth_results=parse_authentication_results(all_str("Authentication-Results")),
        received_spf=parse_received_spf(all_str("Received-SPF")),
        hops=parse_chain(all_str("Received")),
        x_originating_ip=x_orig,
        parse_notes=notes,
        raw_headers=_raw_headers(msg),
        recipients=_addresses((msg.get_all("To") or []) + (msg.get_all("Cc") or [])
                              + (msg.get_all("Delivered-To") or [])),
        body=extract(data) if inspect_body else None,
    )


def parse_file(path: str | Path, inspect_body: bool = False) -> ParsedHeaders:
    path = Path(path)
    return parse_bytes(path.read_bytes(), source=path.name, inspect_body=inspect_body)
