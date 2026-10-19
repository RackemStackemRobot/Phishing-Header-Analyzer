"""Opt-in body inspection: link domains and email addresses from text parts.

Safety model:
  * Only text/plain and text/html parts are read. Attachments are skipped.
  * HTML is tokenized with the standard library parser. Nothing is rendered,
    no scripts run, no images load, and no link is ever visited. This module
    imports no networking code.
  * Only link DOMAINS are kept, never full URLs. Phishing URLs often carry
    per-recipient tracking tokens; leaving them out of reports means nobody can
    click one by accident and confirm the target to the attacker.
  * Decoded text is capped so a huge or malformed message can't bog things down.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser
from urllib.parse import urlsplit

from .util import classify_ip, org_domain

MAX_BODY_CHARS = 5_000_000
MAX_PARTS = 50

_URL_RE = re.compile(r"\bhttps?://[^\s<>\"'()\[\]{}]+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_DOMAIN_TOKEN_RE = re.compile(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b")


@dataclass
class LinkMismatch:
    shown: str      # domain the reader sees in the link text
    actual: str     # domain the link really goes to


@dataclass
class BodyInfo:
    link_domains: dict[str, int] = field(default_factory=dict)   # host -> number of links
    addresses: list[str] = field(default_factory=list)            # unique, lowercase
    mismatches: list[LinkMismatch] = field(default_factory=list)
    text_parts: int = 0
    html_parts: int = 0
    skipped_attachments: int = 0
    truncated: bool = False
    notes: list[str] = field(default_factory=list)


def host_of(url: str) -> str | None:
    """Hostname of an http(s) URL, normalized to lowercase ASCII (punycode). Pure string parsing."""
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https"):
        return None
    try:
        host = parts.hostname
    except ValueError:
        return None
    if not host:
        return None
    host = host.rstrip(".").lower()
    if classify_ip(host):
        return host
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


class _LinkCollector(HTMLParser):
    """Collects link targets, visible text, and anchor text. Never acts on anything."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hrefs: list[str] = []
        self.mailtos: list[str] = []
        self.text: list[str] = []          # all visible text (for addresses)
        self.free_text: list[str] = []     # visible text outside links (for bare URLs)
        self.anchors: list[tuple[str, str]] = []   # (href, visible text)
        self._skip_depth = 0
        self._anchor_href: str | None = None
        self._anchor_text: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in ("script", "style"):
            self._skip_depth += 1
        target = a.get("href") if tag in ("a", "area") else a.get("action") if tag == "form" else None
        if target:
            if target.lower().startswith("mailto:"):
                self.mailtos.append(target[7:].split("?")[0])
            else:
                self.hrefs.append(target)
        if tag == "a":
            self._anchor_href = a.get("href")
            self._anchor_text = []

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip_depth:
            self._skip_depth -= 1
        if tag == "a" and self._anchor_href is not None:
            self.anchors.append((self._anchor_href, " ".join(self._anchor_text)))
            self._anchor_href = None

    def handle_data(self, data):
        if self._skip_depth:
            return
        self.text.append(data)
        if self._anchor_href is not None:
            self._anchor_text.append(data)   # a label, not a destination
        else:
            self.free_text.append(data)


def _add_link(info: BodyInfo, url: str):
    host = host_of(url)
    if host:
        info.link_domains[host] = info.link_domains.get(host, 0) + 1


def _add_addresses(found: set[str], text: str):
    for addr in _EMAIL_RE.findall(text):
        found.add(addr.lower().strip("."))


def _check_anchor(info: BodyInfo, href: str, text: str):
    """Flag links whose visible text names a different site than the real target."""
    actual = host_of(href)
    if not actual:
        return
    for token in _DOMAIN_TOKEN_RE.findall(text):
        shown = token.lower()
        if "@" in text and f"@{shown}" in text.lower():
            continue  # an email address in the text, not a link label
        if org_domain(shown) != org_domain(actual):
            info.mismatches.append(LinkMismatch(shown=shown, actual=actual))
            return


def extract(data: bytes) -> BodyInfo:
    info = BodyInfo()
    try:
        msg = BytesParser(policy=policy.default).parsebytes(data)
    except Exception as exc:  # malformed MIME should never crash header analysis
        info.notes.append(f"body could not be parsed: {type(exc).__name__}")
        return info

    budget = MAX_BODY_CHARS
    addresses: set[str] = set()
    parts_seen = 0

    for part in msg.walk():
        if part.is_multipart():
            continue
        parts_seen += 1
        if parts_seen > MAX_PARTS:
            info.truncated = True
            info.notes.append(f"stopped after {MAX_PARTS} parts")
            break
        if part.get_content_disposition() == "attachment" or part.get_filename():
            info.skipped_attachments += 1
            continue
        ctype = part.get_content_type()
        if ctype not in ("text/plain", "text/html"):
            continue
        try:
            text = part.get_content()
        except Exception as exc:
            info.notes.append(f"a {ctype} part could not be decoded: {type(exc).__name__}")
            continue
        if not isinstance(text, str):
            continue
        if len(text) > budget:
            text = text[:budget]
            info.truncated = True
        budget -= len(text)

        if ctype == "text/plain":
            info.text_parts += 1
            for url in _URL_RE.findall(text):
                _add_link(info, url)
            _add_addresses(addresses, text)
        else:
            info.html_parts += 1
            collector = _LinkCollector()
            try:
                collector.feed(text)
                collector.close()
            except Exception as exc:
                info.notes.append(f"HTML part partly unreadable: {type(exc).__name__}")
            for href in collector.hrefs:
                _add_link(info, href)
            for url in _URL_RE.findall(" ".join(collector.free_text)):
                _add_link(info, url)
            _add_addresses(addresses, " ".join(collector.text))
            for m in collector.mailtos:
                _add_addresses(addresses, m)
            for href, label in collector.anchors:
                _check_anchor(info, href, label)

        if budget <= 0:
            info.truncated = True
            break

    if info.truncated and not any("stopped" in n for n in info.notes):
        info.notes.append(f"body text capped at {MAX_BODY_CHARS:,} characters")
    info.addresses = sorted(addresses)
    return info
