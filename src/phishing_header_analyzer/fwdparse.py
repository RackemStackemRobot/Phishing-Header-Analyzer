"""Recognize forwarded mail.

An INLINE forward copies the original's body into a new message and keeps only a
short text summary (From, Date, Subject, To). Every header the authentication
and delivery-path checks rely on is gone, and no tool can recover it. What
survives is the original sender, subject, and links, and those can still be checked.

This module has no dependencies on the rest of the package so the body extractor
and the parser can both use it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Lines that open a forwarded block, by client.
_MARKERS = re.compile(
    r"^\s*(?:"
    r"-{5,}\s*Forwarded message\s*-{5,}"          # Gmail
    r"|-{5,}\s*Forwarded Message\s*-{5,}"         # Thunderbird
    r"|-{3,}\s*Original Message\s*-{3,}"          # Outlook
    r"|Begin forwarded message:"                  # Apple Mail
    r"|_{10,}"                                    # Outlook separator before From:/Sent:
    r")\s*$",
    re.IGNORECASE | re.MULTILINE,
)
# Markers only a forward produces. Outlook's "Original Message" line and underscore
# separator also head quoted replies, so on their own they don't make a message a forward.
_FORWARD_ONLY = re.compile(r"forwarded message|begin forwarded message", re.IGNORECASE)
_FIELD = re.compile(r"^\s*>?\s*(From|Date|Sent|Subject|To|Cc|Reply-To)\s*:\s*(.*)$", re.IGNORECASE)
_ANGLE = re.compile(r"^(.*?)<\s*([^<>\s]+@[^<>\s]+?)\s*>")
_BARE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_FWD_SUBJECT = re.compile(r"^\s*(?:(?:fwd?|fw)\s*:\s*)+", re.IGNORECASE)
_MSGID = re.compile(r"<([^<>\s]+@[^<>\s]+)>")


@dataclass
class InlineForward:
    from_name: str = ""
    from_address: str = ""
    subject: str = ""
    date_text: str = ""          # as written by the forwarding client; formats vary
    to: list[str] = field(default_factory=list)
    reply_to: str = ""
    depth: int = 1               # how many forward blocks were stacked
    explicit: bool = False       # a forward-only marker was present, not just a reply separator


@dataclass
class ForwardContext:
    kind: str                    # "attached", "inline", or "suspected"
    forwarded_by: str = ""       # address of the person who forwarded it
    wrapper_subject: str = ""
    wrapper_date: str = ""
    original_date_text: str = ""
    references_domain: str = ""  # domain of the original Message-ID, from References
    depth: int = 1
    other_attached: int = 0


def parse_address(value: str) -> tuple[str, str]:
    """(display name, address) from a forward-block line. Handles "Name <a@b>",
    unquoted "Last, First <a@b>", Outlook's "Name [mailto:a@b]", and bare addresses."""
    value = value.strip()
    # Outlook's HTML-to-text turns links into "a@b<mailto:a@b>"; keep one copy of the address.
    value = re.sub(r"<\s*mailto:[^>]*>", "", value, flags=re.IGNORECASE)
    value = re.sub(r"\[mailto:([^\]]+)\]", r"<\1>", value)
    value = re.sub(r"\bmailto:", "", value, flags=re.IGNORECASE)
    m = _ANGLE.search(value)
    if m:
        name = m.group(1).strip().strip('"').strip()
        return name, m.group(2).strip().lower()
    m = _BARE.search(value)
    return ("", m.group(0).lower()) if m else ("", "")


def _block(lines: list[str]) -> InlineForward | None:
    """Parse the header lines that follow a forward marker."""
    fields: dict[str, str] = {}
    last = None
    started = False
    for line in lines:
        if not line.strip():
            if started:
                break
            continue            # Apple Mail and others leave a blank line after the marker
        m = _FIELD.match(line)
        if m:
            key = m.group(1).lower()
            key = "date" if key == "sent" else key
            fields[key] = " ".join(m.group(2).split())   # also folds odd spaces like U+202F
            last, started = key, True
        elif started and last:
            # Wrapped continuation, e.g. Gmail splitting "<" and the address across lines.
            sep = "" if fields[last].endswith("<") else " "
            fields[last] = f"{fields[last]}{sep}{' '.join(line.split())}"
        else:
            break
    if "from" not in fields:
        return None
    name, address = parse_address(fields["from"])
    if not address:
        return None
    return InlineForward(
        from_name=name, from_address=address,
        subject=fields.get("subject", ""), date_text=fields.get("date", ""),
        to=[a for _, a in (parse_address(p) for p in re.split(r",(?![^<]*>)", fields.get("to", ""))) if a],
        reply_to=parse_address(fields.get("reply-to", ""))[1],
    )


def parse_inline_forward(text: str) -> InlineForward | None:
    """The innermost forwarded block in a message body, or None."""
    if not text:
        return None
    text = text.replace("\r\n", "\n")
    found: list[InlineForward] = []
    explicit = False
    for m in _MARKERS.finditer(text):
        fwd = _block(text[m.end():].split("\n")[1:60])
        if fwd:
            found.append(fwd)
            explicit = explicit or bool(_FORWARD_ONLY.search(m.group(0)))
    if not found:
        return None
    innermost = found[-1]
    innermost.depth = len(found)
    innermost.explicit = explicit
    return innermost



def looks_forwarded(subject: str | None) -> bool:
    return bool(subject and _FWD_SUBJECT.match(subject))


def references_root_domain(references: str | None) -> str:
    """Domain of the first Message-ID in a References header: the start of the thread,
    which for a forward is normally the original message."""
    if not references:
        return ""
    m = _MSGID.search(references)
    return m.group(1).rsplit("@", 1)[1].lower().rstrip(".") if m else ""
