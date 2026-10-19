"""Decide which message to analyze when the input is a forward.

  * Forwarded as an attachment: the attached original has its full headers, so
    it becomes the message analyzed. Nested attachments are followed inward.
  * Forwarded inline (with body inspection on): the original's headers are gone.
    A partial original is rebuilt from the forward block (sender, subject, links)
    and marked headers_lost so authentication and delivery-path checks are skipped
    rather than reporting on data that no longer exists.
  * Looks forwarded, but body inspection is off: analyzed as-is, flagged as suspected.
"""

from __future__ import annotations

from .fwdparse import ForwardContext, looks_forwarded, references_root_domain
from .parser import Address, ParsedHeaders, domain_of, parse_bytes

MAX_DEPTH = 5


def _addr_text(a: Address | None) -> str:
    return a.address if a else ""


def resolve(parsed: ParsedHeaders) -> ParsedHeaders:
    """The message the report should be about, with forward context attached."""
    outer = parsed
    inspect_body = parsed.body is not None

    # Follow attached originals inward: a forward of a forward-as-attachment, and so on.
    current, depth = parsed, 0
    while current.attached_originals and depth < MAX_DEPTH:
        inner = parse_bytes(current.attached_originals[0],
                            source=f"{outer.source} (attached original)", inspect_body=inspect_body)
        depth += 1
        inner.forward = ForwardContext(
            kind="attached",
            forwarded_by=_addr_text(outer.from_),
            wrapper_subject=outer.subject or "",
            wrapper_date=outer.date.isoformat() if outer.date else "",
            depth=depth,
            other_attached=len(outer.attached_originals) - 1,
        )
        current = inner
    if depth:
        return current

    fwd = parsed.body.inline_forward if parsed.body else None
    if fwd:
        name, address = fwd.from_name, fwd.from_address
        recipients = list(parsed.recipients) + [
            Address(display_name="", address=a, domain=domain_of(a)) for a in fwd.to]
        refs = (parsed.raw_headers.get("references") or [""])[0]
        ref_domain = references_root_domain(refs)
        return ParsedHeaders(
            source=f"{parsed.source} (inline-forwarded original)",
            subject=fwd.subject or None,
            date=None,  # forwarding clients rewrite dates in non-standard formats
            from_=Address(display_name=name, address=address, domain=domain_of(address)),
            reply_to=([Address(display_name="", address=fwd.reply_to, domain=domain_of(fwd.reply_to))]
                      if fwd.reply_to else []),
            return_path=None,
            sender=None,
            message_id=None,
            message_id_domain=ref_domain or None,
            auth_results=[],
            received_spf=[],
            hops=[],
            x_originating_ip=None,
            parse_notes=[],
            recipients=recipients,
            raw_headers={},
            body=parsed.body,
            headers_lost=True,
            forward=ForwardContext(
                kind="inline",
                forwarded_by=_addr_text(parsed.from_),
                wrapper_subject=parsed.subject or "",
                wrapper_date=parsed.date.isoformat() if parsed.date else "",
                original_date_text=fwd.date_text,
                references_domain=ref_domain,
                depth=fwd.depth,
            ),
        )

    if parsed.body is None and looks_forwarded(parsed.subject):
        parsed.forward = ForwardContext(
            kind="suspected",
            forwarded_by=_addr_text(parsed.from_),
            wrapper_subject=parsed.subject or "",
        )
    return parsed
