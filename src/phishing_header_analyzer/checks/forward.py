"""Findings that explain how a forwarded message was handled."""

from __future__ import annotations

from ..config import Config
from ..findings import Finding
from ..parser import ParsedHeaders

CATEGORY = "forward"


def run(parsed: ParsedHeaders, config: Config) -> list[Finding]:
    ctx = parsed.forward
    if ctx is None:
        return []

    if ctx.kind == "attached":
        detail = ("The message was forwarded as an attachment, so the original arrived intact with "
                  "its full headers. This report analyzes the original, not the forward.")
        if ctx.other_attached:
            detail += (f" {ctx.other_attached} more attached email(s) were not analyzed; "
                       "save each one and run it separately.")
        return [Finding(
            "FORWARD-ATTACHED", CATEGORY, "info", 0, "Analyzed the attached original",
            detail,
            {"forwarded_by": ctx.forwarded_by, "forward_subject": ctx.wrapper_subject,
             "nesting_depth": ctx.depth, "other_attached": ctx.other_attached},
        )]

    if ctx.kind == "inline":
        return [Finding(
            "FORWARD-INLINE", CATEGORY, "info", 0,
            "Forwarded inline: the original's headers were lost",
            "When a message is forwarded inline, the forwarding client keeps only a short text "
            "summary of the original (sender, subject, date). Its authentication results and "
            "delivery path are gone, so SPF, DKIM, DMARC, and Received checks could not run. "
            "The sender, display name, and links were still checked.",
            {"forwarded_by": ctx.forwarded_by, "original_date_as_written": ctx.original_date_text,
             "original_message_id_domain": ctx.references_domain or None,
             "times_forwarded": ctx.depth},
        )]

    return [Finding(
        "FORWARD-SUSPECTED", CATEGORY, "info", 0,
        "This looks like a forward; only the forwarder's headers were checked",
        "The subject marks this as a forward. Without body inspection the tool can't find the "
        "original sender, so these results describe the person who forwarded it.",
        {"forwarded_by": ctx.forwarded_by, "subject": ctx.wrapper_subject},
    )]
