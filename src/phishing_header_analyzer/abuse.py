"""Draft abuse reports (--abuse-reports DIR). This module drafts; it never sends.

For each party that can act on the message (the bulk mail service, each domain's
registrar, the sending network, the Anti-Phishing Working Group, and the platform
for platform notifications) it writes:

  NN-name.eml   A ready-to-send draft in the Abuse Reporting Format (ARF,
                RFC 5965): a human-readable explanation, a machine-readable
                feedback report, and the original message attached. Marked
                X-Unsent so Outlook opens it as a draft.
  NN-name.txt   The same text for pasting into webmail; attach original.eml.

plus original.eml and a README.txt explaining what to send where.

Drafts are written neutrally with a placeholder for the sender's name, so the
person sending them reviews and signs them. There is no code here that sends mail.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from email import message_from_bytes, policy
from email.message import Message
from email.mime.message import MIMEMessage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import format_datetime
from pathlib import Path

from . import __version__
from .parser import ParsedHeaders

APWG = ("Anti-Phishing Working Group", "reportphishing@apwg.org")

# Platforms that take phishing reports by email. Others are reported through the
# "Report" option on the group, file, or envelope itself. Verify before sending.
PLATFORM_REPORT_EMAILS = {
    "PayPal (invoices and money requests)": "phishing@paypal.com",
    "DocuSign": "spoof@docusign.com",
}


@dataclass
class Recipient:
    kind: str            # bulk-mail, registrar, network, apwg, platform
    name: str
    email: str           # empty for form-only platforms
    relation: str        # how this party relates to the message
    request: str         # what we ask them to do
    subjects: list[str] = field(default_factory=list)


@dataclass
class Draft:
    recipient: Recipient
    subject: str
    text: str
    eml: bytes


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:40] or "recipient"


def recipients(report: dict) -> list[Recipient]:
    out: list[Recipient] = []
    seen: set[str] = set()

    def add(r: Recipient):
        key = r.email or r.name
        if key in seen:
            for existing in out:   # same contact covering several domains: one report
                if (existing.email or existing.name) == key:
                    existing.subjects += [s for s in r.subjects if s not in existing.subjects]
            return
        seen.add(key)
        out.append(r)

    for f in report["findings"]:
        ev = f["evidence"]
        if f["check_id"] == "BULK-MAIL-SERVICE":
            add(Recipient("bulk-mail", ev["service"], ev["abuse_contact"],
                          "The message was sent through your service.",
                          "Please investigate and suspend the sending account responsible for this message."))
        if f["check_id"] == "PLATFORM-NOTIFICATION":
            name = ev["platform"]
            add(Recipient("platform", name, PLATFORM_REPORT_EMAILS.get(name, ""),
                          f"The message is a genuine {name} notification triggered by the account below.",
                          "Please review and remove the group, file, envelope, or account that "
                          "triggered this notification."))

    live = report.get("live") or {}
    for d in live.get("domains", []):
        if d.get("abuse_email"):
            add(Recipient("registrar", d["registrar"] or "Registrar", d["abuse_email"],
                          "The following domain(s), registered through you, were used in the message.",
                          "Please review the domain(s) for abuse under your terms of service and "
                          "suspend them if appropriate.", subjects=[d["domain"]]))
    for i in live.get("ips", []):
        if i.get("abuse_email"):
            add(Recipient("network", i["org"] or i["network"] or "Network operator", i["abuse_email"],
                          "The following IP address on your network was involved in the message.",
                          "Please investigate the server at this address.", subjects=[i["ip"]]))

    add(Recipient("apwg", APWG[0], APWG[1],
                  "Submitted for inclusion in phishing intelligence shared with the industry.",
                  "No action is requested beyond processing this report."))
    return out


def _indicators(report: dict) -> dict[str, list[str]]:
    s = report["summary"]
    domains, ips, accounts = [], [], []
    for a in [s["from"], s["return_path"], s["sender"], *s["reply_to"]]:
        if a and a.get("domain") and a["domain"] not in domains:
            domains.append(a["domain"])
    for d in (report["body"].get("link_domains") or []):
        if d["domain"] not in domains:
            (ips if re.fullmatch(r"[\d.:a-fA-F]+", d["domain"]) else domains).append(d["domain"])
    for f in report["findings"]:
        if f["check_id"] == "PLATFORM-ACCOUNTS":
            accounts += f["evidence"]["accounts"]
    live = report.get("live") or {}
    for i in live.get("ips", []):
        if i["ip"] not in ips:
            ips.append(i["ip"])
    return {"Domains": domains, "IP addresses": ips, "Accounts named in the message": accounts}


def _sending_ip(report: dict) -> str:
    """The public IP that handed the message to the recipient's mail server."""
    live = report.get("live") or {}
    if live.get("ips"):
        return live["ips"][0]["ip"]
    from .util import classify_ip
    for hop in reversed(report["received_chain"]):   # nearest the recipient first
        if classify_ip(hop.get("from_ip")) in ("public", "documentation"):
            return hop["from_ip"]
    return ""


def compose_text(report: dict, r: Recipient) -> tuple[str, str]:
    s = report["summary"]
    frm = s["from"]["address"] if s["from"] else "(unknown)"
    rp = s["return_path"]["address"] if s["return_path"] else ""
    subject = f"Abuse report: phishing or fraud email from {s['from']['domain'] if s['from'] else 'unknown sender'}"
    lost = report.get("headers_lost")

    lines = [f"To the {r.name} abuse team,", "",
             "This report concerns an email identified as phishing or fraud. " + r.relation]
    if lost:
        lines.append("The message is attached, but it was forwarded inline before it reached the reporter, "
                     "so the original's full headers are not available.")
    else:
        lines.append("The original message is attached with full headers.")
    if r.subjects:
        lines += ["", "Relevant to you:"] + [f"  {x}" for x in r.subjects]

    lines += ["", "Message summary", f"  Subject:      {s['subject'] or '-'}", f"  From:         {frm}"]
    if rp:
        lines.append(f"  Return-Path:  {rp}")
    date = s["date"] or ((report.get("forward") or {}).get("original_date_text") or "-")
    lines.append(f"  Date:         {date}")
    if s["message_id"]:
        lines.append(f"  Message-ID:   {s['message_id']}")
    if _sending_ip(report):
        lines.append(f"  Sending IP:   {_sending_ip(report)}")

    indicators = _indicators(report)
    if any(indicators.values()):
        lines += ["", "Indicators"]
        for label, values in indicators.items():
            if values:
                lines.append(f"  {label}: {', '.join(values)}")

    reasons = [f"  - {f['title']}" for f in report["findings"] if f["severity"] in ("high", "medium")]
    lines += ["", "Why it was flagged"]
    lines += reasons or ["  - The message content was assessed as fraudulent by the reporting party."]
    lines += ["  [Optional: add a sentence describing what the message asks the recipient to do.]",
              "", "Requested action", f"  {r.request}", "",
              "Indicators are listed as plain text. No links in the message were visited.",
              f"Prepared with phishing-header-analyzer {__version__}.", "",
              "[Your name]", "[Your contact information]", ""]
    return subject, "\n".join(lines)


def _feedback_report(report: dict, raw_msg: Message) -> Message:
    """The machine-readable part of an ARF report (RFC 5965)."""
    s = report["summary"]
    fields = ["Feedback-Type: fraud", f"User-Agent: phishing-header-analyzer/{__version__}", "Version: 1"]
    if s["return_path"]:
        fields.append(f"Original-Mail-From: <{s['return_path']['address']}>")
    chain = report["received_chain"]
    arrival = next((h["timestamp"] for h in reversed(chain) if h["timestamp"]), None)
    if arrival:
        from datetime import datetime
        fields.append(f"Arrival-Date: {format_datetime(datetime.fromisoformat(arrival))}")
    if _sending_ip(report):
        fields.append(f"Source-IP: {_sending_ip(report)}")
    for d in _indicators(report)["Domains"][:10]:
        fields.append(f"Reported-Domain: {d}")
    part = Message()
    part["Content-Type"] = "message/feedback-report"
    part.set_payload("\n".join(fields) + "\n")
    return part


def build_drafts(report: dict, primary: ParsedHeaders) -> list[Draft]:
    raw = primary.raw or b""
    drafts = []
    for r in recipients(report):
        subject, text = compose_text(report, r)
        outer = MIMEMultipart("report")
        outer.set_param("report-type", "feedback-report")
        outer["Subject"] = subject
        if r.email:
            outer["To"] = r.email
        outer["X-Unsent"] = "1"            # Outlook opens this as an editable draft
        outer.attach(MIMEText(text, "plain", "utf-8"))
        original = message_from_bytes(raw, policy=policy.compat32) if raw else Message()
        outer.attach(_feedback_report(report, original))
        outer.attach(MIMEMessage(original))
        drafts.append(Draft(r, subject, text, outer.as_bytes()))
    return drafts


def write_drafts(report: dict, primary: ParsedHeaders, directory: str | Path) -> list[Path]:
    out = Path(directory)
    out.mkdir(parents=True, exist_ok=True)
    written = []
    original = out / "original.eml"
    original.write_bytes(primary.raw or b"")
    written.append(original)

    index = ["ABUSE REPORT DRAFTS", "",
             "These are drafts. Nothing has been sent. Review each one, replace the [Your name] and",
             "[Your contact information] placeholders, and verify each contact on the organization's",
             "own website before sending.", "",
             "How to send:",
             "  Outlook: open the .eml file; it opens as a draft with the original attached. Click Send.",
             "  Thunderbird: open the .eml, then use Edit As New Message.",
             "  Gmail or other webmail: paste the .txt text into a new message, attach original.eml,",
             "  and copy the subject line.", ""]
    if report.get("headers_lost"):
        index += ["Note: this message was forwarded inline, so original.eml is the forward, not the",
                  "original with full headers. If possible, get the original as an attachment and",
                  "re-run before reporting.", ""]

    for n, d in enumerate(build_drafts(report, primary), start=1):
        stem = f"{n:02d}-{_slug(d.recipient.kind + '-' + d.recipient.name)}"
        if d.recipient.email:
            (out / f"{stem}.eml").write_bytes(d.eml)
            (out / f"{stem}.txt").write_text(f"To: {d.recipient.email}\nSubject: {d.subject}\n\n{d.text}",
                                             encoding="utf-8")
            written += [out / f"{stem}.eml", out / f"{stem}.txt"]
            index.append(f"{stem}: {d.recipient.name} <{d.recipient.email}>")
        else:
            (out / f"{stem}.txt").write_text(
                f"{d.recipient.name} takes reports through the Report option on the item itself "
                "(the group, shared file, envelope, or invoice), not by email.\n"
                "Go to the platform's site directly (type the address yourself rather than using the "
                "email's links), find the item, and use Report. Paste this text if a description is "
                "requested:\n\n"
                f"{d.text}", encoding="utf-8")
            written.append(out / f"{stem}.txt")
            index.append(f"{stem}: {d.recipient.name} (report through the platform's Report option)")
        index.append(f"    {d.recipient.relation}")

    readme = out / "README.txt"
    readme.write_text("\n".join(index) + "\n", encoding="utf-8")
    written.append(readme)
    return written
