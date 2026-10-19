"""Build the analysis report and render it as JSON or Markdown.

JSON is raw and machine-readable. Markdown is for pasting into tickets: values
that came from the message are escaped (the sender wrote them) and domains,
addresses, and IPs are defanged so ticketing systems don't make them clickable.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict
from datetime import datetime, timezone

from . import __version__
from .checks import run_all
from .checks.auth import trusted_results
from .config import Config
from .findings import Finding
from .parser import Address, ParsedHeaders
from .scoring import score
from .util import decode_domain

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

HEADLINE_NOTE = "Authentication confirms who delivered the message, not whether its content is safe."

# Concrete next steps, keyed by check ID. Kept here so actions can be tuned in
# one place without touching the checks. Several checks can share one action.
_SPOOFED = ("Treat the From address as spoofed. Quarantine the message and search mail "
            "logs for other messages from the same sending IP or Return-Path.")
_LOOKALIKE = ("Block the domain at the mail gateway and web proxy, and search mail logs "
              "for other messages from it.")
_DISPLAY = ("Judge the actual sending address, not the display name. Confirm with the "
            "real organization through a contact you already have.")
ACTIONS = {
    "PLATFORM-NOTIFICATION": (
        "Find the account that triggered this notification (the inviter, sharer, or invoice "
        "sender named in the message body) and verify it through a channel you already trust. "
        "Don't join, open, sign, or pay until verified. If it's malicious, report the group, "
        "file, or account to the platform as well as blocking it locally."),
    "DMARC-FAIL": _SPOOFED,
    "SPF-FAIL": _SPOOFED,
    "DKIM-FAIL": _SPOOFED,
    "LOOKALIKE-HOMOGLYPH": _LOOKALIKE,
    "LOOKALIKE-NEAR-MISS": _LOOKALIKE,
    "LOOKALIKE-CONTAINS-BRAND": _LOOKALIKE,
    "REPLYTO-MISMATCH": (
        "Don't reply. Contact the apparent sender through a known phone number or address, "
        "especially if the message asks to change payment or banking details."),
    "DISPLAY-NAME-ADDRESS": _DISPLAY,
    "DISPLAY-NAME-BRAND": _DISPLAY,
    "HOP-OUT-OF-ORDER": (
        "Treat Received hops below your gateway as forged. Trust only your gateway's record "
        "of the sending IP."),
    "BOUNDARY-IP-NONROUTABLE": (
        "Check your gateway's connection logs for the true source of this message."),
    "AUTH-UNTRUSTED-ONLY": (
        "Set trusted_authserv_ids in your config to your inbound mail server, then re-run."),
    "PLATFORM-ACCOUNTS": (
        "Verify these accounts named in the notification through a channel you already trust. "
        "Don't join, open, sign, or pay until verified. If they're malicious, report them to "
        "the platform as well as blocking them locally:"),
    "LINK-OFF-PLATFORM": (
        "Block these link domains at the web proxy and mail gateway, and search mail logs for "
        "other messages linking to them:"),
    "LINK-TEXT-MISMATCH": (
        "Treat the message as phishing: its link text disguises where the links go. Block the "
        "real destinations:"),
    "LINK-IP-LITERAL": "Block these IP addresses at the web proxy:",
    "LINK-LOOKALIKE-HOMOGLYPH": _LOOKALIKE,
    "LINK-LOOKALIKE-NEAR-MISS": _LOOKALIKE,
    "LINK-LOOKALIKE-CONTAINS-BRAND": _LOOKALIKE,
}

# Pull the specific indicators an action applies to out of a finding's evidence.
_SUBJECTS = {
    "PLATFORM-ACCOUNTS": lambda ev: ev.get("accounts", []),
    "LINK-OFF-PLATFORM": lambda ev: ev.get("domains", []),
    "LINK-TEXT-MISMATCH": lambda ev: [link["goes_to"] for link in ev.get("links", [])],
    "LINK-IP-LITERAL": lambda ev: ev.get("ips", []),
}


def recommended_actions(findings: list[Finding]) -> list[dict]:
    """One entry per distinct action, in finding order, listing which checks call for it
    and the specific accounts, domains, or IPs it applies to."""
    ids = {f.check_id for f in findings}
    actions: dict[str, dict] = {}
    for f in findings:
        check_id = f.check_id
        # Once the body has named the accounts, the generic "find the account" step is redundant.
        if check_id == "PLATFORM-NOTIFICATION" and "PLATFORM-ACCOUNTS" in ids:
            continue
        text = ACTIONS.get(check_id)
        if not text:
            continue
        entry = actions.setdefault(text, {"action": text, "because": [], "subjects": []})
        entry["because"].append(check_id)
        for s in _SUBJECTS.get(check_id, lambda ev: [])(f.evidence):
            if s not in entry["subjects"]:
                entry["subjects"].append(s)
    if "PLATFORM-ACCOUNTS" in ids and "PLATFORM-NOTIFICATION" in ids:
        actions[ACTIONS["PLATFORM-ACCOUNTS"]]["because"].insert(0, "PLATFORM-NOTIFICATION")
    return list(actions.values())


NOTES = [
    "DKIM signatures were not verified locally. Verdicts are those recorded by the receiving server.",
    "Headers added before your organization's mail gateway can be forged by the sender.",
    "The risk score supports analyst judgment. It is not a verdict on its own.",
]


# ---------- building ----------

def _addr(a: Address | None) -> dict | None:
    return asdict(a) if a else None


def _body_section(parsed: ParsedHeaders) -> dict:
    """Body summary for the report. Link domains only: full URLs and the full list of
    addresses are deliberately left out (accounts that matter appear in findings)."""
    b = parsed.body
    if b is None:
        return {"inspected": False}
    return {
        "inspected": True,
        "link_domains": [{"domain": d, "displays_as": decode_domain(d), "links": n}
                         for d, n in sorted(b.link_domains.items(), key=lambda kv: (-kv[1], kv[0]))],
        "text_parts": b.text_parts,
        "html_parts": b.html_parts,
        "skipped_attachments": b.skipped_attachments,
        "truncated": b.truncated,
    }


def build_report(parsed: ParsedHeaders, config: Config | None = None,
                 analyzed_at: datetime | None = None) -> dict:
    """Run every check and assemble the full report as a plain dict.

    analyzed_at is optional so the same input can produce byte-identical output.
    """
    config = config or Config()
    findings = sorted(run_all(parsed, config),
                      key=lambda f: (SEVERITY_ORDER[f.severity], -f.points, f.check_id))
    risk = score(findings)
    trusted, basis = trusted_results(parsed, config)

    return {
        "tool": {"name": "phishing-header-analyzer", "version": __version__},
        "source": parsed.source,
        "analyzed_at": analyzed_at.astimezone(timezone.utc).isoformat() if analyzed_at else None,
        "risk": asdict(risk),
        "headline_note": HEADLINE_NOTE,
        "recommended_actions": recommended_actions(findings),
        "summary": {
            "subject": parsed.subject,
            "date": parsed.date.isoformat() if parsed.date else None,
            "from": _addr(parsed.from_),
            "reply_to": [_addr(a) for a in parsed.reply_to],
            "return_path": _addr(parsed.return_path),
            "sender": _addr(parsed.sender),
            "message_id": parsed.message_id,
            "x_originating_ip": parsed.x_originating_ip,
        },
        "authentication": {
            "trust_basis": basis,
            "trusted_results": [asdict(r) for r in trusted],
            "all_results": [asdict(r) for r in parsed.auth_results],
            "received_spf": [asdict(r) for r in parsed.received_spf],
            "dkim_verified_locally": False,
        },
        "received_chain": [
            {**asdict(h), "timestamp": h.timestamp.isoformat() if h.timestamp else None}
            for h in parsed.hops
        ],
        "body": _body_section(parsed),
        "findings": [asdict(f) for f in findings],
        "parse_notes": parsed.parse_notes,
        "notes": NOTES,
    }


def analyze(parsed: ParsedHeaders, config: Config | None = None,
            analyzed_at: datetime | None = None) -> tuple[dict, list[Finding]]:
    """Convenience wrapper returning the report and Finding objects."""
    report = build_report(parsed, config, analyzed_at)
    return report, [Finding(**f) for f in report["findings"]]


# ---------- JSON ----------

def to_json(report: dict) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False) + "\n"


# ---------- Markdown ----------

_HOST_RE = re.compile(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z][A-Za-z0-9-]+\b")
_IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_SCHEME_RE = re.compile(r"\bhttp(s?)://", re.IGNORECASE)
_MD_SPECIAL = re.compile(r"([\\`*\[\]<>|#])")


_DEFANG_RE = re.compile(
    r"(?P<local>[A-Za-z0-9._%+-]+)@(?P<maildomain>(?:[A-Za-z0-9-]+\.)+[A-Za-z][A-Za-z0-9-]+)"
    rf"|(?P<ip>{_IPV4_RE.pattern})"
    rf"|(?P<host>{_HOST_RE.pattern})"
)


def _defang_match(m: re.Match) -> str:
    if m.group("local") is not None:
        # Only the domain half of an address is linkable; keep the username copyable.
        return f"{m.group('local')}@{m.group('maildomain').replace('.', '[.]')}"
    return m.group(0).replace(".", "[.]")


def defang(text: str) -> str:
    """contoso.example -> contoso[.]example, 203.0.113.5 -> 203[.]0[.]113[.]5, http -> hxxp.
    Email addresses keep their username intact: first.last@contoso[.]example."""
    text = _SCHEME_RE.sub(lambda m: "hxxp" + m.group(1) + "://", text)
    return _DEFANG_RE.sub(_defang_match, text)


def _escape(value, do_defang: bool) -> str:
    text = " ".join(str(value).split())        # no line breaks inside a cell
    text = _MD_SPECIAL.sub(r"\\\1", text)      # neutralize Markdown/HTML
    return defang(text) if do_defang else text


def _flatten(value, do_defang: bool) -> str:
    """Render nested evidence readably. Keys are ours (escaped only); values may be attacker-written."""
    if isinstance(value, dict):
        return "; ".join(f"{_escape(k, False)}: {_flatten(v, do_defang)}"
                         for k, v in value.items() if v not in (None, "", [], {}))
    if isinstance(value, (list, tuple)):
        return ", ".join(f"({_flatten(v, do_defang)})" if isinstance(v, dict) else _flatten(v, do_defang)
                         for v in value)
    return _escape(value, do_defang)


def _cell(value, do_defang: bool = True) -> str:
    """Make an untrusted value safe for a Markdown table cell."""
    if value in (None, "", [], {}):
        return "-"
    return _flatten(value, do_defang) or "-"


def _fmt_addr(a: dict | None) -> str | None:
    if not a:
        return None
    return f'"{a["display_name"]}" {a["address"]}' if a["display_name"] else a["address"]


def _delay(seconds) -> str:
    if seconds is None:
        return "-"
    sign = "-" if seconds < 0 else "+"
    s = abs(int(seconds))
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    return f"{sign}{h}h{m:02d}m{sec:02d}s" if h else f"{sign}{m}m{sec:02d}s"


def to_markdown(report: dict, do_defang: bool = True) -> str:
    c = lambda v: _cell(v, do_defang)  # noqa: E731
    r, s, a = report["risk"], report["summary"], report["authentication"]
    lines: list[str] = []
    add = lines.append

    add(f"# Phishing Header Analysis: {_cell(report['source'], False)}")
    add("")
    add(f"**Header risk: {r['level'].upper()} ({r['score']}/100)**")
    add("")
    add(f"_{report['headline_note']}_")
    add("")
    for reason in r["reasons"]:
        add(f"- {reason}")
    add("")

    if report["recommended_actions"]:
        add("## Recommended Actions")
        add("")
        for i, item in enumerate(report["recommended_actions"], start=1):
            add(f"{i}. {item['action']} _({', '.join(item['because'])})_")
            for subject in item.get("subjects", []):
                add(f"   - {c(subject)}")   # attacker-derived: escaped and defanged
        add("")

    add("## Message")
    add("")
    add("| Field | Value |")
    add("| --- | --- |")
    add(f"| Subject | {c(s['subject'])} |")
    add(f"| Date | {c(s['date'])} |")
    add(f"| From | {c(_fmt_addr(s['from']))} |")
    add(f"| Reply-To | {c([_fmt_addr(x) for x in s['reply_to']])} |")
    add(f"| Return-Path | {c(_fmt_addr(s['return_path']))} |")
    if s["sender"]:
        add(f"| Sender | {c(_fmt_addr(s['sender']))} |")
    add(f"| Message-ID | {c(s['message_id'])} |")
    if s["x_originating_ip"]:
        add(f"| X-Originating-IP | {c(s['x_originating_ip'])} |")
    add("")

    add("## Findings")
    add("")
    if report["findings"]:
        add("| Severity | Points | Check | Finding | Evidence |")
        add("| --- | --- | --- | --- | --- |")
        for f in report["findings"]:
            add(f"| {f['severity']} | {f['points']} | `{f['check_id']}` | {c(f['title'])} | {c(f['evidence'])} |")
        add("")
        add("### Why these matter")
        add("")
        for f in report["findings"]:
            add(f"- **{f['check_id']}**: {_cell(f['detail'], False)}")
    else:
        add("No findings.")
    add("")

    add("## Authentication")
    add("")
    add(f"Trust basis: {a['trust_basis']}.")
    add("")
    if a["trusted_results"]:
        add("| Method | Result | Recorded by | Details |")
        add("| --- | --- | --- | --- |")
        for res in a["trusted_results"]:
            details = dict(res["properties"])
            if res["policy"]:
                details["policy"] = res["policy"]
            add(f"| {res['method']} | {res['result']} | {c(res['authserv_id'])} | {c(details)} |")
    else:
        add("No trusted authentication results.")
    add("")

    add("## Message Body")
    add("")
    body = report["body"]
    if not body["inspected"]:
        add("Not inspected (headers only). To check link domains and platform accounts, "
            "re-run and answer `y` at the prompt, or pass `--inspect-body`.")
    else:
        add(f"Inspected {body['text_parts']} text and {body['html_parts']} HTML part(s); "
            f"{body['skipped_attachments']} attachment(s) skipped, not opened. "
            "Link domains only; no link was visited.")
        add("")
        if body["link_domains"]:
            add("| Link domain | Links |")
            add("| --- | --- |")
            for d in body["link_domains"]:
                shown = d["domain"] if d["displays_as"] == d["domain"] else f"{d['domain']} ({d['displays_as']})"
                add(f"| {c(shown)} | {d['links']} |")
        else:
            add("No links found.")
    add("")

    add("## Received Chain (origin first)")
    add("")
    if report["received_chain"]:
        add("| Hop | From | IP | By | Protocol | Time (UTC) | Delay |")
        add("| --- | --- | --- | --- | --- | --- | --- |")
        for h in report["received_chain"]:
            add(f"| {h['index']} | {c(h['from_host'])} | {c(h['from_ip'])} | {c(h['by_host'])} | "
                f"{c(h['protocol'])} | {c(h['timestamp'])} | {_delay(h['delay_seconds'])} |")
    else:
        add("No Received headers.")
    add("")

    if report["parse_notes"]:
        add("## Parse Notes")
        add("")
        for n in report["parse_notes"]:
            add(f"- {c(n)}")
        add("")

    add("## Notes")
    add("")
    for n in report["notes"]:
        add(f"- {n}")
    add("")
    tool = report["tool"]
    stamp = f" at {report['analyzed_at']}" if report["analyzed_at"] else ""
    add(f"_Generated by {tool['name']} {tool['version']}{stamp}._")
    add("")
    return "\n".join(lines)
