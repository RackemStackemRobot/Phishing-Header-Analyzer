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

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

NOTES = [
    "DKIM signatures were not verified locally. Verdicts are those recorded by the receiving server.",
    "Headers added before your organization's mail gateway can be forged by the sender.",
    "The risk score supports analyst judgment. It is not a verdict on its own.",
]


# ---------- building ----------

def _addr(a: Address | None) -> dict | None:
    return asdict(a) if a else None


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


def defang(text: str) -> str:
    """contoso.example -> contoso[.]example, 203.0.113.5 -> 203[.]0[.]113[.]5, http -> hxxp."""
    text = _SCHEME_RE.sub(lambda m: "hxxp" + m.group(1) + "://", text)
    text = _IPV4_RE.sub(lambda m: m.group(0).replace(".", "[.]"), text)
    return _HOST_RE.sub(lambda m: m.group(0).replace(".", "[.]"), text)


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
    add(f"**Risk: {r['level'].upper()} ({r['score']}/100)**")
    add("")
    for reason in r["reasons"]:
        add(f"- {reason}")
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
