"""Command-line entry point.

Exit codes:
  0  analysis completed (and risk below --fail-on, if given)
  1  input or config error
  2  bad command-line usage (argparse)
  3  risk level met or exceeded --fail-on
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO

from . import __version__
from .config import Config
from .parser import parse_bytes
from .report import build_report, to_json, to_markdown
from .scoring import LEVELS

EXIT_OK, EXIT_ERROR, EXIT_RISK = 0, 1, 3
MAX_INPUT_BYTES = 50 * 1024 * 1024  # refuse anything absurdly large


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="phishing-header-analyzer",
        description="Defensive email header analyzer for phishing triage. Works fully offline.",
    )
    p.add_argument("input", help="path to an .eml file or a text file of raw headers; use - to read stdin")
    p.add_argument("--format", choices=("json", "md"), default="json", help="report format (default: json)")
    p.add_argument("--out", metavar="PATH", help="write the report to a file instead of stdout")
    p.add_argument("--config", metavar="PATH",
                   help="JSON settings: protected_domains, org_domains, freemail_domains, trusted_authserv_ids")
    p.add_argument("--no-defang", action="store_true",
                   help="leave domains, IPs, and URLs clickable in Markdown output")
    p.add_argument("--no-timestamp", action="store_true",
                   help="omit the analysis time so repeat runs produce identical output")
    p.add_argument("--fail-on", choices=LEVELS, metavar="LEVEL",
                   help="exit with code 3 if the risk level is at or above LEVEL (low, medium, high)")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _read_input(arg: str, stdin: BinaryIO) -> tuple[bytes, str]:
    if arg == "-":
        data = stdin.read(MAX_INPUT_BYTES + 1)
        source = "<stdin>"
    else:
        path = Path(arg)
        if not path.is_file():
            raise FileNotFoundError(f"input file not found: {arg}")
        if path.stat().st_size > MAX_INPUT_BYTES:
            raise ValueError(f"input file is larger than {MAX_INPUT_BYTES // (1024 * 1024)} MB")
        data, source = path.read_bytes(), path.name
    if len(data) > MAX_INPUT_BYTES:
        raise ValueError(f"input is larger than {MAX_INPUT_BYTES // (1024 * 1024)} MB")
    if not data.strip():
        raise ValueError("input is empty")
    return data, source


def main(argv: list[str] | None = None, stdin: BinaryIO | None = None,
         stdout: BinaryIO | None = None, stderr=None) -> int:
    args = build_arg_parser().parse_args(argv)
    stdin = stdin or sys.stdin.buffer
    stdout = stdout or sys.stdout.buffer
    stderr = stderr or sys.stderr

    try:
        config = Config.from_file(args.config) if args.config else Config()
        data, source = _read_input(args.input, stdin)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=stderr)
        return EXIT_ERROR

    parsed = parse_bytes(data, source=source)
    if parsed.from_ is None and not parsed.hops and not parsed.auth_results:
        print("error: no email headers found in input", file=stderr)
        return EXIT_ERROR

    analyzed_at = None if args.no_timestamp else datetime.now(timezone.utc)
    report = build_report(parsed, config, analyzed_at)
    text = to_markdown(report, do_defang=not args.no_defang) if args.format == "md" else to_json(report)

    # Write bytes as UTF-8 so non-Latin domains don't crash narrow consoles (e.g. Windows cp1252).
    encoded = text.encode("utf-8")
    if args.out:
        try:
            Path(args.out).write_bytes(encoded)
        except OSError as exc:
            print(f"error: could not write {args.out}: {exc}", file=stderr)
            return EXIT_ERROR
        print(f"Report written to {args.out} (risk: {report['risk']['level']}, "
              f"score {report['risk']['score']}/100)", file=stderr)
    else:
        stdout.write(encoded)
        stdout.flush()

    if args.fail_on and LEVELS.index(report["risk"]["level"]) >= LEVELS.index(args.fail_on):
        return EXIT_RISK
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
