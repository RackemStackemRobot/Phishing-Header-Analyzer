# How to run

## Requirements

- Python 3.10 or newer
- No third-party packages (standard library only)

## Install

From the repo root:

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e .
```

You can also run it without installing, from the repo root:

```bash
PYTHONPATH=src python -m phishing_header_analyzer message.eml
```

## Get the headers

- **Outlook (desktop):** open the message, File > Properties, copy "Internet headers" into a text file. Or drag the message out of Outlook to save it, then export as `.eml`.
- **Gmail:** open the message, three-dot menu > "Show original," then "Download original" to get a `.eml`.
- **Thunderbird:** File > Save As > File to save as `.eml`.

A plain text file containing only the pasted headers also works.

## Usage

```bash
# JSON report to stdout
phishing-header-analyzer message.eml

# Markdown report to stdout
phishing-header-analyzer message.eml --format md

# Write the report to a file
phishing-header-analyzer message.eml --format md --out report.md

# Use your organization's settings
phishing-header-analyzer message.eml --config my-org.json

# Read pasted headers from stdin
phishing-header-analyzer - < headers.txt
```

## The body-inspection prompt

When you run it at a terminal, it asks:

```
Inspect the message body too? This reads the text parts only, to list link domains
and the accounts behind platform notifications. Nothing is opened, rendered, or visited.
  y = yes   n = headers only   Esc or any other key = cancel
>
```

It's a single keypress; no Enter needed. Anything typed before the question appears is ignored, so a stray keypress can't answer it. Cancelling writes no report and exits with code 4.

To skip the question, pass `--inspect-body` or `--headers-only`. Scripts, scheduled jobs, and piped input (`-`) are never prompted and run headers-only unless `--inspect-body` is given.

## Full investigation in one command

```bash
phishing-header-analyzer message.eml --config my-org.json --inspect-body --live \
    --format md --out report.md --abuse-reports reports
```

That writes the report to `report.md` and draft abuse reports into the `reports` folder. Open `reports/README.txt` for what to send where. On Windows PowerShell, put it all on one line (or end each line with a backtick instead of a backslash).

## Options

| Option | What it does |
| --- | --- |
| `--format json` or `md` | Report format. Default is `json`. |
| `--out PATH` | Write the report to a file instead of the screen. |
| `--config PATH` | Load settings from a JSON file (see below). |
| `--inspect-body` | Also inspect the message body, without asking. |
| `--headers-only` | Analyze headers only, without asking. |
| `--live` | Look up domain registration dates and abuse contacts via RDAP. Needs internet access; queries public registries only. |
| `--abuse-reports DIR` | Write draft abuse reports into `DIR`. Nothing is sent. Combine with `--live` to include registrars and network operators. |
| `--no-defang` | Leave domains, IPs, and URLs clickable in Markdown output. |
| `--no-timestamp` | Leave out the analysis time so repeat runs give identical output. |
| `--fail-on LEVEL` | Exit with code 3 if the risk is at or above `low`, `medium`, or `high`. |
| `--version` | Show the version. |

## Config file

Copy `examples/config.example.json` and edit it. Every key is optional; anything you leave out keeps its default.

| Key | Purpose |
| --- | --- |
| `org_domains` | Your own organization's domains. Lookalikes of these are flagged. |
| `protected_domains` | Brands and vendors your users trust. Replaces the built-in list (Microsoft, PayPal, DocuSign, major banks and shippers, and others). |
| `freemail_domains` | Free mail providers. A Reply-To pointing at one of these is weighted higher. Replaces the built-in list. |
| `trusted_authserv_ids` | Hostnames of your own inbound mail servers. Only Authentication-Results headers stamped by these are trusted. If left empty, the topmost Authentication-Results header is trusted and the report says so. |
| `platform_senders` | Notification services whose authentic mail still needs a human check (Google Groups, DocuSign, PayPal invoices, and others). An object of `"address pattern": "display name"` pairs; `*` is a wildcard. Replaces the built-in list. |
| `platform_link_domains` | Domains each platform legitimately links to, keyed by its sending domain, for example `"google.com": ["google.com", "googlegroups.com", "gstatic.com"]`. Links from a platform notification to anything else are flagged. If a real notification gets flagged for a link it legitimately uses, add that domain here. Replaces the built-in list. |

Setting `trusted_authserv_ids` is the most important step for accurate results, because it stops forged authentication headers from being believed.

**Gmail users:** set `trusted_authserv_ids` to `["mx.google.com"]`. That's the name Gmail's servers stamp on their authentication results.

Example `platform_senders` entry:

```json
{
  "platform_senders": {
    "*@groups.google.com": "Google Groups",
    "*@docusign.net": "DocuSign",
    "*@notify.vendor-portal.example": "Vendor portal"
  }
}
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Analysis completed |
| 1 | Input or config error (missing file, empty input, not an email, bad JSON) |
| 2 | Invalid command-line options |
| 3 | Risk met or exceeded the `--fail-on` level |
| 4 | Cancelled at the body-inspection prompt |

`--fail-on` lets you use the tool in scripts and mail-triage pipelines, for example to route high-risk messages to an analyst queue.

## Run the tests

```bash
python -m unittest discover -s tests -v
```
