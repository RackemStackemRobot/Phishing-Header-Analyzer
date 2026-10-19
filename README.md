# phishing-header-analyzer

Defensive email header analyzer for phishing triage. Outputs JSON or Markdown reports.

Give it a saved `.eml` file or a text file of raw headers. It parses the authentication results, sender identity fields, and the Received chain, then produces a report an analyst can drop straight into a ticket. Every risk point in the score comes with a stated reason, so you can see exactly why a message scored the way it did.

This tool is designed to be safe by default:

- It works fully offline. It makes no DNS queries or network requests.
- It never opens links or attachments in the message.
- It does not upload data anywhere.
- It is intended for defensive triage and analyst training.

## What it checks (v0.1)

### Authentication results

- SPF, DKIM, and DMARC verdicts from `Authentication-Results` and `Received-SPF`
- ARC results when present
- Missing authentication headers (reported as "unknown," not as a pass)

### Sender identity

- `From` vs `Return-Path` vs `Reply-To` vs `Sender` domain mismatches
- `Message-ID` domain that doesn't match the sending domain
- Display names that contain a different email address
- Display names that use a protected brand name the sending domain doesn't match

### Received chain

- Each hop parsed into from, by, IP, and timestamp, shown in delivery order
- Large delays between hops
- Timestamps out of order
- Private or reserved IP addresses where a public hop is expected

### Lookalike domains

- Punycode / IDN domains
- Homoglyph substitutions (for example `0` for `o`, `rn` for `m`)
- Near-miss spellings of domains on an editable protected-brands list

## Note on DKIM

v0.1 does not cryptographically verify DKIM signatures. It reports the verdict the receiving mail server recorded in `Authentication-Results` and says so in the report. Live DNS lookups and signature verification are planned as an opt-in `--live` mode in a later release.

## Run

- JSON:
  - `phishing-header-analyzer message.eml`
- Markdown:
  - `phishing-header-analyzer message.eml --format md`

See [HOW_TO_RUN.md] for install steps and options.

## Safety note

This is not an offensive tool. It analyzes headers of messages you already received so you can decide whether they are malicious and respond.
