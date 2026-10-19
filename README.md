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

### Trusted-service abuse

- Authentic notifications from platforms attackers abuse to deliver lures: Google Groups invites, Google Drive shares, SharePoint/OneDrive, DocuSign, Adobe Sign, Dropbox, PayPal invoices, QuickBooks invoices, GitHub, and others (editable list)
- These pass SPF, DKIM, and DMARC because the platform really sent them. The finding tells the analyst to verify the account that triggered the notification, not the platform

## Note on DKIM

v0.1 does not cryptographically verify DKIM signatures. It reports the verdict the receiving mail server recorded in `Authentication-Results` and says so in the report. Live DNS lookups and signature verification are planned as an opt-in `--live` mode in a later release.

## Header risk score

Each finding carries points. The score is their sum, capped at 100, and every point traces back to a stated reason in the report. It is labeled "header risk" on purpose: authentication confirms who delivered a message, not whether its content is safe.

| Level | Rule |
| --- | --- |
| low | score under 20 |
| medium | score 20 to 49, or any single high-severity finding |
| high | score 50 or more, or two or more high-severity findings |

Passing SPF, DKIM, and DMARC does not make a message safe. An attacker who registers a lookalike domain can pass all three. The included test fixtures demonstrate this.

## Reports

Every report opens with **Recommended Actions** when there's something to do, such as quarantining a spoofed message, blocking a lookalike domain, or verifying the account behind a platform notification.

- **JSON:** raw, complete, and machine-readable, for SIEM or SOAR ingestion.
- **Markdown:** for pasting into tickets. Sender-written values (subjects, display names) are escaped so they can't break tables or inject formatting, and domains, IPs, and URLs are defanged (`example[.]com`, `hxxp://`) so ticketing systems don't make them clickable.

## Run

- JSON:
  - `phishing-header-analyzer message.eml`
- Markdown:
  - `phishing-header-analyzer message.eml --format md`
- With your organization's settings:
  - `phishing-header-analyzer message.eml --config my-org.json`

See [HOW_TO_RUN.md](HOW_TO_RUN.md) for install steps, all options, and the config file format.

## Safety note

This is not an offensive tool. It analyzes headers of messages you already received so you can decide whether they are malicious and respond.

