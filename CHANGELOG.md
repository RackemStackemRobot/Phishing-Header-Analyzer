# Changelog

## 0.2.1

### Fixed

- `--version` and report footers now show the correct version.
- Generated abuse-report folders (`reports/`) are ignored by git so real messages aren't committed.

## 0.2.0

Built and tuned against real phishing samples.

### Added

- **Opt-in body inspection** with a single-keypress prompt (`y` / `n` / Esc), plus `--inspect-body` and `--headers-only`. Scripts and piped input are never prompted and stay headers-only. Reports list link domains only, never full URLs, so per-recipient tracking tokens never reach a ticket.
- **Link checks:** link text that disguises its destination, links to bare IPs, and lookalike link domains.
- **Trusted-service abuse detection:** authentic Google Groups, Drive, SharePoint, DocuSign, PayPal invoice, and similar notifications triggered by an attacker. Flags links that leave the platform and lists the accounts named in the notification.
- **Forwarded mail:** analyzes the attached original of a forward-as-attachment (nested forwards included, headers-only mode too). For inline forwards, recovers the innermost original sender from Gmail, Outlook, Apple Mail, and Thunderbird forward blocks, runs the checks that still apply, and says plainly which data was lost.
- **Bulk mail service identification** (SendGrid, Mailgun, Amazon SES, Mailchimp/Mandrill, Postmark, SparkPost, Brevo, Constant Contact) from strong fingerprints only.
- **`--live` RDAP lookups:** domain registration date, registrar, and abuse contact; network owner and abuse contact for the sending IP. Flags recently registered domains. Queries public registries only, never the sender's servers.
- **`--abuse-reports DIR`:** draft abuse reports in the Abuse Reporting Format (RFC 5965) for the bulk mail service, registrars, network operators, the Anti-Phishing Working Group, and abused platforms, with the original attached byte for byte. Drafts only; nothing is ever sent.
- **Recommended Actions** at the top of every report, naming the specific accounts, domains, and IPs to act on.
- A "Header risk" headline with a note that authentication confirms who delivered a message, not whether its content is safe.

### Fixed

- DKIM alignment for Gmail's `header.i=@domain` format.
- Quoted values in Authentication-Results.
- Received timestamps with fractional seconds and ISO-style dates (SendGrid).
- Defanging no longer brackets the username half of email addresses.
- CLI tests no longer wait for a keypress when run in a real terminal.

## 0.1.0

Initial release: offline header analysis covering SPF, DKIM, DMARC, and ARC verdicts; sender identity mismatches; display name tricks; Received chain timing; lookalike domains; risk scoring; JSON and Markdown reports.
