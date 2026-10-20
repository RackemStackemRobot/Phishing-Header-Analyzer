# Changelog

## 0.2.2

Tuned against real recruiter, vendor, and agency mail. Most of these were false positives on legitimate messages.

### Added

- **Hiring platforms** (JobDiva, Oracle Taleo, Workday, Paradox, Newton) and **Salesforce Marketing Cloud** are recognized. Mail-merge Message-IDs, platform-only DKIM signatures, and Reply-To addresses that go back to the employer are reported as informational, not as identity mismatches.
- **Clock offset detection:** a hop that runs backwards by an exact time-zone step, matching the Date header, is reported as a misconfigured server clock instead of forged headers.
- **Monitor-only DMARC:** a passing message from a domain at `p=none` is noted, since that domain can be spoofed without being rejected.
- **Click tracking:** the sender's own links rewritten through its mail platform's tracker (for example `exct.net`) are reported at low severity, with the fix (a branded tracking domain). Link text naming any other site is still a disguise.
- **Own-domain links:** link text showing an old or alternate brand name while the link goes to the sender's own domain is reported at low severity.

### Fixed

- `.gov`, `.mil`, and `.edu` domains are no longer flagged as lookalikes (`dhs.gov` was matched against `dhl.com`). With `--live`, spelling lookalikes on domains registered for five years or more are scored low.
- Quoted reply chains (`Re:` with Outlook `From:` / `Sent:` blocks) are no longer mistaken for inline forwards. Forwards still need a forward marker or a `Fwd:` / `FW:` subject.
- Outlook's `name <a@b<mailto:a@b>>` address format in forward blocks is parsed correctly.
- Microsoft 365 Message-IDs (`*.prod.outlook.com`) are no longer flagged.
- Registrar and network abuse steps are folded into one line on low-risk messages. Social and footer sites, platform domains, and the recipient's own mail filter (Proofpoint, Mimecast, and similar) are no longer looked up or suggested for reports.
- The link-mismatch action no longer says to treat a message as phishing outright.
- SPF results now explain what each one means; `none` says the domain has no SPF record.

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
