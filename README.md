# phishing-header-analyzer

Defensive email header analyzer for phishing triage. Outputs JSON or Markdown reports.

Give it a saved `.eml` file or a text file of raw headers. It parses the authentication results, sender identity fields, and the Received chain, then produces a report an analyst can drop straight into a ticket. Every risk point in the score comes with a stated reason, so you can see exactly why a message scored the way it did.

This tool is designed to be safe by default:

- It works fully offline. It makes no DNS queries or network requests.
- It never opens links or attachments in the message.
- It reads the message body only if you say yes (see Body inspection).
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

### Bulk mail service

- Identifies the bulk email service that delivered the message (SendGrid, Mailgun, Amazon SES, Mailchimp/Mandrill, Postmark, SparkPost, Brevo, Constant Contact) from DKIM signatures, relay hostnames, and service-specific headers. Empty leftover headers are ignored, since real scam mail sometimes carries blank headers named after other services.
- Informational only, since legitimate newsletters use these services too. Its value is the recommended action: the service can suspend the sending account, which is usually more effective than blocking one domain. Verify the abuse contact on the service's website before sending a report.

### Forwarded mail

Phishing often reaches an analyst as a forward from the person who received it. How it was forwarded decides what can be checked:

- **Forwarded as an attachment:** the original arrives intact. The tool finds it, follows nested attachments inward, and analyzes the original with full headers. The forwarder is listed separately under "Forwarded By." This works in headers-only mode too, since an attached email's headers are still headers.
- **Forwarded inline** (the normal Forward button): the forwarding client keeps only a text summary of the original, so its authentication results and delivery path are gone for good. With body inspection on, the tool recovers the innermost original's sender, subject, and date from the forward block (Gmail, Outlook, Apple Mail, and Thunderbird formats), runs the sender, display-name, lookalike, and link checks against that sender, skips the checks whose data was lost, and says so at the top of the report. It also recovers the original Message-ID's domain from the `References` header when present.
- **Looks forwarded but the body wasn't inspected:** the report says the results describe the forwarder, not the original sender.

For the best results, ask for suspicious mail to be sent as an attachment. In Gmail on a computer: open the message, three-dot menu, **Forward as attachment** (the Gmail phone app can't do this), or **Download message** and send the `.eml` file.

### Body inspection (opt-in)

At a terminal, the tool asks before reading the message body. Answer `y` to inspect it, `n` for headers only, or press Esc (or any other key) to cancel. Scripts and piped input are never prompted and stay headers-only unless `--inspect-body` is passed.

With body inspection on, it also checks:

- Platform notifications that link outside the platform (a "Google Groups" invite linking to some other site)
- The accounts named inside platform notifications (the inviter, the group address), listed as indicators to verify or report
- Link text that shows one site but goes to another
- Links to bare IP addresses
- Lookalike link domains, using the same homoglyph and typo checks as sender domains

How it stays safe:

- Only text and HTML parts are read. Attachments are skipped, never opened.
- HTML is read as text. Nothing is rendered, no scripts run, no images load, and **no link is ever visited**. The tool contains no networking code, and a test blocks all network access during analysis to prove it on every commit.
- Reports contain link **domains** only, never full URLs. Phishing URLs often carry per-recipient tracking tokens; leaving them out means no one can click one from a ticket and confirm to the attacker that the target is live.
- Body text is capped at 5 million characters.

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
