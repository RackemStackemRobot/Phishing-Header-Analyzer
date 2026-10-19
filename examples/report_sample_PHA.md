# Phishing Header Analysis: message.eml

**Header risk: MEDIUM (45/100)**

_Authentication confirms who delivered the message, not whether its content is safe._

- score 45 is between 20 and 49

## Recommended Actions

1. Block these link domains at the web proxy and mail gateway, and search mail logs for other
messages linking to them: _(LINK-OFF-PLATFORM)_
   - up[.]XXXXXXXXX[.]XX
2. If this message is malicious, report the sending server to its network operator, attaching the
original .eml (--abuse-reports can draft these): _(NETWORK-ABUSE)_
   - 209[.]85[.]220[.]69: Google LLC \<network-abuse@google[.]com\>
3. Verify these accounts named in the notification through a channel you already trust. Don't join,
open, sign, or pay until verified. If they're malicious, report them to the platform as well as
blocking them locally: _(PLATFORM-NOTIFICATION, PLATFORM-ACCOUNTS)_
   - XXXXX@XXXXX[.]XXXXXXXXXX[.]XX

## Message

| Field | Value |
| --- | --- |
| Subject | Invitation to join Start Connecting |
| Date | 2026-10-19T17:06:45+00:00 |
| From | "Google Groups" noreply@groups[.]google[.]com |
| Reply-To | - |
| Return-Path | noreply@groups[.]google[.]com |
| Message-ID | \<XXXXXXXXXXXXXXXXXX@notifications[.]google[.]com\> |

## Findings

| Severity | Points | Check | Finding | Evidence |
| --- | --- | --- | --- | --- |
| high | 25 | `LINK-OFF-PLATFORM` | Google Groups notification links outside Google Groups | platform: Google Groups; domains: up[.]XXXXXXXXX[.]XX; allowed: google[.]com, googlegroups[.]com, googleusercontent[.]com, gstatic[.]com, withgoogle[.]com |
| medium | 20 | `PLATFORM-NOTIFICATION` | Authentic Google Groups notification sent on behalf of another account | platform: Google Groups; from: noreply@groups[.]google[.]com |
| info | 0 | `LIVE-LOOKUP-NOTES` | Some live lookups didn't complete | notes: XXXXXXXXX[.]XX: no RDAP service for .XX domains, XXXXXXXXXX[.]XX: no RDAP service for .XX domains |
| info | 0 | `NETWORK-ABUSE` | Network abuse contacts found | contacts: 209[.]85[.]220[.]69: Google LLC \<network-abuse@google[.]com\> |
| info | 0 | `PLATFORM-ACCOUNTS` | Accounts named in the Google Groups notification | platform: Google Groups; accounts: XXXXX@XXXXX[.]XXXXXXXXXX[.]XX |

### Why these matter

- **LINK-OFF-PLATFORM**: A genuine Google Groups notification links back to Google Groups. Links to other sites
usually mean the attacker put their own landing page in the group description, file name, or message the platform
delivered.
- **PLATFORM-NOTIFICATION**: This message really came from Google Groups, which is why SPF, DKIM, and DMARC pass.
That authenticates the platform, not the account that triggered the notification. Attackers create real groups,
shares, envelopes, and invoices so the platform delivers their lure for them.
- **LIVE-LOOKUP-NOTES**: Results for these may be missing. Registries vary in what they publish, and some
country-code domains have no RDAP service.
- **NETWORK-ABUSE**: From public IP registration data. The network operator can act on the server that sent or
hosts this message's content.
- **PLATFORM-ACCOUNTS**: These addresses appear in the notification and are likely the account that triggered it
or the group, file, or envelope it points to. They are the indicators to verify, report to the platform, or block.

## Authentication

Trust basis: matched configured trusted servers.

| Method | Result | Recorded by | Details |
| --- | --- | --- | --- |
| dkim | pass | mx[.]google[.]com | header.i: @google[.]com; header.s: 20251104; header.b: PqVQeT2y |
| spf | pass | mx[.]google[.]com | smtp.mailfrom: noreply@groups[.]google[.]com |
| dmarc | pass | mx[.]google[.]com | header.from: google[.]com; policy: reject |
| dkim | pass | mx[.]google[.]com | header.i: @gmail[.]com |

## Message Body

Inspected 1 text and 1 HTML part(s); 0 file attachment(s) skipped, not opened. Link domains only; no link was visited.

| Link domain | Links |
| --- | --- |
| groups[.]google[.]com | 11 |
| support[.]google[.]com | 4 |
| up[.]XXXXXXXXX[.]XX | 2 |

## Live Lookups (RDAP)

| Domain | Registered | Age (days) | Registrar | Abuse contact |
| --- | --- | --- | --- | --- |
| XXXXXXXXX[.]XX | lookup failed: no RDAP service for .XX domains | - | - | - |
| XXXXXXXXXX[.]XX | lookup failed: no RDAP service for .XX domains | - | - | - |

| IP | Network | Organization | Country | Abuse contact |
| --- | --- | --- | --- | --- |
| 209[.]85[.]220[.]69 | GOOGLE | Google LLC | - | network-abuse@google[.]com |


## Received Chain (origin first)

| Hop | From | IP | By | Protocol | Time (UTC) | Delay |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | XXXX-XXX-XXX[.]google[.]com | 209[.]85[.]220[.]69 | mx[.]google[.]com | SMTPS | 2026-10-19T17:06:46+00:00 | - |
| 2 | - | - | 2002:a05:7010:cb19:b0:557:3fa3:5b27 | SMTP | 2026-10-19T17:06:46+00:00 | +0m00s |

## Notes

- DKIM signatures were not verified locally. Verdicts are those recorded by the receiving server.
- Headers added before your organization's mail gateway can be forged by the sender.
- The risk score supports analyst judgment. It is not a verdict on its own.

_Generated by phishing-header-analyzer 0.2.1 at 2026-10-19T23:37:13.172962+00:00._
