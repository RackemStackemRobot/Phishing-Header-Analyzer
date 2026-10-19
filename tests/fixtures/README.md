# Test fixtures

All fixtures are synthetic. Domains use the reserved `.example` TLD (RFC 2606) and IP addresses come from the RFC 5737 documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), so nothing here resolves or points at a real organization. DKIM signature values are placeholders and will not verify.

The recipient organization in every fixture is `northwind.example`, with `mx1.northwind.example` (192.0.2.10) as its trusted inbound gateway. The protected brand is `contoso-bank.example`.

| Fixture | Scenario | Expected findings |
| --- | --- | --- |
| `clean.eml` | Legitimate bank statement notice | SPF/DKIM/DMARC pass, all identity domains aligned, sequential hops. Low risk. |
| `spf_fail.eml` | Spoofed bank security alert from a rented VPS | SPF fail, DKIM none, DMARC fail; Return-Path and Message-ID domains differ from From; hop timestamps out of order; Date header far older than first hop. High risk. |
| `replyto_mismatch.eml` | Vendor invoice / BEC payment redirect | Auth passes for the sending domain; display name contains a different email address; Reply-To points at an unrelated free mail domain. Elevated risk despite passing auth. |
| `lookalike_domain.eml` | Credential phish from attacker-owned lookalike domain | Auth passes; From domain is a homoglyph of the protected brand (`0` for `o`); display name claims the brand. High risk despite passing auth. |
| `headers_only.txt` | Pasted raw headers, no body, no auth results | No `Authentication-Results` (verdicts unknown); punycode/IDN From domain (`xn--nrthwind-nbh.example`, which renders as "northwind" with a Cyrillic "о") impersonating the recipient's own domain; Message-ID domain mismatch. |
