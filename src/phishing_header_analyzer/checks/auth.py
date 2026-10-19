"""SPF, DKIM, DMARC, and ARC verdict checks.

v0.1 trusts the verdicts your own mail server recorded. It does not re-verify
signatures or look up DNS records.
"""

from __future__ import annotations

from ..config import Config
from ..findings import Finding
from ..parser import AuthResult, ParsedHeaders
from ..util import is_within

CATEGORY = "authentication"


def trusted_results(parsed: ParsedHeaders, config: Config) -> tuple[list[AuthResult], str]:
    """Pick the Authentication-Results we can trust and explain how we chose them."""
    if not parsed.auth_results:
        return [], "none present"
    if config.trusted_authserv_ids:
        trusted = [r for r in parsed.auth_results
                   if r.authserv_id and any(is_within(r.authserv_id, t) for t in config.trusted_authserv_ids)]
        return trusted, "matched configured trusted servers"
    return [r for r in parsed.auth_results if r.header_index == 0], "assumed topmost header is trusted"


def _first(results: list[AuthResult], method: str) -> AuthResult | None:
    return next((r for r in results if r.method == method), None)


def dkim_signing_domain(result: AuthResult) -> str | None:
    """The domain that made a DKIM signature.

    Most servers record it as header.d=example.com. Gmail records header.i=@example.com
    (the signing identity, which RFC 6376 requires to be within the d= domain).
    """
    d = result.properties.get("header.d")
    if d:
        return d.lower().rstrip(".")
    i = result.properties.get("header.i")
    if i and "@" in i:
        return i.rsplit("@", 1)[1].lower().rstrip(".") or None
    return None


def run(parsed: ParsedHeaders, config: Config) -> list[Finding]:
    if parsed.headers_lost:
        return []  # inline-forwarded original: there are no authentication results to judge
    out: list[Finding] = []
    results, basis = trusted_results(parsed, config)

    if not parsed.auth_results:
        out.append(Finding(
            "AUTH-NO-RESULTS", CATEGORY, "medium", 10,
            "No Authentication-Results header",
            "The receiving server recorded no SPF, DKIM, or DMARC verdicts, so the "
            "sender's authenticity is unknown. Common with pasted headers, forwarded "
            "mail, or servers that don't stamp results.",
        ))
        return out

    if not results:
        out.append(Finding(
            "AUTH-UNTRUSTED-ONLY", CATEGORY, "medium", 10,
            "Authentication-Results present, but none from a trusted server",
            "Every Authentication-Results header was stamped by a server not on the "
            "trusted list. Headers added before your gateway can be forged by the sender.",
            {"authserv_ids": sorted({r.authserv_id or "?" for r in parsed.auth_results})},
        ))
        return out

    ignored = sorted({r.authserv_id or "?" for r in parsed.auth_results if r not in results})
    if ignored:
        out.append(Finding(
            "AUTH-EXTRA-HEADERS", CATEGORY, "info", 0,
            "Additional Authentication-Results headers ignored",
            "These were not stamped by the trusted server and may have been inserted "
            "by the sender to make the message look authenticated.",
            {"ignored_authserv_ids": ignored, "trust_basis": basis},
        ))

    # SPF
    spf = _first(results, "spf")
    spf_scores = {"fail": ("high", 25), "softfail": ("medium", 10), "neutral": ("low", 5),
                  "none": ("low", 5), "permerror": ("low", 5), "temperror": ("low", 3)}
    if spf is None:
        out.append(Finding("SPF-MISSING", CATEGORY, "low", 5, "No SPF verdict recorded",
                           "The trusted server did not record an SPF result."))
    elif spf.result in spf_scores:
        sev, pts = spf_scores[spf.result]
        out.append(Finding(
            f"SPF-{spf.result.upper()}", CATEGORY, sev, pts, f"SPF result: {spf.result}",
            "The sending server is not authorized by the envelope sender's domain to send its mail.",
            {"smtp.mailfrom": spf.properties.get("smtp.mailfrom"), "authserv_id": spf.authserv_id},
        ))

    # DKIM
    from_domain = parsed.from_.domain if parsed.from_ else None
    dkims = [r for r in results if r.method == "dkim"]
    passing = [r for r in dkims if r.result == "pass"]
    if not dkims or all(r.result == "none" for r in dkims):
        out.append(Finding("DKIM-NONE", CATEGORY, "medium", 10, "Message is not DKIM-signed",
                           "There is no cryptographic signature tying the message to a domain."))
    elif not passing:
        out.append(Finding(
            "DKIM-FAIL", CATEGORY, "high", 20, "DKIM signature failed",
            "A signature was present but did not verify. The message may have been "
            "altered or the signature forged.",
            {"results": [r.result for r in dkims],
             "signing_domains": [dkim_signing_domain(r) for r in dkims]},
        ))
    elif from_domain and not any(
        (sd := dkim_signing_domain(r)) and (is_within(from_domain, sd) or is_within(sd, from_domain))
        for r in passing
    ):
        out.append(Finding(
            "DKIM-UNALIGNED", CATEGORY, "low", 5, "DKIM passed for a different domain than From",
            "The signature is valid, but it was made by a domain other than the one in "
            "the From address. Common with mailing services, also common in phishing.",
            {"from_domain": from_domain, "signing_domains": [dkim_signing_domain(r) for r in passing]},
        ))

    # DMARC
    dmarc = _first(results, "dmarc")
    if dmarc is None or dmarc.result == "none":
        out.append(Finding(
            "DMARC-NONE", CATEGORY, "medium", 10, "No DMARC result for the From domain",
            "The From domain has no DMARC policy, or none was evaluated, so spoofing "
            "of that domain is not being blocked.",
            {"from_domain": from_domain},
        ))
    elif dmarc.result in ("fail", "permerror", "temperror"):
        out.append(Finding(
            "DMARC-FAIL", CATEGORY, "high", 30, f"DMARC result: {dmarc.result}",
            "The From address is not authenticated by SPF or DKIM in alignment with its "
            "domain. This is the strongest single indicator of a spoofed sender.",
            {"header.from": dmarc.properties.get("header.from"), "policy": dmarc.policy},
        ))

    # ARC (only reported when it fails; a pass just means forwarding was vouched for)
    arc = _first(results, "arc")
    if arc and arc.result == "fail":
        out.append(Finding("ARC-FAIL", CATEGORY, "low", 5, "ARC chain failed",
                           "The forwarding chain's authentication record did not validate."))

    # Received-SPF disagreeing with the trusted SPF verdict
    if spf and parsed.received_spf:
        other = {r.result for r in parsed.received_spf} - {spf.result}
        if other:
            out.append(Finding(
                "SPF-CONFLICT", CATEGORY, "low", 5, "Received-SPF disagrees with Authentication-Results",
                "Two SPF verdicts in the same message disagree. One may have been inserted by the sender.",
                {"authentication_results": spf.result, "received_spf": sorted(other)},
            ))

    return out
