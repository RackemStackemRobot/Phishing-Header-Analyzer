"""Shared helpers: domain normalization, IP classification, homoglyph matching."""

from __future__ import annotations

import ipaddress
import re

# Common multi-part public suffixes. Not a full Public Suffix List, which would
# need a download; good enough to avoid treating "co.uk" as an organization.
_MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.nz", "co.jp", "co.kr", "co.in", "com.br", "com.mx", "com.cn",
    "com.tr", "co.za", "com.sg", "com.hk",
}


def org_domain(domain: str | None) -> str | None:
    """Approximate the registrable domain: mail.contoso.co.uk -> contoso.co.uk."""
    if not domain:
        return None
    labels = domain.lower().strip().rstrip(".").split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in _MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def org_label(domain: str | None) -> str | None:
    """The brand-bearing label of the registrable domain: contoso.co.uk -> contoso."""
    od = org_domain(domain)
    return od.split(".")[0] if od else None


def same_org(a: str | None, b: str | None) -> bool:
    return bool(a and b and org_domain(a) == org_domain(b))


def is_within(domain: str | None, parent: str) -> bool:
    """True if domain equals parent or is a subdomain of it."""
    if not domain:
        return False
    domain, parent = domain.lower(), parent.lower()
    return domain == parent or domain.endswith("." + parent)


def decode_idna(label: str) -> str:
    """Decode a punycode label for display and comparison. Returns input on failure."""
    if not label.lower().startswith("xn--"):
        return label
    try:
        return label.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        return label


def decode_domain(domain: str) -> str:
    return ".".join(decode_idna(lbl) for lbl in domain.split("."))


# ---------- IP classification ----------

_RANGES = [
    ("loopback", ipaddress.ip_network("127.0.0.0/8")),
    ("private", ipaddress.ip_network("10.0.0.0/8")),
    ("private", ipaddress.ip_network("172.16.0.0/12")),
    ("private", ipaddress.ip_network("192.168.0.0/16")),
    ("cgnat", ipaddress.ip_network("100.64.0.0/10")),
    ("link-local", ipaddress.ip_network("169.254.0.0/16")),
    ("unspecified", ipaddress.ip_network("0.0.0.0/8")),
    # RFC 5737 documentation ranges. Treated as public-like so test fixtures
    # behave the way real internet addresses would.
    ("documentation", ipaddress.ip_network("192.0.2.0/24")),
    ("documentation", ipaddress.ip_network("198.51.100.0/24")),
    ("documentation", ipaddress.ip_network("203.0.113.0/24")),
    ("loopback", ipaddress.ip_network("::1/128")),
    ("private", ipaddress.ip_network("fc00::/7")),
    ("link-local", ipaddress.ip_network("fe80::/10")),
    ("documentation", ipaddress.ip_network("2001:db8::/32")),
]

NON_ROUTABLE = {"loopback", "private", "cgnat", "link-local", "unspecified"}


def classify_ip(ip: str | None) -> str | None:
    """Return loopback, private, cgnat, link-local, unspecified, documentation, or public."""
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for name, net in _RANGES:
        if addr.version == net.version and addr in net:
            return name
    return "public"


# ---------- homoglyphs and near-misses ----------

# Characters commonly swapped in for Latin letters. Maps to a shared "skeleton"
# so visually similar strings compare equal. Not the full Unicode confusables
# table, just the substitutions seen most in phishing domains.
_CONFUSABLES = str.maketrans({
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "l", "ј": "j", "ѕ": "s", "ԁ": "d", "ӏ": "l", "к": "k", "м": "m",
    "н": "h", "т": "t", "в": "b", "ԛ": "q", "ԝ": "w",
    # Greek
    "ο": "o", "α": "a", "ε": "e", "ι": "l", "κ": "k", "ν": "v", "ρ": "p",
    "τ": "t", "υ": "u", "χ": "x",
    # Digits and look-alike ASCII
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "i": "l",
})

_SEQUENCES = (("rn", "m"), ("vv", "w"))


def skeleton(text: str) -> str:
    s = decode_idna(text).lower().translate(_CONFUSABLES)
    for seq, repl in _SEQUENCES:
        s = s.replace(seq, repl)
    return s


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        cur = [i]
        for j, cb in enumerate(b, start=1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


_ALNUM = re.compile(r"[^a-z0-9]")


def compact(text: str) -> str:
    """Lowercase and strip everything but letters and digits: 'Contoso-Bank' -> 'contosobank'."""
    return _ALNUM.sub("", text.lower())
