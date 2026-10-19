"""Analyzer settings: protected brands, your own domains, and trusted servers.

Defaults are a starting point. Organizations should supply their own list of
protected domains (their own domains plus vendors and brands their users trust).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_PROTECTED_DOMAINS = [
    "microsoft.com", "office.com", "outlook.com", "live.com",
    "google.com", "apple.com", "icloud.com", "amazon.com",
    "paypal.com", "docusign.com", "dropbox.com", "linkedin.com",
    "adobe.com", "zoom.us", "netflix.com", "chase.com",
    "bankofamerica.com", "wellsfargo.com", "fedex.com", "dhl.com",
    "usps.com", "irs.gov",
]

DEFAULT_FREEMAIL_DOMAINS = [
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
    "msn.com", "yahoo.com", "ymail.com", "aol.com", "icloud.com", "me.com",
    "proton.me", "protonmail.com", "gmx.com", "gmx.net", "mail.com",
    "yandex.com", "zoho.com", "tutanota.com",
]


@dataclass
class Config:
    # Brands and vendors to watch for impersonation and lookalikes.
    protected_domains: list[str] = field(default_factory=lambda: list(DEFAULT_PROTECTED_DOMAINS))
    # Your own organization's domains. Also checked for lookalikes.
    org_domains: list[str] = field(default_factory=list)
    # Free mail providers. Reply-To pointing at one of these is weighted higher.
    freemail_domains: list[str] = field(default_factory=lambda: list(DEFAULT_FREEMAIL_DOMAINS))
    # Hostnames of your own inbound mail servers. Only Authentication-Results
    # headers stamped by these are trusted. If empty, the topmost
    # Authentication-Results header is trusted and the report says so.
    trusted_authserv_ids: list[str] = field(default_factory=list)

    @property
    def watched_domains(self) -> list[str]:
        seen, out = set(), []
        for d in self.org_domains + self.protected_domains:
            d = d.lower().strip().rstrip(".")
            if d and d not in seen:
                seen.add(d)
                out.append(d)
        return out

    @classmethod
    def from_file(cls, path: str | Path) -> "Config":
        """Load settings from JSON. Keys not present keep their defaults."""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        known = {f for f in cls.__dataclass_fields__}
        unknown = set(data) - known
        if unknown:
            raise ValueError(f"unknown config keys: {', '.join(sorted(unknown))}")
        return cls(**{k: [str(v).lower() for v in data[k]] for k in data})
