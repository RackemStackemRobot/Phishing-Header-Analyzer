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


# Notification services attackers abuse to deliver lures through the real platform
# (a real Google Group invite, a real DocuSign envelope, a real PayPal invoice).
# Keys are patterns matched against the From address (* is a wildcard); values
# are display names. A starting point: verify and extend for your environment.
DEFAULT_PLATFORM_SENDERS = {
    "*@groups.google.com": "Google Groups",
    "drive-shares-*@google.com": "Google Drive sharing",
    "comments-noreply@docs.google.com": "Google Docs comments",
    "calendar-notification@google.com": "Google Calendar",
    "*@sharepointonline.com": "Microsoft SharePoint / OneDrive",
    "*@docusign.net": "DocuSign",
    "*@*.docusign.net": "DocuSign",
    "*@echosign.com": "Adobe Acrobat Sign",
    "*@adobesign.com": "Adobe Acrobat Sign",
    "no-reply@dropbox.com": "Dropbox",
    "service@paypal.com": "PayPal (invoices and money requests)",
    "*@notification.intuit.com": "Intuit QuickBooks invoices",
    "notifications@github.com": "GitHub notifications",
}


# Domains each platform legitimately links to, keyed by the registrable domain of
# its sending address. Links from a platform notification to anything else are
# flagged. Extend this when real notifications produce false positives.
DEFAULT_PLATFORM_LINK_DOMAINS = {
    "google.com": ["google.com", "googlegroups.com", "gstatic.com", "googleusercontent.com", "withgoogle.com"],
    "sharepointonline.com": ["sharepoint.com", "sharepointonline.com", "microsoft.com", "office.com",
                             "microsoftonline.com", "live.com", "office365.com"],
    "docusign.net": ["docusign.net", "docusign.com"],
    "echosign.com": ["echosign.com", "adobesign.com", "adobe.com"],
    "adobesign.com": ["echosign.com", "adobesign.com", "adobe.com"],
    "dropbox.com": ["dropbox.com", "dropboxusercontent.com"],
    "paypal.com": ["paypal.com", "paypalobjects.com"],
    "intuit.com": ["intuit.com", "quickbooks.com"],
    "github.com": ["github.com", "githubusercontent.com"],
}


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
    # Notification platforms whose authenticated mail still needs a human to
    # check who triggered it. Pattern -> display name.
    platform_senders: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_PLATFORM_SENDERS))
    # Sender registrable domain -> domains its notifications legitimately link to.
    platform_link_domains: dict[str, list[str]] = field(
        default_factory=lambda: {k: list(v) for k, v in DEFAULT_PLATFORM_LINK_DOMAINS.items()})

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
        values = {}
        for key, value in data.items():
            if key == "platform_senders":
                if not isinstance(value, dict):
                    raise ValueError("platform_senders must be an object of pattern: name pairs")
                values[key] = {str(k).lower(): str(v) for k, v in value.items()}
            elif key == "platform_link_domains":
                if not isinstance(value, dict) or not all(isinstance(v, list) for v in value.values()):
                    raise ValueError("platform_link_domains must be an object of domain: [domains] pairs")
                values[key] = {str(k).lower(): [str(d).lower() for d in v] for k, v in value.items()}
            else:
                if not isinstance(value, list):
                    raise ValueError(f"{key} must be a list")
                values[key] = [str(v).lower() for v in value]
        return cls(**values)
