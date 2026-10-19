"""Opt-in live lookups (--live) using RDAP, the structured successor to WHOIS.

Why RDAP and not DNS: RDAP queries go to IANA and to the registries and regional
internet registries (Verisign, ARIN, RIPE, ...), never to the sender's own
servers. A DNS lookup for a phisher's domain can reach nameservers the phisher
runs and tell them someone is investigating. RDAP answers the questions that
matter most for triage, domain age and abuse contacts, without that risk.

Safety rules:
  * Only runs when asked (--live). Default analysis makes no network requests.
  * HTTPS only, including redirects. Responses are size-capped and time-limited.
  * Looks up registrable domains and public IPs only, capped in number, and skips
    big well-known domains (protected brands, free mail, platform domains).
  * A failed lookup becomes a note in the report; it never stops the analysis.
"""

from __future__ import annotations

import ipaddress
import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from . import __version__
from .config import Config
from .util import classify_ip, org_domain

BOOTSTRAP = {
    "dns": "https://data.iana.org/rdap/dns.json",
    "ipv4": "https://data.iana.org/rdap/ipv4.json",
    "ipv6": "https://data.iana.org/rdap/ipv6.json",
}
USER_AGENT = f"phishing-header-analyzer/{__version__} (+https://github.com/RackemStackemRobot/Phishing-Header-Analyzer)"
TIMEOUT_SECONDS = 10
MAX_RESPONSE_BYTES = 2_000_000
MAX_DOMAINS = 10
MAX_IPS = 3


class LiveError(Exception):
    pass


@dataclass
class DomainInfo:
    domain: str
    registered: str | None = None     # ISO date of registration
    age_days: int | None = None
    registrar: str = ""
    abuse_email: str = ""
    abuse_phone: str = ""
    source: str = ""                  # RDAP URL queried
    error: str = ""


@dataclass
class IpInfo:
    ip: str
    network: str = ""                 # network name, e.g. SENDGRID
    range: str = ""
    org: str = ""                     # registrant organization
    country: str = ""
    abuse_email: str = ""
    source: str = ""
    error: str = ""


@dataclass
class LiveResults:
    domains: list[DomainInfo] = field(default_factory=list)
    ips: list[IpInfo] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


# ---------- HTTPS fetch ----------

class _HttpsOnlyRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.lower().startswith("https://"):
            raise LiveError(f"refused redirect to non-HTTPS URL: {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_HttpsOnlyRedirects())


def https_json(url: str) -> dict:
    """GET a JSON document over HTTPS with a timeout and a size cap."""
    if not url.lower().startswith("https://"):
        raise LiveError(f"refused non-HTTPS URL: {url}")
    req = urllib.request.Request(url, headers={
        "Accept": "application/rdap+json, application/json",
        "User-Agent": USER_AGENT,
    })
    try:
        with _OPENER.open(req, timeout=TIMEOUT_SECONDS) as resp:
            data = resp.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise LiveError(f"HTTP {exc.code}" + (" (not found)" if exc.code == 404 else "")) from None
    except urllib.error.URLError as exc:
        raise LiveError(f"could not connect: {exc.reason}") from None
    except TimeoutError:
        raise LiveError("timed out") from None
    if len(data) > MAX_RESPONSE_BYTES:
        raise LiveError("response too large")
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise LiveError("response was not valid JSON") from None


# ---------- RDAP parsing ----------

def _vcard(entity: dict) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    try:
        for prop in entity.get("vcardArray", [None, []])[1]:
            name, _params, _kind, value = prop[0], prop[1], prop[2], prop[3]
            if isinstance(value, list):
                value = " ".join(str(v) for v in value if v)
            if value:
                out.setdefault(str(name).lower(), []).append(str(value))
    except (IndexError, TypeError, AttributeError):
        pass
    return out


def _find_role(entities: list, role: str) -> dict | None:
    """First entity with this role, searching nested entities too."""
    for e in entities or []:
        if not isinstance(e, dict):
            continue
        if role in (e.get("roles") or []):
            return e
        found = _find_role(e.get("entities"), role)
        if found:
            return found
    return None


def _contact(entity: dict | None) -> tuple[str, str]:
    if not entity:
        return "", ""
    v = _vcard(entity)
    email = (v.get("email") or [""])[0].strip().lower()
    phone = (v.get("tel") or [""])[0].replace("tel:", "").strip()
    return email, phone


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def parse_domain(domain: str, data: dict, now: datetime) -> DomainInfo:
    info = DomainInfo(domain=domain)
    events = data.get("events")
    for event in events if isinstance(events, list) else []:
        if isinstance(event, dict) and event.get("eventAction") == "registration":
            reg = _parse_date(event.get("eventDate"))
            if reg:
                info.registered = reg.date().isoformat()
                info.age_days = max(0, (now - reg).days)
    registrar = _find_role(data.get("entities"), "registrar")
    if registrar:
        info.registrar = (_vcard(registrar).get("fn") or [""])[0]
        info.abuse_email, info.abuse_phone = _contact(_find_role(registrar.get("entities"), "abuse"))
    if not info.abuse_email:
        info.abuse_email, info.abuse_phone = _contact(_find_role(data.get("entities"), "abuse"))
    return info


def parse_ip(ip: str, data: dict) -> IpInfo:
    info = IpInfo(ip=ip)
    info.network = str(data.get("name") or "")
    start, end = data.get("startAddress"), data.get("endAddress")
    info.range = f"{start} - {end}" if start and end else ""
    info.country = str(data.get("country") or "")
    registrant = _find_role(data.get("entities"), "registrant")
    if registrant:
        info.org = (_vcard(registrant).get("fn") or [""])[0]
    info.abuse_email, _ = _contact(_find_role(data.get("entities"), "abuse"))
    return info


# ---------- RDAP client ----------

class Rdap:
    """Finds the right RDAP server through IANA's bootstrap files, then queries it."""

    def __init__(self, fetch: Callable[[str], dict] = https_json):
        self.fetch = fetch
        self._bootstrap: dict[str, list] = {}
        self._bootstrap_error: dict[str, str] = {}

    def _services(self, kind: str) -> list:
        if kind in self._bootstrap_error:   # don't wait out the same timeout once per lookup
            raise LiveError(self._bootstrap_error[kind])
        if kind not in self._bootstrap:
            try:
                data = self.fetch(BOOTSTRAP[kind])
                self._bootstrap[kind] = (data.get("services") if isinstance(data, dict) else None) or []
            except LiveError as exc:
                self._bootstrap_error[kind] = f"IANA bootstrap unavailable: {exc}"
                raise LiveError(self._bootstrap_error[kind]) from None
        return self._bootstrap[kind]

    @staticmethod
    def _https_base(urls: list[str]) -> str | None:
        for u in urls:
            if u.lower().startswith("https://"):
                return u if u.endswith("/") else u + "/"
        return None

    def domain_url(self, domain: str) -> str:
        tld = domain.rsplit(".", 1)[-1].lower()
        for entry in self._services("dns"):
            tlds, urls = entry[0], entry[1]
            if tld in [t.lower() for t in tlds]:
                base = self._https_base(urls)
                if base:
                    return f"{base}domain/{domain}"
        raise LiveError(f"no RDAP service for .{tld} domains")

    def ip_url(self, ip: str) -> str:
        addr = ipaddress.ip_address(ip)
        best, best_len = None, -1
        for entry in self._services("ipv4" if addr.version == 4 else "ipv6"):
            for cidr in entry[0]:
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                except ValueError:
                    continue
                if addr in net and net.prefixlen > best_len:
                    base = self._https_base(entry[1])
                    if base:
                        best, best_len = base, net.prefixlen
        if not best:
            raise LiveError(f"no RDAP service for {ip}")
        return f"{best}ip/{ip}"

    def domain(self, domain: str, now: datetime) -> DomainInfo:
        try:
            url = self.domain_url(domain)
            data = self.fetch(url)
            if not isinstance(data, dict):
                raise LiveError("unexpected RDAP response")
            info = parse_domain(domain, data, now)
            info.source = url
            return info
        except LiveError as exc:
            return DomainInfo(domain=domain, error=str(exc))
        except Exception as exc:  # a malformed registry response must not stop the analysis
            return DomainInfo(domain=domain, error=f"could not read RDAP response ({type(exc).__name__})")

    def ip(self, ip: str) -> IpInfo:
        try:
            url = self.ip_url(ip)
            data = self.fetch(url)
            if not isinstance(data, dict):
                raise LiveError("unexpected RDAP response")
            info = parse_ip(ip, data)
            info.source = url
            return info
        except LiveError as exc:
            return IpInfo(ip=ip, error=str(exc))
        except Exception as exc:
            return IpInfo(ip=ip, error=f"could not read RDAP response ({type(exc).__name__})")


# ---------- what to look up ----------

def _skip_domains(config: Config) -> set[str]:
    skip = {org_domain(d) for d in config.watched_domains + config.freemail_domains}
    for sender, family in config.platform_link_domains.items():
        skip.add(org_domain(sender))
        skip.update(org_domain(d) for d in family)
    skip.discard(None)
    return skip


def targets(parsed, config: Config) -> tuple[list[str], list[str]]:
    """Registrable domains and public IPs worth looking up, in priority order."""
    from .checks.hops import boundary_hop          # local imports avoid a cycle at load time
    from .checks.platform import authentic_platform

    skip = _skip_domains(config)
    domains: list[str] = []

    def add(d: str | None):
        od = org_domain(d) if d else None
        if od and od not in skip and od not in domains and not classify_ip(od):
            domains.append(od)

    for a in [parsed.from_, parsed.return_path, parsed.sender, *parsed.reply_to]:
        if a:
            add(a.domain)
    if parsed.body:
        for host in parsed.body.link_domains:
            add(host)
        if authentic_platform(parsed, config):
            recipients = {r.address for r in parsed.recipients}
            for addr in parsed.body.addresses:
                if addr not in recipients:
                    add(addr.rsplit("@", 1)[1])

    ips: list[str] = []
    candidates = []
    hop = boundary_hop(parsed, config)
    if hop and hop.from_ip:
        candidates.append(hop.from_ip)
    if parsed.x_originating_ip:
        candidates.append(parsed.x_originating_ip)
    if parsed.body:
        candidates.extend(h for h in parsed.body.link_domains if classify_ip(h))
    for ip in candidates:
        if classify_ip(ip) == "public" and ip not in ips:
            ips.append(ip)

    return domains[:MAX_DOMAINS], ips[:MAX_IPS]


def run_lookups(parsed, config: Config, rdap: Rdap | None = None,
                now: datetime | None = None) -> LiveResults:
    rdap = rdap or Rdap()
    now = now or datetime.now(timezone.utc)
    domains, ips = targets(parsed, config)
    results = LiveResults()
    try:
        results.domains = [rdap.domain(d, now) for d in domains]
        results.ips = [rdap.ip(ip) for ip in ips]
    except Exception as exc:  # never let a lookup problem stop the analysis
        results.notes.append(f"live lookups stopped: {type(exc).__name__}")
    if not domains and not ips:
        results.notes.append("nothing to look up (only well-known or private domains and IPs)")
    return results
