"""shodan — Shodan DNS/主机情报 (付费 key SHODAN_API_KEY)。"""
from __future__ import annotations

from . import SourceAdapter, register
from ..artifacts import OsintArtifact
from ..http_client import get_key, safe_get_json


@register
class ShodanAdapter(SourceAdapter):
    name = "shodan"
    entity_types = ("domain", "ip")
    paid = True
    env_key = "SHODAN_API_KEY"
    polite_delay = 1.0

    def collect(self, target, entity_type="", limit=20):
        if entity_type == "ip":
            return self._host(target, limit)
        return self._domain(target, limit)

    def _host(self, ip: str, limit: int) -> list[OsintArtifact]:
        data = safe_get_json(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": get_key(self.env_key)},
        )
        if not isinstance(data, dict):
            return []
        return [
            OsintArtifact(
                source=self.name, entity_type="domain", value=hn, label=hn,
                raw={"reverse_ip": ip}, evidence=f"shodan host {ip}",
                confidence="high",
            )
            for hn in (data.get("hostnames") or [])[:limit] if hn
        ]

    def _domain(self, domain: str, limit: int) -> list[OsintArtifact]:
        data = safe_get_json(
            f"https://api.shodan.io/dns/domain/{domain}",
            params={"key": get_key(self.env_key)},
        )
        if not isinstance(data, dict):
            return []
        arts: list[OsintArtifact] = []
        for sub in (data.get("subdomains") or [])[:limit]:
            fqdn = f"{sub}.{domain}"
            arts.append(OsintArtifact(
                source=self.name, entity_type="subdomain", value=fqdn, label=fqdn,
                raw={"parent": domain}, evidence=f"shodan dns {domain}",
                confidence="high",
            ))
        return arts
