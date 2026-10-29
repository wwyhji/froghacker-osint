"""securitytrails — 子域名枚举 (付费 key SECURITYTRAILS_API_KEY)。"""
from __future__ import annotations

from . import SourceAdapter, register
from ..artifacts import OsintArtifact
from ..http_client import safe_get_json


@register
class SecuritytrailsAdapter(SourceAdapter):
    name = "securitytrails"
    entity_types = ("domain",)
    paid = True
    env_key = "SECURITYTRAILS_API_KEY"
    polite_delay = 1.0

    def collect(self, target, entity_type="", limit=20):
        data = safe_get_json(
            f"https://api.securitytrails.com/v1/domain/{target}/subdomains",
            key_name=self.env_key, key_header="APIKEY",
        )
        if not isinstance(data, dict):
            return []
        arts: list[OsintArtifact] = []
        for sub in (data.get("subdomains") or [])[:limit]:
            fqdn = f"{sub}.{target}"
            arts.append(OsintArtifact(
                source=self.name, entity_type="subdomain", value=fqdn, label=fqdn,
                raw={"parent": target}, evidence=f"securitytrails {target}",
                confidence="high",
            ))
        return arts
