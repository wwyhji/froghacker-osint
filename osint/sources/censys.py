"""censys — 主机/ASN 情报 (付费 CENSYS_API_ID + CENSYS_API_SECRET)。"""
from __future__ import annotations

from . import SourceAdapter, register
from ..artifacts import OsintArtifact
from ..http_client import get_key, safe_get_json


@register
class CensysAdapter(SourceAdapter):
    name = "censys"
    entity_types = ("ip",)
    paid = True
    env_key = "CENSYS_API_ID"
    extra_keys = ("CENSYS_API_SECRET",)
    polite_delay = 1.5

    def collect(self, target, entity_type="", limit=20):
        data = safe_get_json(
            f"https://search.censys.io/api/v2/hosts/{target}",
            auth=(get_key("CENSYS_API_ID"), get_key("CENSYS_API_SECRET")),
        )
        if not isinstance(data, dict):
            return []
        host = data.get("result", data)
        asn = (host.get("autonomous_system") or {}).get("asn")
        arts: list[OsintArtifact] = []
        if asn:
            arts.append(OsintArtifact(
                source=self.name, entity_type="asn", value=f"AS{asn}", label=f"AS{asn}",
                raw={"ip": target}, evidence=f"censys {target}",
                confidence="high",
            ))
        return arts
