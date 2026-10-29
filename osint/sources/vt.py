"""vt — VirusTotal 域名/IP 情报 (付费 key VT_API_KEY)。"""
from __future__ import annotations

from . import SourceAdapter, register
from ..artifacts import OsintArtifact
from ..http_client import safe_get_json


@register
class VirusTotalAdapter(SourceAdapter):
    name = "vt"
    entity_types = ("domain", "ip")
    paid = True
    env_key = "VT_API_KEY"
    polite_delay = 1.0

    def collect(self, target, entity_type="", limit=20):
        kind = entity_type or "domain"
        data = safe_get_json(
            f"https://www.virustotal.com/api/v3/{kind}s/{target}",
            key_name=self.env_key, key_header="x-apikey",
        )
        if not isinstance(data, dict):
            return []
        attrs = data.get("data", {}).get("attributes", {})
        arts: list[OsintArtifact] = []
        if kind == "domain":
            for r in (attrs.get("last_dns_records") or [])[:limit]:
                val = r.get("value", "")
                rt = (r.get("type") or "").upper()
                if val and rt in ("A", "AAAA", "CNAME"):
                    arts.append(OsintArtifact(
                        source=self.name, entity_type="dns_record", value=val,
                        label=f"{rt} record",
                        raw={"domain": target, "record_type": rt, "value": val},
                        evidence=f"virustotal {target}",
                        confidence="high",
                    ))
        return arts
