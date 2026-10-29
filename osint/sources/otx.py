"""otx — AlienVault OTX 被动 DNS (免费无 key, 公共 indicator 端点)。"""
from __future__ import annotations

from . import SourceAdapter, register
from ..artifacts import OsintArtifact
from ..http_client import safe_get_json


@register
class OtxAdapter(SourceAdapter):
    name = "otx"
    entity_types = ("domain", "ip")
    polite_delay = 1.5
    rate_limit = (1, 1)  # unverified, conservative 1/s

    def collect(self, target, entity_type="", limit=20):
        kind = entity_type or "domain"
        data = safe_get_json(
            f"https://otx.alienvault.com/api/v1/indicators/{kind}/{target}/passive_dns"
        )
        if not isinstance(data, dict):
            return []
        arts: list[OsintArtifact] = []
        for rec in (data.get("passive_dns") or [])[:limit]:
            host = rec.get("hostname", "")
            ip = rec.get("address", "")
            if host and host != target:
                arts.append(OsintArtifact(
                    source=self.name, entity_type="subdomain", value=host, label=host,
                    raw={"parent": target, "ip": ip},
                    evidence=f"OTX passive DNS {target}",
                    confidence="medium",
                ))
            if ip:
                arts.append(OsintArtifact(
                    source=self.name, entity_type="ip", value=ip, label=ip,
                    raw={"hostname": host},
                    evidence=f"OTX passive DNS {target}",
                    confidence="medium",
                ))
        return arts
