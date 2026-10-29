"""chainabuse — 勒索/欺诈/钓鱼地址报告 (免费无 key, Chainalysis Chainabuse)。

GET https://api.chainabuse.com/v0/reports?address=<addr>
返回报告列表, 每条含 category (ransomware/scam/darknet_market/...)。
"""
from __future__ import annotations

from . import SourceAdapter, register
from ..artifacts import OsintArtifact
from ..http_client import safe_get_json


@register
class ChainabuseAdapter(SourceAdapter):
    name = "chainabuse"
    entity_types = ("crypto_address",)
    paid = False
    polite_delay = 1.0
    rate_limit = (1, 1)  # unverified, conservative 1/s

    def collect(self, target, entity_type="", limit=20):
        data = safe_get_json(
            "https://api.chainabuse.com/v0/reports",
            params={"address": target},
        )
        # 兼容 list 或 {"reports": [...]} 两种返回形态
        if isinstance(data, list):
            reports = data
        elif isinstance(data, dict):
            reports = data.get("reports") or data.get("data") or []
        else:
            return []
        arts: list[OsintArtifact] = [OsintArtifact(
            source=self.name, entity_type="crypto_address", value=target, label=target,
            raw={"report_count": len(reports)}, evidence=f"chainabuse {target}",
            confidence="medium",
        )]
        for r in reports[:limit]:
            if not isinstance(r, dict):
                continue
            cat = r.get("category") or r.get("abuse_type") or ""
            if cat:
                arts.append(OsintArtifact(
                    source=self.name, entity_type="breach", value=cat, label=cat,
                    raw={"address": target, "category": cat},
                    evidence=f"chainabuse {target} -> {cat}",
                    confidence="medium",
                ))
        return arts
