"""greynoise — 互联网噪声/扫描器 IP 分类 (社区版免费 key GREYNOISE_API_KEY)。

Community API: GET https://api.greynoise.io/v3/community/{ip}  (header ``key``)。
返回 classification (malicious/benign/unknown) + 标签/组织。
"""
from __future__ import annotations

from . import SourceAdapter, register
from ..artifacts import OsintArtifact
from ..http_client import safe_get_json


@register
class GreynoiseAdapter(SourceAdapter):
    name = "greynoise"
    entity_types = ("ip",)
    paid = True
    env_key = "GREYNOISE_API_KEY"
    polite_delay = 1.0

    def collect(self, target, entity_type="", limit=20):
        data = safe_get_json(
            f"https://api.greynoise.io/v3/community/{target}",
            key_name=self.env_key, key_header="key",
        )
        if not isinstance(data, dict):
            return []
        classification = data.get("classification") or "unknown"
        confidence = {"malicious": "high", "benign": "low"}.get(classification, "medium")
        arts: list[OsintArtifact] = [OsintArtifact(
            source=self.name, entity_type="ip", value=target, label=target,
            raw=data,
            evidence=f"greynoise community {target} -> {classification}",
            confidence=confidence,
        )]
        # 组织/ASN 标签
        meta = data.get("metadata") or {}
        org = meta.get("organization")
        if org:
            arts.append(OsintArtifact(
                source=self.name, entity_type="org", value=org, label=org,
                raw={"ip": target}, evidence=f"greynoise org {target}",
                confidence="medium",
            ))
        return arts
