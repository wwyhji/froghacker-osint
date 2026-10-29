"""leakix — 泄露数据搜索引擎 (免费注册 key LEAKIX_API_KEY)。

Search API: GET https://leakix.net/api/v1/search?scope=leak&q=<query>  (header ``api-key``)。
返回 items[], 每条含 ip/host/port/protocol/event_type。
"""
from __future__ import annotations

from . import SourceAdapter, register
from ..artifacts import OsintArtifact
from ..http_client import safe_get_json


@register
class LeakixAdapter(SourceAdapter):
    name = "leakix"
    entity_types = ("email", "domain", "ip", "username")
    paid = True
    env_key = "LEAKIX_API_KEY"
    polite_delay = 1.5

    def collect(self, target, entity_type="", limit=20):
        data = safe_get_json(
            "https://leakix.net/api/v1/search",
            params={"scope": "leak", "q": target},
            key_name=self.env_key, key_header="api-key",
        )
        if not isinstance(data, dict):
            return []
        arts: list[OsintArtifact] = []
        for item in (data.get("items") or [])[:limit]:
            if not isinstance(item, dict):
                continue
            host = item.get("host") or ""
            ip = item.get("ip") or ""
            event_type = item.get("event_type") or item.get("service") or "leak"
            ev = f"leakix {target} -> {event_type}"
            if host:
                etype = "domain" if host.count(".") == 1 else "subdomain"
                arts.append(OsintArtifact(
                    source=self.name, entity_type=etype, value=host, label=host,
                    raw=item, evidence=ev, confidence="medium",
                ))
            if ip:
                arts.append(OsintArtifact(
                    source=self.name, entity_type="ip", value=ip, label=ip,
                    raw=item, evidence=ev, confidence="medium",
                ))
            if not host and not ip and event_type:
                arts.append(OsintArtifact(
                    source=self.name, entity_type="breach", value=event_type,
                    label=event_type, raw=item, evidence=ev, confidence="low",
                ))
        return arts
