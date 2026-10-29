"""urlscan — urlscan.io 搜索 (免费无 key, 限速)。"""
from __future__ import annotations

from . import SourceAdapter, register
from ..artifacts import OsintArtifact
from ..http_client import safe_get_json


@register
class UrlscanAdapter(SourceAdapter):
    name = "urlscan"
    entity_types = ("domain", "ip", "url")
    polite_delay = 1.5
    rate_limit = (20, 60)  # ~20/min unauth + 500/day

    def collect(self, target, entity_type="", limit=20):
        q = f"domain:{target}" if entity_type in ("domain", "subdomain", "") else target
        data = safe_get_json(
            "https://urlscan.io/api/v1/search/",
            params={"q": q, "size": min(limit, 100)},
        )
        if not isinstance(data, dict):
            return []
        arts: list[OsintArtifact] = []
        for r in (data.get("results") or [])[:limit]:
            page = r.get("page") or {}
            dom = page.get("domain", "")
            ip = page.get("ip", "")
            url = page.get("url", "") or (r.get("task") or {}).get("url", "")
            if dom:
                arts.append(OsintArtifact(
                    source=self.name, entity_type="domain", value=dom, label=dom,
                    raw={"ip": ip}, evidence=f"urlscan.io 扫描 {target}",
                    confidence="high",
                ))
            if ip:
                arts.append(OsintArtifact(
                    source=self.name, entity_type="ip", value=ip, label=ip,
                    raw={"domain": dom}, evidence=f"urlscan.io 扫描 {target}",
                    confidence="high",
                ))
            if url:
                arts.append(OsintArtifact(
                    source=self.name, entity_type="url", value=url, label=url,
                    raw={"domain": dom}, evidence=f"urlscan.io 扫描 {target}",
                    confidence="medium",
                ))
        return arts
