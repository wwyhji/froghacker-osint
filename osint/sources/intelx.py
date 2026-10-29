"""intelx — Intelligence X 暗网/泄露搜索 (付费 INTELX_API_KEY)。

两阶段 API (header ``x-key``):
  1. POST https://2.intelx.io/intelligent/search  body {"term": ...}  -> {id}
  2. GET  https://2.intelx.io/intelligent/search/result?id=<id>&limit=N -> {records[]}
每条 record 的 bucket 指示泄露来源分类。
"""
from __future__ import annotations

from . import SourceAdapter, register
from ..artifacts import OsintArtifact
from ..http_client import safe_post_json, safe_get_json


@register
class IntelxAdapter(SourceAdapter):
    name = "intelx"
    entity_types = ("email", "domain", "ip", "phone", "username")
    paid = True
    env_key = "INTELX_API_KEY"
    polite_delay = 2.0

    def collect(self, target, entity_type="", limit=20):
        search = safe_post_json(
            "https://2.intelx.io/intelligent/search",
            json={"term": target, "maxresults": limit, "media": 0, "sort": 2},
            key_name=self.env_key, key_header="x-key",
        )
        if not isinstance(search, dict) or not search.get("id"):
            return []
        result = safe_get_json(
            "https://2.intelx.io/intelligent/search/result",
            params={"id": search["id"], "limit": limit},
            key_name=self.env_key, key_header="x-key",
        )
        if not isinstance(result, dict):
            return []
        arts: list[OsintArtifact] = []
        for rec in (result.get("records") or [])[:limit]:
            if not isinstance(rec, dict):
                continue
            bucket = rec.get("bucket") or "unknown"
            name = rec.get("name") or bucket
            arts.append(OsintArtifact(
                source=self.name, entity_type="breach", value=name, label=bucket,
                raw=rec,
                evidence=f"intelx {target} -> {bucket}",
                confidence="medium",
            ))
        return arts
