"""dehashed — 泄露数据库聚合查询 (付费 DEHASHED_EMAIL + DEHASHED_API_KEY)。

Search API: GET https://api.dehashed.com/search?query=<query>  (HTTP Basic Auth: email:key)。
返回 entries[], 每条含 email/username/name/ip_address/database_name。

安全: 只提取元数据字段 (email/username/person/ip/breach)，刻意跳过 password/
hashed_password 等凭据，避免明文泄露进入 artifact/KB。
"""
from __future__ import annotations

from . import SourceAdapter, register
from ..artifacts import OsintArtifact
from ..http_client import get_key, safe_get_json


@register
class DehashedAdapter(SourceAdapter):
    name = "dehashed"
    entity_types = ("email", "username", "domain", "ip", "phone")
    paid = True
    env_key = "DEHASHED_API_KEY"
    extra_keys = ("DEHASHED_EMAIL",)
    polite_delay = 1.5

    def collect(self, target, entity_type="", limit=20):
        data = safe_get_json(
            "https://api.dehashed.com/search",
            params={"query": target},
            auth=(get_key("DEHASHED_EMAIL"), get_key("DEHASHED_API_KEY")),
        )
        if not isinstance(data, dict):
            return []
        arts: list[OsintArtifact] = []
        for entry in (data.get("entries") or [])[:limit]:
            if not isinstance(entry, dict):
                continue
            db = entry.get("database_name") or "unknown"
            ev = f"dehashed {target} -> {db}"
            # 仅元数据字段; 凭据 (password/hashed_password) 刻意忽略
            email = entry.get("email")
            username = entry.get("username")
            name = entry.get("name")
            ip = entry.get("ip_address")
            if email:
                arts.append(OsintArtifact(
                    source=self.name, entity_type="email", value=email, label=email,
                    raw={"database_name": db}, evidence=ev, confidence="high",
                ))
            if username:
                arts.append(OsintArtifact(
                    source=self.name, entity_type="username", value=username, label=username,
                    raw={"database_name": db}, evidence=ev, confidence="high",
                ))
            if name:
                arts.append(OsintArtifact(
                    source=self.name, entity_type="person", value=name, label=name,
                    raw={"database_name": db}, evidence=ev, confidence="medium",
                ))
            if ip:
                arts.append(OsintArtifact(
                    source=self.name, entity_type="ip", value=ip, label=ip,
                    raw={"database_name": db}, evidence=ev, confidence="medium",
                ))
            if not any((email, username, name, ip)):
                arts.append(OsintArtifact(
                    source=self.name, entity_type="breach", value=db, label=db,
                    raw={}, evidence=ev, confidence="low",
                ))
        return arts
