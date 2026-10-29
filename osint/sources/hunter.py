"""hunter — Hunter.io 企业邮箱 (付费 key HUNTERIO_API_KEY)。"""
from __future__ import annotations

from . import SourceAdapter, register
from ..artifacts import OsintArtifact
from ..http_client import get_key, safe_get_json


@register
class HunterAdapter(SourceAdapter):
    name = "hunter"
    entity_types = ("domain",)
    paid = True
    env_key = "HUNTERIO_API_KEY"
    polite_delay = 1.0

    def collect(self, target, entity_type="", limit=20):
        data = safe_get_json(
            "https://api.hunter.io/v2/domain-search",
            params={"domain": target, "api_key": get_key(self.env_key), "limit": limit},
        )
        if not isinstance(data, dict):
            return []
        arts: list[OsintArtifact] = []
        for e in (data.get("data", {}).get("emails") or [])[:limit]:
            email = e.get("value", "")
            if email:
                arts.append(OsintArtifact(
                    source=self.name, entity_type="email", value=email, label=email,
                    raw=e, evidence=f"hunter.io domain-search {target}",
                    confidence="high",
                ))
        return arts
