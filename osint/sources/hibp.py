"""hibp — HaveIBeenPwned 泄露查询 (付费 key HIBP_API_KEY)。"""
from __future__ import annotations

from . import SourceAdapter, register
from ..artifacts import OsintArtifact
from ..http_client import safe_get_json


@register
class HibpAdapter(SourceAdapter):
    name = "hibp"
    entity_types = ("email",)
    paid = True
    env_key = "HIBP_API_KEY"
    polite_delay = 1.5

    def collect(self, target, entity_type="", limit=20):
        data = safe_get_json(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{target}",
            key_name=self.env_key, key_header="hibp-api-key",
            params={"truncateResponse": "false"},
        )
        if not isinstance(data, list):
            return []
        return [
            OsintArtifact(
                source=self.name, entity_type="breach", value=b.get("Name", ""),
                label=b.get("Title", b.get("Name", "")), raw=b,
                evidence=f"HIBP 泄露 {b.get('Name', '')}",
                confidence="high",
            )
            for b in data[:limit] if b.get("Name")
        ]
