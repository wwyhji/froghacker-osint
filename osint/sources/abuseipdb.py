"""abuseipdb — 恶意 IP 信誉 (付费 key ABUSEIPDB_API_KEY)。"""
from __future__ import annotations

from . import SourceAdapter, register
from ..artifacts import OsintArtifact
from ..http_client import safe_get_json


@register
class AbuseipdbAdapter(SourceAdapter):
    name = "abuseipdb"
    entity_types = ("ip",)
    paid = True
    env_key = "ABUSEIPDB_API_KEY"
    polite_delay = 1.0

    def collect(self, target, entity_type="", limit=20):
        data = safe_get_json(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": target, "maxAgeInDays": "90"},
            key_name=self.env_key, key_header="Key",
        )
        if not isinstance(data, dict):
            return []
        d = data.get("data") or {}
        if not d:
            return []
        score = d.get("abuseConfidenceScore", 0)
        return [OsintArtifact(
            source=self.name, entity_type="ip", value=target, label=target, raw=d,
            evidence=f"abuseipdb {target}",
            confidence="high" if score > 50 else "medium",
        )]
