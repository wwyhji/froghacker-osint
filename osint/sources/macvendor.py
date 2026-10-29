"""macvendor — 免费无 key MAC OUI 厂商查询 (api.macvendors.com)。

mac 实体: https://api.macvendors.com/{mac} -> 纯文本厂商名。
图边: mac -> org
"""
from __future__ import annotations

from . import SourceAdapter, register
from ..artifacts import OsintArtifact
from ..http_client import safe_get_text


@register
class MacVendorAdapter(SourceAdapter):
    name = "macvendor"
    entity_types = ("mac",)
    paid = False
    polite_delay = 1.0
    rate_limit = (1, 1)  # 1/s + 1000/day (official free tier)

    def collect(self, target, entity_type="", limit=20):
        vendor = safe_get_text(f"https://api.macvendors.com/{target}")
        if not vendor:
            return []
        vendor = vendor.strip()
        if not vendor or "error" in vendor.lower() or "no vendor" in vendor.lower():
            return []

        mac = target
        arts: list[OsintArtifact] = [OsintArtifact(
            source=self.name, entity_type="mac", value=mac, label=mac,
            raw={"vendor": vendor},
            evidence=f"macvendors {mac}",
            confidence="high",
        )]
        arts.append(OsintArtifact(
            source=self.name, entity_type="org", value=vendor, label=vendor,
            raw={"mac": mac},
            evidence=f"macvendors {mac} -> {vendor}",
            confidence="high",
        ))
        return arts
