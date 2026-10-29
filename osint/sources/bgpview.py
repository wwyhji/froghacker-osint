"""bgpview — 免费无 key ASN/BGP 网络情报 (api.bgpview.io)。

ip 实体:  /ip/{ip}          -> {asn, org, country, prefix}
asn 实体: /asn/{asn}        -> 元数据 (org/country); /asn/{asn}/prefixes -> 前缀列表
图边: ip -> asn -> org
"""
from __future__ import annotations

from . import SourceAdapter, register
from ..artifacts import OsintArtifact
from ..http_client import safe_get_json


@register
class BgpViewAdapter(SourceAdapter):
    name = "bgpview"
    entity_types = ("asn", "ip")
    paid = False
    polite_delay = 1.0
    rate_limit = (2, 1)  # no hard limit, CF-throttled, ~3 RPS community

    def collect(self, target, entity_type="", limit=20):
        kind = entity_type or ("asn" if str(target).upper().startswith("AS") else "ip")
        if kind == "asn":
            return self._asn(target, limit)
        return self._ip(target, limit)

    def _ip(self, ip: str, limit: int) -> list[OsintArtifact]:
        data = safe_get_json(f"https://api.bgpview.io/ip/{ip}")
        if not isinstance(data, dict):
            return []
        d = data.get("data") or {}
        prefixes = d.get("prefixes") or []
        first = prefixes[0] if prefixes else {}
        asn_info = first.get("asn") or {}
        asn_num = asn_info.get("asn")
        asn = f"AS{asn_num}" if asn_num is not None else ""
        org = asn_info.get("name") or ""
        country = asn_info.get("country_code") or ""
        prefix = first.get("prefix") or ""

        arts: list[OsintArtifact] = [OsintArtifact(
            source=self.name, entity_type="ip", value=ip, label=ip,
            raw={"asn": asn, "org": org, "country": country, "prefix": prefix},
            evidence=f"bgpview ip {ip}",
            confidence="high",
        )]
        if asn:
            arts.append(OsintArtifact(
                source=self.name, entity_type="asn", value=asn, label=asn,
                raw={"org": org, "country": country, "ip": ip},
                evidence=f"bgpview ip {ip} -> {asn}",
                confidence="high",
            ))
        if org:
            arts.append(OsintArtifact(
                source=self.name, entity_type="org", value=org, label=org,
                raw={"asn": asn, "ip": ip},
                evidence=f"bgpview ip {ip} org",
                confidence="medium",
            ))
        return arts

    def _asn(self, asn: str, limit: int) -> list[OsintArtifact]:
        num = str(asn).upper().lstrip("AS")
        meta = safe_get_json(f"https://api.bgpview.io/asn/{num}")
        prefixes_data = safe_get_json(f"https://api.bgpview.io/asn/{num}/prefixes")

        d = (meta.get("data") if isinstance(meta, dict) else None) or {}
        org = d.get("name") or ""
        country = d.get("country_code") or ""

        prefixes: list[str] = []
        if isinstance(prefixes_data, dict):
            pd = prefixes_data.get("data") or {}
            for key in ("ipv4_prefixes", "ipv6_prefixes"):
                for p in pd.get(key, []) or []:
                    if isinstance(p, dict) and p.get("prefix"):
                        prefixes.append(p["prefix"])

        value = f"AS{num}"
        arts: list[OsintArtifact] = [OsintArtifact(
            source=self.name, entity_type="asn", value=value, label=value,
            raw={"org": org, "country": country, "prefixes": prefixes[:limit]},
            evidence=f"bgpview asn {value}",
            confidence="high",
        )]
        if org:
            arts.append(OsintArtifact(
                source=self.name, entity_type="org", value=org, label=org,
                raw={"asn": value},
                evidence=f"bgpview asn {value} org",
                confidence="high",
            ))
        return arts
