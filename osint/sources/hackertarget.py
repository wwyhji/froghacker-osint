"""hackertarget — 免费无 key 子域名/反查 IP (纯文本 API)。"""
from __future__ import annotations

from . import SourceAdapter, register
from ..artifacts import OsintArtifact
from ..http_client import safe_get_text


@register
class HackerTargetAdapter(SourceAdapter):
    name = "hackertarget"
    entity_types = ("domain", "subdomain", "ip")
    polite_delay = 1.0
    rate_limit = (50, 86400)  # ~50/day/IP (conservative vs 200 official)

    def collect(self, target, entity_type="", limit=20):
        if entity_type == "ip":
            return self._reverse_ip(target, limit)
        return self._hostsearch(target, limit)

    def _hostsearch(self, domain: str, limit: int) -> list[OsintArtifact]:
        text = safe_get_text("https://api.hackertarget.com/hostsearch/", params={"q": domain})
        if not text:
            return []
        arts: list[OsintArtifact] = []
        for line in text.splitlines()[:limit]:
            if not line or "error" in line.lower() or "api count exceeded" in line.lower():
                continue
            parts = line.split(",")
            host = parts[0].strip() if parts else ""
            ip = parts[1].strip() if len(parts) > 1 else ""
            if host:
                arts.append(OsintArtifact(
                    source=self.name, entity_type="subdomain", value=host, label=host,
                    raw={"parent": domain, "ip": ip},
                    evidence=f"hackertarget hostsearch {domain}",
                    confidence="high",
                ))
            if ip:
                arts.append(OsintArtifact(
                    source=self.name, entity_type="ip", value=ip, label=ip,
                    raw={"hostname": host, "domain": domain},
                    evidence=f"hackertarget hostsearch {domain}",
                    confidence="high",
                ))
        return arts

    def _reverse_ip(self, ip: str, limit: int) -> list[OsintArtifact]:
        text = safe_get_text("https://api.hackertarget.com/reverseiplookup/", params={"q": ip})
        if not text:
            return []
        arts: list[OsintArtifact] = []
        for line in text.splitlines()[:limit]:
            dom = line.strip()
            if not dom or "error" in dom.lower() or "api count exceeded" in dom.lower():
                continue
            arts.append(OsintArtifact(
                source=self.name, entity_type="domain", value=dom, label=dom,
                raw={"reverse_ip": ip},
                evidence=f"hackertarget reverseiplookup {ip}",
                confidence="medium",
            ))
        return arts
