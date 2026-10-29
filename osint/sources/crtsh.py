"""crtsh — 证书透明度日志 (复用 domain_intel._query_crtsh)。"""
from __future__ import annotations

from . import SourceAdapter, register
from ..artifacts import OsintArtifact


@register
class CrtshAdapter(SourceAdapter):
    name = "crtsh"
    entity_types = ("domain", "subdomain")
    polite_delay = 1.0  # _query_crtsh 内部已有 3s 延迟

    def collect(self, target, entity_type="", limit=20):
        from ..domain_intel import _query_crtsh

        certs = _query_crtsh(target) or []
        arts: list[OsintArtifact] = []
        for c in certs[:limit]:
            cn = c.common_name or ""
            if cn:
                arts.append(OsintArtifact(
                    source=self.name, entity_type="cert", value=cn, label=cn,
                    raw=c.to_dict(),
                    evidence=f"crt.sh 证书透明度: {target}",
                    confidence="high",
                ))
            for s in (c.subdomains or [])[:limit]:
                arts.append(OsintArtifact(
                    source=self.name, entity_type="subdomain", value=s, label=s,
                    raw={"parent": target, "common_name": cn},
                    evidence=f"crt.sh 证书 SAN: {cn or target}",
                    confidence="high",
                ))
        return arts
