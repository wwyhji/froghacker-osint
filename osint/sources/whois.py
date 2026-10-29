"""whois — 域名注册信息 (复用 domain_intel._query_whois)。"""
from __future__ import annotations

from . import SourceAdapter, register
from ..artifacts import OsintArtifact


@register
class WhoisAdapter(SourceAdapter):
    name = "whois"
    entity_types = ("domain",)
    polite_delay = 2.0  # _query_whois 内部已有 2s 延迟

    def collect(self, target, entity_type="", limit=20):
        from ..domain_intel import _query_whois

        info = _query_whois(target)
        if not info:
            return []
        domain = info.domain or target
        arts: list[OsintArtifact] = []
        if info.registrant_name:
            arts.append(OsintArtifact(
                source=self.name, entity_type="person", value=info.registrant_name,
                label=info.registrant_name, raw={"domain": domain},
                evidence=f"WHOIS {domain} registrant",
                confidence="medium",
            ))
        if info.registrant_org:
            arts.append(OsintArtifact(
                source=self.name, entity_type="org", value=info.registrant_org,
                label=info.registrant_org, raw={"domain": domain},
                evidence=f"WHOIS {domain} org",
                confidence="medium",
            ))
        if info.registrant_email:
            arts.append(OsintArtifact(
                source=self.name, entity_type="email", value=info.registrant_email,
                label=info.registrant_email, raw={"domain": domain},
                evidence=f"WHOIS {domain} email",
                confidence="medium",
            ))
        return arts
