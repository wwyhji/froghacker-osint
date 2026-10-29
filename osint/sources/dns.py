"""dns — DNS 记录 (复用 domain_intel._query_dns)。"""
from __future__ import annotations

from . import SourceAdapter, register
from ..artifacts import OsintArtifact


@register
class DnsAdapter(SourceAdapter):
    name = "dns"
    entity_types = ("domain", "subdomain")
    polite_delay = 1.0

    def collect(self, target, entity_type="", limit=20):
        from ..domain_intel import _query_dns

        recs = _query_dns(target) or []
        return [
            OsintArtifact(
                source=self.name, entity_type="dns_record", value=rec.value,
                label=f"{rec.type} record",
                raw={"domain": target, "record_type": rec.type, "value": rec.value},
                evidence=f"DNS {rec.type} {target}",
                confidence="high",
            )
            for rec in recs[:limit]
        ]
