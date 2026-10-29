"""wayback — Wayback Machine 历史快照 (复用 domain_intel._query_wayback)。"""
from __future__ import annotations

from . import SourceAdapter, register
from ..artifacts import OsintArtifact


@register
class WaybackAdapter(SourceAdapter):
    name = "wayback"
    entity_types = ("domain", "subdomain")
    polite_delay = 1.0
    rate_limit = (1, 1)  # polite 1/s

    def collect(self, target, entity_type="", limit=20):
        from ..domain_intel import _query_wayback

        snaps = _query_wayback(target, max_results=limit) or []
        return [
            OsintArtifact(
                source=self.name, entity_type="url", value=snap.url, label=snap.url,
                raw={
                    "timestamp": snap.timestamp,
                    "status_code": snap.status_code,
                    "snapshot_url": snap.snapshot_url,
                },
                evidence=snap.snapshot_url,
                confidence="medium",
            )
            for snap in snaps
        ]
