"""emailrep — 邮箱信誉 (复用 email_lookup._check_emailrep, 免费无 key)。"""
from __future__ import annotations

from . import SourceAdapter, register
from ..artifacts import OsintArtifact


@register
class EmailrepAdapter(SourceAdapter):
    name = "emailrep"
    entity_types = ("email",)
    polite_delay = 1.0
    rate_limit = (1, 1)  # unverified, conservative 1/s

    def collect(self, target, entity_type="", limit=20):
        from ..email_lookup import _check_emailrep

        r = _check_emailrep(target)
        if not r:
            return []
        suspicious = bool(r.blacklisted or r.malicious or r.suspicious)
        return [OsintArtifact(
            source=self.name, entity_type="email", value=target, label=target,
            raw={
                "reputation": r.reputation, "suspicious": r.suspicious,
                "blacklisted": r.blacklisted, "malicious": r.malicious,
                "spam": r.spam, "description": r.details,
            },
            evidence=f"emailrep.io/{target}",
            confidence="high" if suspicious else "medium",
        )]
