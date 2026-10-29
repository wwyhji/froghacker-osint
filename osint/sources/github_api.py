"""github_api — GitHub 用户/组织查询 (免费无 key, 60 req/h 限速)。"""
from __future__ import annotations

from . import SourceAdapter, register
from ..artifacts import OsintArtifact
from ..http_client import safe_get_json


@register
class GithubApiAdapter(SourceAdapter):
    name = "github_api"
    entity_types = ("username", "org")
    polite_delay = 1.0
    rate_limit = (60, 3600)  # 60 req/h unauthenticated (official)

    def collect(self, target, entity_type="", limit=20):
        kind = entity_type or "username"
        seg = "orgs" if kind == "org" else "users"
        data = safe_get_json(
            f"https://api.github.com/{seg}/{target}",
            headers={"Accept": "application/vnd.github+json"},
        )
        if not isinstance(data, dict) or "login" not in data:
            return []

        login = data.get("login", target)
        arts: list[OsintArtifact] = [OsintArtifact(
            source=self.name, entity_type=kind, value=login, label=login,
            raw=data, evidence=f"github.com/{login}",
            confidence="high",
        )]
        if data.get("name"):
            arts.append(OsintArtifact(
                source=self.name, entity_type="person", value=data["name"], label=data["name"],
                raw={"username": login}, evidence=f"github 用户 {login}",
                confidence="medium",
            ))
        if data.get("company"):
            arts.append(OsintArtifact(
                source=self.name, entity_type="org", value=data["company"].lstrip("@"),
                label=data["company"], raw={"username": login},
                evidence=f"github 用户 {login} company",
                confidence="low",
            ))
        if data.get("blog"):
            arts.append(OsintArtifact(
                source=self.name, entity_type="url", value=data["blog"], label=data["blog"],
                raw={"username": login}, evidence=f"github 用户 {login} blog",
                confidence="medium",
            ))
        return arts
