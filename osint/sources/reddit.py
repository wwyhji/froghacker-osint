"""reddit — Reddit 用户深度情报 (免费无 key, 公开 JSON API)。

GET https://www.reddit.com/user/{username}/about.json -> karma/注册时间/头像。
"""
from __future__ import annotations

from . import SourceAdapter, register
from ..artifacts import OsintArtifact
from ..http_client import safe_get_json


@register
class RedditAdapter(SourceAdapter):
    name = "reddit"
    entity_types = ("username",)
    paid = False
    polite_delay = 1.0
    rate_limit = (1, 1)  # public JSON rate-limited

    def collect(self, target, entity_type="", limit=20):
        data = safe_get_json(
            f"https://www.reddit.com/user/{target}/about.json",
        )
        if not isinstance(data, dict):
            return []
        d = data.get("data") or {}
        if not d:
            return []
        return [OsintArtifact(
            source=self.name, entity_type="social_profile", value=target, label=target,
            raw={
                "platform": "reddit",
                "username": target,
                "link_karma": d.get("link_karma"),
                "comment_karma": d.get("comment_karma"),
                "created_utc": d.get("created_utc"),
                "icon_img": d.get("icon_img"),
            },
            evidence=f"reddit.com/user/{target}",
            confidence="high",
        )]
