"""username_search.py — 跨平台用户名搜索。

向 30+ 平台发送 HTTP 探针，检测指定用户名是否已注册。
每个平台配置了 URL 模板、预期状态码和"未找到"关键字检测。

用法:
    from osint.username_search import username_search
    result = username_search("johndoe")
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

import requests

# ── 平台配置 ────────────────────────────────────────────────────
# (name, url_template, expected_status, not_found_keywords)

PlatformConfig = tuple[str, str, int, Optional[str]]

PLATFORMS: list[PlatformConfig] = [
    ("GitHub",        "https://github.com/{username}",                 200, "Not Found"),
    ("Reddit",        "https://www.reddit.com/user/{username}",        200, "Page not found"),
    ("Instagram",     "https://www.instagram.com/{username}/",        200, "Sorry"),
    ("Medium",        "https://medium.com/@{username}",               200, "Page not found"),
    ("Dev.to",        "https://dev.to/{username}",                    200, "Page not found"),
    ("HackerNews",    "https://news.ycombinator.com/user?id={username}", 200, "No such user"),
    ("StackOverflow", "https://stackoverflow.com/users/{username}",   200, "Page not found"),
    ("Keybase",       "https://keybase.io/{username}",                200, "not found"),
    ("Telegram",      "https://t.me/{username}",                      200, "If you have Telegram"),
    ("Pinterest",     "https://www.pinterest.com/{username}/",        200, "Looking for something"),
    ("TikTok",        "https://www.tiktok.com/@{username}",           200, "Couldn't find this account"),
    ("YouTube",       "https://www.youtube.com/@{username}",          200, "This channel is not available"),
    ("Twitch",        "https://www.twitch.tv/{username}",             200, "Page not found"),
    ("Steam",         "https://steamcommunity.com/id/{username}",     200, "The specified profile could not be found"),
    ("GitLab",        "https://gitlab.com/{username}",                200, "Page not found"),
    ("BitBucket",     "https://bitbucket.org/{username}",             200, "This profile could not be found"),
    ("DockerHub",     "https://hub.docker.com/u/{username}",          200, "Not Found"),
    ("PyPI",          "https://pypi.org/user/{username}/",            200, "Page not found"),
    ("npm",           "https://www.npmjs.com/~{username}",            200, "not found"),
    ("Pastebin",      "https://pastebin.com/u/{username}",            200, "404 Not Found"),
    ("Replit",        "https://replit.com/@{username}",               200, "Page not found"),
    ("Behance",       "https://www.behance.net/{username}",           200, "Page not found"),
    ("Dribbble",      "https://dribbble.com/{username}",              200, "Page not found"),
    ("Flickr",        "https://www.flickr.com/people/{username}",     200, "Page not found"),
    ("Mastodon",      "https://mastodon.social/@{username}",          200, "Page not found"),
    ("Twitter",       "https://twitter.com/{username}",               200, "This account doesn't exist"),
    ("Snapchat",      "https://www.snapchat.com/add/{username}",      200, "Sorry! We couldn't find that user"),
    ("VK",            "https://vk.com/{username}",                    200, "Page not found"),
    ("Tumblr",        "https://{username}.tumblr.com",                200, "There's nothing here"),
    ("Bilibili",      "https://space.bilibili.com/{username}",        200, "页面不存在"),
    ("知乎",          "https://www.zhihu.com/people/{username}",      200, "404"),
    ("DeviantArt",    "https://www.deviantart.com/{username}",        200, "Page not found"),
    ("SoundCloud",    "https://soundcloud.com/{username}",            200, "Sorry"),
    ("Roblox",        "https://www.roblox.com/user.aspx?username={username}", 200, "Page cannot be found"),
    ("Bandcamp",      "https://{username}.bandcamp.com",              200, "Not Found"),
]

# 不可靠平台 — 总是返回 200 难以区分
UNRELIABLE_PLATFORMS: set[str] = {"Facebook", "LinkedIn"}

_REQUEST_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}


# ── Data Classes ────────────────────────────────────────────────


@dataclass
class PlatformResult:
    """单个平台的用户名搜索结果。"""
    platform: str = ""
    profile_url: str = ""
    exists: bool = False
    status_code: int = 0
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "platform": self.platform,
            "profile_url": self.profile_url,
            "exists": self.exists,
            "status_code": self.status_code,
            "error": self.error,
        }


@dataclass
class UsernameSearchResult:
    """聚合的用户名搜索结果。"""
    username: str = ""
    found_on: list[PlatformResult] = field(default_factory=list)
    not_found_on: list[PlatformResult] = field(default_factory=list)
    total_checked: int = 0
    total_found: int = 0
    search_time: float = 0.0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "username": self.username,
            "total_checked": self.total_checked,
            "total_found": self.total_found,
            "search_time": self.search_time,
            "found_on": [r.to_dict() for r in self.found_on],
            "not_found_on": [r.to_dict() for r in self.not_found_on],
            "errors": self.errors,
        }


# ── Internal Helpers ────────────────────────────────────────────


def _check_platform(
    username: str,
    config: PlatformConfig,
    timeout: int = 10,
    smart_check: bool = True,
) -> PlatformResult:
    """检查用户名在单个平台上是否存在。"""
    name, url_template, expected_status, not_found_hint = config
    profile_url = url_template.format(username=username)

    result = PlatformResult(
        platform=name,
        profile_url=profile_url,
    )

    try:
        resp = requests.get(
            profile_url,
            headers=_REQUEST_HEADERS,
            timeout=timeout,
            allow_redirects=True,
        )
        result.status_code = resp.status_code

        if resp.status_code == 429:
            result.error = "被限流 (429)"
            return result

        if resp.status_code == 403:
            result.error = "被禁止 (403)"
            return result

        if resp.status_code == 404:
            result.exists = False
            return result

        if resp.status_code == expected_status:
            if smart_check and not_found_hint:
                body = resp.text[:2000].lower()
                if not_found_hint.lower() in body:
                    result.exists = False
                    return result
            result.exists = True
        else:
            result.exists = resp.status_code < 400

    except requests.Timeout:
        result.error = "超时"
    except requests.ConnectionError:
        result.error = "连接失败"
    except requests.RequestException as e:
        result.error = str(e)

    return result


# ── Public API ──────────────────────────────────────────────────


def username_search(
    username: str,
    platforms: Optional[list[str]] = None,
    timeout: int = 10,
    rate_delay: float = 0.5,
    smart_check: bool = True,
) -> UsernameSearchResult:
    """跨 30+ 平台搜索用户名存在性。

    Args:
        username:    要查询的用户名
        platforms:   要检查的特定平台名列表 (默认: 全部)
        timeout:     每次 HTTP 请求超时 (秒)
        rate_delay:  平台间延迟 (秒), 避免限流
        smart_check: 检查响应正文中"未找到"关键字减少假阳性

    Returns UsernameSearchResult.
    """
    start = time.time()
    result = UsernameSearchResult(username=username)

    if platforms:
        active = [p for p in PLATFORMS if p[0] in platforms]
        if not active:
            result.errors.append(f"未找到指定平台: {platforms}")
            return result
    else:
        active = PLATFORMS

    total = len(active)
    print(f"  [用户名] 跨 {total} 个平台搜索: {username}")
    print(f"  {'='*50}")

    for i, config in enumerate(active, 1):
        name = config[0]
        print(f"    [{i}/{total}] {name:15s} ...", end=" ", flush=True)

        pr = _check_platform(username, config, timeout, smart_check)

        if pr.exists:
            result.found_on.append(pr)
            print(f"[+] 存在  {pr.profile_url}")
        elif pr.error:
            result.errors.append(f"[{name}] {pr.error}")
            result.not_found_on.append(pr)
            print(f"[!] {pr.error}")
        else:
            result.not_found_on.append(pr)
            print(f"[-] 未注册")

        if rate_delay > 0 and i < total:
            time.sleep(rate_delay)

    result.total_checked = total
    result.total_found = len(result.found_on)
    result.search_time = time.time() - start

    print(f"  {'='*50}")
    print(f"  结果: 在 {result.total_found}/{total} 个平台找到")

    return result
