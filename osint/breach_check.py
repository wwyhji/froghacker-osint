"""breach_check.py — 数据泄露检查。

数据源:
  1. HaveIBeenPwned API v3 — 泄露记录查询

用法:
    from osint.breach_check import breach_check
    result = breach_check("user@example.com")
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Optional

import requests

HIBP_BREACH_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{email}"

_REQUEST_HEADERS = {
    "User-Agent": "FrogHackerOSINT/1.0",
}


# ── Data Classes ────────────────────────────────────────────────


@dataclass
class BreachInfo:
    """单个数据泄露记录。"""
    name: str = ""
    title: str = ""
    domain: str = ""
    breach_date: str = ""
    added_date: str = ""
    pwn_count: int = 0
    data_classes: list[str] = field(default_factory=list)
    description: str = ""
    is_verified: bool = False
    is_fabricated: bool = False
    is_sensitive: bool = False
    is_retired: bool = False
    is_spam_list: bool = False

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "title": self.title,
            "domain": self.domain,
            "breach_date": self.breach_date,
            "pwn_count": self.pwn_count,
            "data_classes": self.data_classes,
            "is_verified": self.is_verified,
            "is_sensitive": self.is_sensitive,
            "is_spam_list": self.is_spam_list,
        }


@dataclass
class BreachCheckResult:
    """泄露检查结果。"""
    email: str = ""
    breaches: list[BreachInfo] = field(default_factory=list)
    total_breaches: int = 0
    source: str = ""
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "email": self.email,
            "total_breaches": self.total_breaches,
            "source": self.source,
            "breaches": [b.to_dict() for b in self.breaches],
            "error": self.error,
        }


# ── Public API ──────────────────────────────────────────────────


def breach_check(
    email: str,
    check_hibp: bool = True,
    api_key: str = "",
) -> BreachCheckResult:
    """检查邮箱是否出现在已知数据泄露中。

    Args:
        email:      目标邮箱
        check_hibp: 是否查询 HaveIBeenPwned API (需 HIBP_API_KEY)
        api_key:    API key (默认从 HIBP_API_KEY 环境变量读取)

    Returns BreachCheckResult.
    """
    result = BreachCheckResult(email=email)
    api_key = api_key or os.environ.get("HIBP_API_KEY", "")

    if not check_hibp or not api_key:
        result.source = "none"
        result.error = "未设置 HIBP_API_KEY，跳过泄露检查"
        print(f"  [泄露] 跳过 (未设置 HIBP_API_KEY)")
        return result

    print(f"  [HIBP] 查询数据泄露: {email}")
    try:
        headers = {**_REQUEST_HEADERS, "hibp-api-key": api_key}
        url = HIBP_BREACH_URL.format(email=email)
        resp = requests.get(url, headers=headers, timeout=15)

        if resp.status_code == 404:
            print(f"    未发现泄露记录")
            result.source = "hibp"
            return result

        if resp.status_code == 401:
            result.error = "HIBP API key 无效"
            print(f"    [错误] API key 无效")
            return result

        if resp.status_code != 200:
            result.error = f"HIBP 返回 {resp.status_code}"
            print(f"    [错误] HTTP {resp.status_code}")
            return result

        items = resp.json()
        for item in items:
            result.breaches.append(BreachInfo(
                name=item.get("Name", ""),
                title=item.get("Title", ""),
                domain=item.get("Domain", ""),
                breach_date=item.get("BreachDate", ""),
                added_date=item.get("AddedDate", ""),
                pwn_count=item.get("PwnCount", 0),
                data_classes=item.get("DataClasses", []),
                description=item.get("Description", "")[:200],
                is_verified=item.get("IsVerified", False),
                is_fabricated=item.get("IsFabricated", False),
                is_sensitive=item.get("IsSensitive", False),
                is_retired=item.get("IsRetired", False),
                is_spam_list=item.get("IsSpamList", False),
            ))

        result.total_breaches = len(result.breaches)
        result.source = "hibp"

        print(f"    发现 {result.total_breaches} 次泄露:")
        for b in result.breaches:
            print(f"      - {b.title:30s} ({b.breach_date}) {', '.join(b.data_classes[:5])}")

        time.sleep(1.5)

    except requests.RequestException as e:
        result.error = f"HIBP 查询失败: {e}"
        print(f"    [错误] {e}")

    return result
