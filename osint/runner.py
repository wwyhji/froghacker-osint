"""runner.py — OSINT 全自动管线编排。

自动检测目标类型 (邮箱/域名/用户名)，调度对应子模块。

用法:
    from osint.runner import run_osint
    result = run_osint("user@example.com")
"""

from __future__ import annotations

__weld_status__ = {"welded": True, "target": "alpha_loop.ingest", "via": "run_osint", "since": "2026-07-03"}

import time
from dataclasses import dataclass, field
from typing import Optional

from .email_lookup import email_lookup, EmailIntelResult
from .username_search import username_search, UsernameSearchResult
from .domain_intel import domain_intel, DomainIntelResult
from .social_lookup import social_lookup, SocialIntelResult
from .breach_check import breach_check, BreachCheckResult
from .graph_engine import detect_type
from .reporter import format_artifacts


# ── Data Classes ────────────────────────────────────────────────


@dataclass
class OsintResult:
    """完整 OSINT 管线输出。"""
    target: str = ""
    target_type: str = ""
    email: Optional[EmailIntelResult] = None
    username: Optional[UsernameSearchResult] = None
    domain: Optional[DomainIntelResult] = None
    social: Optional[SocialIntelResult] = None
    breach: Optional[BreachCheckResult] = None
    deep: Optional[dict] = None
    errors: list[str] = field(default_factory=list)
    search_time: float = 0.0

    def to_dict(self) -> dict:
        d: dict = {
            "target": self.target,
            "target_type": self.target_type,
            "search_time": self.search_time,
            "errors": self.errors,
        }
        if self.email:
            d["email"] = self.email.to_dict()
        if self.username:
            d["username"] = self.username.to_dict()
        if self.domain:
            d["domain"] = self.domain.to_dict()
        if self.social:
            d["social"] = self.social.to_dict()
        if self.breach:
            d["breach"] = self.breach.to_dict()
        if self.deep:
            d["deep"] = self.deep
        return d


# ── Public API ──────────────────────────────────────────────────


def run_osint(
    target: str,
    target_type: str = "auto",
    modules: Optional[list[str]] = None,
    check_hibp: bool = False,
    check_hunter: bool = False,
    check_smtp: bool = False,
    deep: bool = False,
) -> OsintResult:
    """运行完整 OSINT 管线。

    目标类型决定了运行哪些模块:
      email    -> email_lookup + social_lookup(email) + breach_check
      username -> username_search + social_lookup(username)
      domain   -> domain_intel

    Args:
        target:       要调查的目标
        target_type:  强制目标类型 ("email" / "username" / "domain" / "auto")
        modules:      子模块白名单 (默认: 基于类型的所有模块)
        check_hibp:   是否检查 HIBP 泄露
        check_hunter: 是否查询 Hunter.io
        check_smtp:   是否进行 SMTP 验证

    Returns OsintResult.
    """
    start = time.time()

    if target_type == "auto":
        target_type = detect_type(target)

    result = OsintResult(target=target, target_type=target_type)
    print(f"\n{'='*60}")
    print(f"  OSINT 情报收集 — {target}")
    print(f"  类型: {target_type}")
    print(f"{'='*60}")

    if target_type == "email":
        print(f"\n[1/3] 邮箱情报收集")
        try:
            result.email = email_lookup(
                target,
                check_reputation=True,
                check_hibp=check_hibp,
                check_hunter=check_hunter,
                check_smtp=check_smtp,
                guess_patterns=True,
            )
        except Exception as e:
            result.errors.append(f"邮箱情报失败: {e}")

        print(f"\n[2/3] 社交媒体情报 (GitHub 提交)")
        try:
            result.social = social_lookup(target, target_type="email")
        except Exception as e:
            result.errors.append(f"社交情报失败: {e}")

        print(f"\n[3/3] 数据泄露检查")
        try:
            result.breach = breach_check(target, check_hibp=check_hibp)
        except Exception as e:
            result.errors.append(f"泄露检查失败: {e}")

    elif target_type == "username":
        print(f"\n[1/2] 跨平台用户名搜索")
        try:
            result.username = username_search(target)
        except Exception as e:
            result.errors.append(f"用户名搜索失败: {e}")

        print(f"\n[2/2] 社交媒体情报 (GitHub)")
        try:
            result.social = social_lookup(target, target_type="username")
        except Exception as e:
            result.errors.append(f"社交情报失败: {e}")

    elif target_type == "domain":
        print(f"\n[1/1] 域名情报收集")
        try:
            result.domain = domain_intel(target)
        except Exception as e:
            result.errors.append(f"域名情报失败: {e}")

    else:
        # ip / phone / crypto_address: 无专用子模块, 走主动采集
        print(f"\n[1/1] 主动采集 ({target_type})")
        try:
            from . import sources
            arts = sources.collect(target, entity_type=target_type, limit=20)
            for line in format_artifacts(arts):
                print(f"  {line}")
            result.deep = {"collected": len(arts)}
        except Exception as e:
            result.errors.append(f"采集失败: {e}")

    # 深度关联图谱 (可选, 默认关闭)
    if deep:
        print(f"\n[深度] 关联图谱展开")
        try:
            from .osint_agent import run_agent
            agent_result = run_agent(target, target_type=result.target_type, max_depth=2)
            result.deep = agent_result.to_dict()
        except Exception as e:
            result.errors.append(f"深度分析失败: {e}")

    result.search_time = time.time() - start

    print(f"\n{'='*60}")
    print(f"  完成! 耗时: {result.search_time:.1f}s")
    if result.errors:
        print(f"  错误: {len(result.errors)}")
        for e in result.errors:
            print(f"    - {e}")
    print(f"{'='*60}")

    return result
