"""email_lookup.py — 邮箱 OSINT 情报收集。

数据源:
  1. 格式验证 — 正则语法 + MX 记录 + 临时域名黑名单
  2. EmailRep.io — 免费信誉查询 (无需 API key)
  3. HaveIBeenPwned — 泄露检查 (需 HIBP_API_KEY)
  4. Hunter.io — 企业邮箱验证 (需 HUNTERIO_API_KEY)
  5. SMTP 验证 — 连接 MX 服务器验证邮箱存在性 (默认关闭)
  6. 模式猜测 — 从域名推测常见邮箱命名模式

用法:
    from osint.email_lookup import email_lookup
    result = email_lookup("user@example.com")
"""

from __future__ import annotations

import json
import os
import re
import socket
import time
from dataclasses import dataclass, field
from typing import Optional

import requests

# ── 临时邮箱域名黑名单 (常见的一次性邮箱) ─────────────────────────

DISPOSABLE_DOMAINS: set[str] = {
    "mailinator.com", "guerrillamail.com", "temp-mail.org", "throwaway.email",
    "10minutemail.com", "yopmail.com", "sharklasers.com", "cock.li",
    "protonmail.com", "tempmail.com", "trashmail.com", "maildrop.cc",
    "getairmail.com", "emailfake.com", "tempr.email", "spam4.me",
    "dispostable.com", "moakt.com", "thankyou2010.com", "mailexpire.com",
    "mailmetrash.com", "mintemail.com", "mytrashmail.com", "spambox.us",
    "tempemail.net", "spamgourmet.com", "jetable.org", "emailondeck.com",
    "burnermail.io", "inboxbear.com", "mailsac.com", "mailcatch.com",
    "tempalias.com", "throwaway.io", "spamdecoy.net", "deadfake.com",
    "haltospam.com", "sneakemail.com", "spamex.com", "trash2009.com",
}

# ── API 端点 ────────────────────────────────────────────────────

EMAILREP_URL = "https://emailrep.io/{email}"
HIBP_BREACH_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
HIBP_PASTE_URL = "https://haveibeenpwned.com/api/v3/pasteaccount/{email}"
HUNTER_VERIFY_URL = "https://api.hunter.io/v2/email-verifier"

_REQUEST_HEADERS = {
    "User-Agent": "FrogHackerOSINT/1.0",
    "Accept": "application/json",
}


# ── Data Classes ────────────────────────────────────────────────


@dataclass
class EmailFormat:
    """邮箱格式验证结果。"""
    syntax_valid: bool = False
    local_part: str = ""
    domain: str = ""
    has_mx: bool = False
    disposable: bool = False
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "syntax_valid": self.syntax_valid,
            "local_part": self.local_part,
            "domain": self.domain,
            "has_mx": self.has_mx,
            "disposable": self.disposable,
            "reason": self.reason,
        }


@dataclass
class EmailRepResult:
    """EmailRep.io 信誉数据。"""
    email: str = ""
    reputation: str = ""
    suspicious: bool = False
    blacklisted: bool = False
    malicious: bool = False
    spam: bool = False
    details: str = ""

    def to_dict(self) -> dict:
        return {
            "email": self.email,
            "reputation": self.reputation,
            "suspicious": self.suspicious,
            "blacklisted": self.blacklisted,
            "malicious": self.malicious,
            "spam": self.spam,
            "details": self.details,
        }


@dataclass
class HIBPBreach:
    """HaveIBeenPwned 泄露记录。"""
    name: str = ""
    title: str = ""
    domain: str = ""
    breach_date: str = ""
    pwn_count: int = 0
    data_classes: list[str] = field(default_factory=list)
    is_verified: bool = False
    is_sensitive: bool = False
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
class HIBPResult:
    """HIBP 检查结果。"""
    breaches: list[HIBPBreach] = field(default_factory=list)
    total_breaches: int = 0

    def to_dict(self) -> dict:
        return {
            "total_breaches": self.total_breaches,
            "breaches": [b.to_dict() for b in self.breaches],
        }


@dataclass
class HunterResult:
    """Hunter.io 邮箱验证结果。"""
    email: str = ""
    score: int = 0
    first_name: str = ""
    last_name: str = ""
    position: str = ""
    phone: str = ""
    disposable: bool = False
    webmail: bool = False
    accept_all: bool = False

    def to_dict(self) -> dict:
        return {
            "email": self.email,
            "score": self.score,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "position": self.position,
            "phone": self.phone,
            "disposable": self.disposable,
            "webmail": self.webmail,
            "accept_all": self.accept_all,
        }


@dataclass
class SmtpResult:
    """SMTP 验证结果 (不发送邮件)。"""
    deliverable: bool = False
    full_inbox: bool = False
    catch_all: bool = False
    disabled: bool = False
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "deliverable": self.deliverable,
            "full_inbox": self.full_inbox,
            "catch_all": self.catch_all,
            "disabled": self.disabled,
            "reason": self.reason,
        }


@dataclass
class EmailIntelResult:
    """邮箱情报综合结果。"""
    email: str = ""
    format: EmailFormat = field(default_factory=EmailFormat)
    reputation: Optional[EmailRepResult] = None
    hibp: Optional[HIBPResult] = None
    hunter: Optional[HunterResult] = None
    smtp: Optional[SmtpResult] = None
    guessed_patterns: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d: dict = {
            "email": self.email,
            "format": self.format.to_dict(),
            "guessed_patterns": self.guessed_patterns,
            "errors": self.errors,
        }
        if self.reputation:
            d["reputation"] = self.reputation.to_dict()
        if self.hibp:
            d["hibp"] = self.hibp.to_dict()
        if self.hunter:
            d["hunter"] = self.hunter.to_dict()
        if self.smtp:
            d["smtp"] = self.smtp.to_dict()
        return d


# ── Internal Helpers ────────────────────────────────────────────


def _validate_email(email: str) -> EmailFormat:
    """检查邮箱语法、MX 记录、临时域名。"""
    result = EmailFormat()
    result.email = email

    pattern = r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$"
    match = re.match(pattern, email)
    if not match:
        result.reason = "语法格式无效"
        return result

    result.syntax_valid = True
    local, domain = email.rsplit("@", 1)
    result.local_part = local
    result.domain = domain

    # 检查临时域名
    if domain.lower() in DISPOSABLE_DOMAINS:
        result.disposable = True
        result.reason = "临时邮箱域名"
        return result

    # 检查 MX 记录
    try:
        import dns.resolver
        try:
            answers = dns.resolver.resolve(domain, "MX")
            result.has_mx = bool(list(answers))
        except Exception:
            result.has_mx = False
    except ImportError:
        result.has_mx = False

    if not result.has_mx:
        result.reason = "域名无 MX 记录"
    else:
        result.reason = "有效"

    return result


def _check_emailrep(email: str) -> Optional[EmailRepResult]:
    """查询 EmailRep.io 信誉 (免费, 无需 API key)。"""
    try:
        url = EMAILREP_URL.format(email=email)
        resp = requests.get(
            url, headers=_REQUEST_HEADERS, timeout=10,
        )
        if resp.status_code == 429:
            time.sleep(3)
            resp = requests.get(url, headers=_REQUEST_HEADERS, timeout=10)
        if resp.status_code != 200:
            return None

        data = resp.json()
        return EmailRepResult(
            email=email,
            reputation=data.get("reputation", ""),
            suspicious=data.get("suspicious", False),
            blacklisted=data.get("blacklisted", False),
            malicious=data.get("malicious", False),
            spam=data.get("details", {}).get("spam", False),
            details=data.get("details", {}).get("description", ""),
        )
    except requests.RequestException:
        return None


def _check_hibp(email: str, api_key: str = "") -> Optional[HIBPResult]:
    """查询 HaveIBeenPwned 泄露记录。"""
    api_key = api_key or os.environ.get("HIBP_API_KEY", "")
    if not api_key:
        return None

    result = HIBPResult()
    try:
        headers = {**_REQUEST_HEADERS, "hibp-api-key": api_key}
        url = HIBP_BREACH_URL.format(email=email)
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 404:
            return result
        if resp.status_code != 200:
            return None

        for item in resp.json():
            result.breaches.append(HIBPBreach(
                name=item.get("Name", ""),
                title=item.get("Title", ""),
                domain=item.get("Domain", ""),
                breach_date=item.get("BreachDate", ""),
                pwn_count=item.get("PwnCount", 0),
                data_classes=item.get("DataClasses", []),
                is_verified=item.get("IsVerified", False),
                is_sensitive=item.get("IsSensitive", False),
                is_spam_list=item.get("IsSpamList", False),
            ))
        result.total_breaches = len(result.breaches)
        time.sleep(1.5)  # HIBP 速率限制
        return result
    except requests.RequestException:
        return None


def _check_hunter(email: str, api_key: str = "") -> Optional[HunterResult]:
    """查询 Hunter.io 邮箱验证。"""
    api_key = api_key or os.environ.get("HUNTERIO_API_KEY", "")
    if not api_key:
        return None

    try:
        params = {"email": email, "api_key": api_key}
        resp = requests.get(
            HUNTER_VERIFY_URL, params=params, headers=_REQUEST_HEADERS, timeout=10,
        )
        if resp.status_code != 200:
            return None

        data = resp.json().get("data", {})
        return HunterResult(
            email=email,
            score=data.get("score", 0),
            first_name=data.get("first_name", ""),
            last_name=data.get("last_name", ""),
            position=data.get("position", ""),
            phone=data.get("phone", ""),
            disposable=data.get("disposable", False),
            webmail=data.get("webmail", False),
            accept_all=data.get("accept_all", False),
        )
    except requests.RequestException:
        return None


def _check_smtp(email: str) -> Optional[SmtpResult]:
    """SMTP 邮箱存在性验证 (不发送邮件)。

    警告: 此操作会在目标邮件服务器留下日志。
    仅限授权测试使用。
    """
    result = SmtpResult()
    domain = email.split("@", 1)[-1] if "@" in email else ""

    try:
        mx_records = []
        try:
            import dns.resolver
            answers = dns.resolver.resolve(domain, "MX")
            mx_records = sorted(
                answers, key=lambda r: r.preference,
            )
        except ImportError:
            pass

        if not mx_records:
            result.reason = "无 MX 记录"
            return result

        mx_host = str(mx_records[0].exchange).rstrip(".")

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((mx_host, 25))

        def recv():
            return sock.recv(4096).decode("utf-8", errors="replace")

        def send(cmd: str):
            sock.sendall((cmd + "\r\n").encode())

        recv()  # banner
        send(f"HELO froghackerg-osint.local")
        recv()
        send(f"MAIL FROM:<verify@example.org>")
        recv()
        send(f"RCPT TO:<{email}>")
        response = recv()

        code = 0
        if response:
            try:
                code = int(response[:3])
            except (ValueError, IndexError):
                pass

        if code == 250:
            result.deliverable = True
            result.reason = "邮箱存在"
        elif code == 550:
            result.deliverable = False
            result.reason = "邮箱不存在"
        elif code == 551:
            result.deliverable = False
            result.reason = "非本地邮箱"
        elif code == 552:
            result.deliverable = True
            result.full_inbox = True
            result.reason = "邮箱满"
        elif code == 450:
            result.disabled = True
            result.reason = "暂时不可用 (可能触发限流)"
        else:
            result.reason = f"未知响应: {response[:60]}"

        send("QUIT")
        recv()
        sock.close()
        return result

    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        result.reason = f"连接失败: {e}"
        return result
    except Exception as e:
        result.reason = f"SMTP 验证异常: {e}"
        return result


def _guess_email_patterns(domain: str) -> list[str]:
    """从域名猜测常见邮箱命名模式。"""
    common = [
        f"admin@{domain}",
        f"info@{domain}",
        f"contact@{domain}",
        f"support@{domain}",
        f"sales@{domain}",
        f"help@{domain}",
        f"service@{domain}",
        f"webmaster@{domain}",
        f"postmaster@{domain}",
        f"hostmaster@{domain}",
        f"abuse@{domain}",
        f"noreply@{domain}",
        f"feedback@{domain}",
        f"team@{domain}",
        f"hello@{domain}",
        f"hr@{domain}",
        f"press@{domain}",
        f"privacy@{domain}",
        f"partner@{domain}",
        f"marketing@{domain}",
    ]
    return common


# ── Public API ──────────────────────────────────────────────────


def email_lookup(
    email: str,
    check_reputation: bool = True,
    check_hibp: bool = False,
    check_hunter: bool = False,
    check_smtp: bool = False,
    guess_patterns: bool = False,
) -> EmailIntelResult:
    """对邮箱执行全方位情报收集。

    Args:
        email:            目标邮箱
        check_reputation: 查询 EmailRep.io (免费)
        check_hibp:       查询 HaveIBeenPwned (需 HIBP_API_KEY)
        check_hunter:     查询 Hunter.io (需 HUNTERIO_API_KEY)
        check_smtp:       SMTP 邮箱验证 (默认关闭)
        guess_patterns:   从域名猜测邮箱命名模式

    Returns EmailIntelResult.
    """
    result = EmailIntelResult(email=email)

    # 1. 格式验证 (始终执行)
    print(f"  [格式] 验证邮箱格式...")
    result.format = _validate_email(email)
    print(f"    {'有效' if result.format.syntax_valid else '无效'}, "
          f"MX: {'有' if result.format.has_mx else '无'}, "
          f"临时邮箱: {'是' if result.format.disposable else '否'}")

    if not result.format.syntax_valid:
        return result

    # 2. EmailRep.io 信誉
    if check_reputation:
        print(f"  [EmailRep] 查询信誉...")
        result.reputation = _check_emailrep(email)
        if result.reputation:
            print(f"    信誉: {result.reputation.reputation}, "
                  f"可疑: {'是' if result.reputation.suspicious else '否'}, "
                  f"黑名单: {'是' if result.reputation.blacklisted else '否'}")
        else:
            print(f"    (查询失败或不可用)")

    # 3. HIBP 泄露检查
    if check_hibp:
        hibp_key = os.environ.get("HIBP_API_KEY", "")
        if hibp_key:
            print(f"  [HIBP] 查询数据泄露...")
            result.hibp = _check_hibp(email, hibp_key)
            if result.hibp:
                print(f"    发现 {result.hibp.total_breaches} 次泄露")
                for b in result.hibp.breaches[:5]:
                    print(f"      - {b.title} ({b.breach_date}): {', '.join(b.data_classes)}")
        else:
            print(f"  [HIBP] 跳过 (未设置 HIBP_API_KEY)")

    # 4. Hunter.io 验证
    if check_hunter:
        hunter_key = os.environ.get("HUNTERIO_API_KEY", "")
        if hunter_key:
            print(f"  [Hunter] 查询邮箱验证...")
            result.hunter = _check_hunter(email, hunter_key)
            if result.hunter:
                print(f"    置信度: {result.hunter.score}/100, "
                      f"姓名: {result.hunter.first_name} {result.hunter.last_name}")
        else:
            print(f"  [Hunter] 跳过 (未设置 HUNTERIO_API_KEY)")

    # 5. SMTP 验证
    if check_smtp:
        print(f"  [SMTP] 验证邮箱存在性 (将在目标服务器留下日志)...")
        result.smtp = _check_smtp(email)
        if result.smtp:
            print(f"    可投递: {'是' if result.smtp.deliverable else '否'}, "
                  f"原因: {result.smtp.reason}")

    # 6. 模式猜测
    if guess_patterns:
        domain = result.format.domain
        result.guessed_patterns = _guess_email_patterns(domain)
        print(f"    猜测 {len(result.guessed_patterns)} 个可能邮箱")

    return result
