"""domain_intel.py — 域名 OSINT 情报收集。

数据源:
  1. WHOIS — 通过 socket 查询注册信息
  2. DNS — A/AAAA/MX/NS/TXT/SOA/CNAME 记录
  3. crt.sh — 证书透明度日志
  4. Wayback Machine — 历史快照

蛙客的情报触角伸向互联网的每一个角落.

用法:
    from osint.domain_intel import domain_intel
    result = domain_intel("example.com")
"""

from __future__ import annotations

import json
import re
import socket
import time
from dataclasses import dataclass, field
from typing import Optional

import requests

# ── WHOIS 服务器映射 ────────────────────────────────────────────

_WHOIS_SERVERS = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "info": "whois.afilias.net",
    "io": "whois.nic.io",
    "cn": "whois.cnnic.cn",
    "uk": "whois.nic.uk",
    "de": "whois.denic.de",
    "ru": "whois.tcinet.ru",
    "jp": "whois.jprs.jp",
    "fr": "whois.nic.fr",
    "br": "whois.registro.br",
    "au": "whois.audns.net.au",
    "cc": "whois.nic.cc",
    "tv": "whois.nic.tv",
    "me": "whois.nic.me",
    "co": "whois.nic.co",
    "biz": "whois.nic.biz",
    "pro": "whois.nic.pro",
    "mobi": "whois.nic.mobi",
}

_REQUEST_HEADERS = {
    "User-Agent": "FrogHackerOSINT/1.0",
    "Accept": "application/json",
}

# ── WHOIS 解析正则 ─────────────────────────────────────────────

_WHOIS_PATTERNS: dict[str, re.Pattern] = {
    "registrar": re.compile(
        r"(?:Registrar:|registrar:|Sponsoring Registrar:)\s*(.+?)[\r\n]",
        re.IGNORECASE,
    ),
    "creation_date": re.compile(
        r"(?:Creation Date:|creation_date:|Created On:|created:)\s*(.+?)[\r\n]",
        re.IGNORECASE,
    ),
    "expiration_date": re.compile(
        r"(?:Registrar Registration Expiration Date:|Registry Expiry Date:|"
        r"Expiration Date:|expires:)\s*(.+?)[\r\n]",
        re.IGNORECASE,
    ),
    "updated_date": re.compile(
        r"(?:Updated Date:|updated_date:|Last Updated:)\s*(.+?)[\r\n]",
        re.IGNORECASE,
    ),
    "name_servers": re.compile(
        r"(?:Name Server:|nserver:)\s*(.+?)[\r\n]",
        re.IGNORECASE,
    ),
    "registrant_name": re.compile(
        r"(?:Registrant Name:|Registrant:)\s*(.+?)[\r\n]",
        re.IGNORECASE,
    ),
    "registrant_org": re.compile(
        r"(?:Registrant Organization:|org:)\s*(.+?)[\r\n]",
        re.IGNORECASE,
    ),
    "registrant_email": re.compile(
        r"(?:Registrant Email:|Registrant E-mail:)\s*(.+?)[\r\n]",
        re.IGNORECASE,
    ),
}


# ── Data Classes ────────────────────────────────────────────────


@dataclass
class WhoisInfo:
    """解析后的 WHOIS 记录。"""
    domain: str = ""
    registrar: str = ""
    creation_date: str = ""
    expiration_date: str = ""
    updated_date: str = ""
    name_servers: list[str] = field(default_factory=list)
    registrant_name: str = ""
    registrant_org: str = ""
    registrant_email: str = ""

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "registrar": self.registrar,
            "creation_date": self.creation_date,
            "expiration_date": self.expiration_date,
            "updated_date": self.updated_date,
            "name_servers": self.name_servers,
            "registrant_name": self.registrant_name,
            "registrant_org": self.registrant_org,
            "registrant_email": self.registrant_email,
        }


@dataclass
class DNSRecord:
    """单个 DNS 记录。"""
    type: str = ""
    value: str = ""

    def to_dict(self) -> dict:
        return {"type": self.type, "value": self.value}


@dataclass
class CertEntry:
    """证书透明度日志条目。"""
    common_name: str = ""
    issuer: str = ""
    issued_date: str = ""
    expires_date: str = ""
    subdomains: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "common_name": self.common_name,
            "issuer": self.issuer,
            "issued_date": self.issued_date,
            "expires_date": self.expires_date,
            "subdomains": self.subdomains[:10],
        }


@dataclass
class WaybackEntry:
    """Wayback Machine 快照。"""
    url: str = ""
    timestamp: str = ""
    status_code: int = 0
    snapshot_url: str = ""

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "timestamp": self.timestamp,
            "status_code": self.status_code,
            "snapshot_url": self.snapshot_url,
        }


@dataclass
class DomainIntelResult:
    """聚合的域名情报结果。"""
    domain: str = ""
    whois: Optional[WhoisInfo] = None
    dns_records: list[DNSRecord] = field(default_factory=list)
    certificates: list[CertEntry] = field(default_factory=list)
    wayback_snapshots: list[WaybackEntry] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d: dict = {
            "domain": self.domain,
            "dns_records": [r.to_dict() for r in self.dns_records],
            "certificates": self.certificates[:10],
            "errors": self.errors,
        }
        if self.whois:
            d["whois"] = self.whois.to_dict()
        if self.wayback_snapshots:
            d["wayback_snapshots"] = [w.to_dict() for w in self.wayback_snapshots[:10]]
        return d


# ── Internal Helpers ────────────────────────────────────────────


def _query_whois(domain: str) -> Optional[WhoisInfo]:
    """通过 socket 查询 WHOIS 注册信息 (带缓存, 与 collect/identity 共享)。"""
    from .cache import cache, cache_key
    key = cache_key("domain", domain, "whois_raw")
    cached = cache.get(key)
    if cached is not None:
        return cached

    tld = domain.split(".")[-1] if "." in domain else ""
    server = _WHOIS_SERVERS.get(tld, "whois.verisign-grs.com")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(15)
        sock.connect((server, 43))
        sock.sendall(f"{domain}\r\n".encode())

        raw = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            raw += chunk
        sock.close()

        text = raw.decode("utf-8", errors="replace")

        info = WhoisInfo(domain=domain)
        for key, pattern in _WHOIS_PATTERNS.items():
            match = pattern.search(text)
            if match:
                value = match.group(1).strip()
                if key == "name_servers":
                    info.name_servers.append(value)
                else:
                    setattr(info, key, value)

        time.sleep(2)  # WHOIS 礼貌延迟
        cache.set(key, info)
        return info

    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def _query_dns(domain: str) -> list[DNSRecord]:
    """收集 DNS 记录。"""
    records: list[DNSRecord] = []

    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5

        for rt in ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]:
            try:
                answers = resolver.resolve(domain, rt)
                for ans in answers:
                    records.append(DNSRecord(type=rt, value=str(ans)))
            except Exception:
                continue
    except ImportError:
        pass

    return records


def _query_crtsh(domain: str) -> list[CertEntry]:
    """查询 crt.sh 证书透明度日志。"""
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        resp = requests.get(url, headers=_REQUEST_HEADERS, timeout=15)

        if resp.status_code != 200:
            return []

        data = resp.json()
        seen_cn: set[str] = set()
        entries: list[CertEntry] = []

        for item in data[:50]:
            cn = item.get("common_name", "")
            if cn in seen_cn:
                continue
            seen_cn.add(cn)

            name_value = item.get("name_value", "")
            subdomains = [s.strip() for s in name_value.split("\n") if s.strip()] if name_value else []

            entries.append(CertEntry(
                common_name=cn,
                issuer=item.get("issuer_name", ""),
                issued_date=item.get("not_before", ""),
                expires_date=item.get("not_after", ""),
                subdomains=subdomains,
            ))

        time.sleep(3)
        return entries

    except (requests.RequestException, json.JSONDecodeError):
        return []


def _query_wayback(domain: str, max_results: int = 10) -> list[WaybackEntry]:
    """查询 Wayback Machine 历史快照。"""
    try:
        url = (
            f"https://web.archive.org/cdx/search/cdx"
            f"?url={domain}/*&output=json&limit={max_results}"
            f"&fl=original,timestamp,statuscode"
        )
        resp = requests.get(url, headers=_REQUEST_HEADERS, timeout=15)

        if resp.status_code != 200:
            return []

        data = resp.json()
        entries: list[WaybackEntry] = []

        for row in data[1:]:  # 第一行是 header
            if len(row) >= 3:
                original_url = row[0]
                ts = row[1]
                sc = int(row[2]) if row[2].isdigit() else 0
                snapshot_url = f"https://web.archive.org/web/{ts}/{original_url}"
                entries.append(WaybackEntry(
                    url=original_url,
                    timestamp=ts,
                    status_code=sc,
                    snapshot_url=snapshot_url,
                ))

        return entries

    except (requests.RequestException, json.JSONDecodeError, IndexError):
        return []


# ── Public API ──────────────────────────────────────────────────


def domain_intel(
    domain: str,
    check_whois: bool = True,
    check_dns: bool = True,
    check_certificates: bool = True,
    check_wayback: bool = True,
    max_wayback: int = 10,
) -> DomainIntelResult:
    """对域名执行全方位情报收集。

    Args:
        domain:            目标域名
        check_whois:       查询 WHOIS 注册数据
        check_dns:         收集 DNS 记录
        check_certificates:查询 crt.sh 证书透明度
        check_wayback:     查询 Wayback Machine 历史
        max_wayback:       检索的最大快照数

    Returns DomainIntelResult.
    """
    result = DomainIntelResult(domain=domain)

    # 1. WHOIS
    if check_whois:
        print(f"  [WHOIS] 查询注册信息...")
        result.whois = _query_whois(domain)
        if result.whois and result.whois.registrar:
            print(f"    注册商: {result.whois.registrar}")
            print(f"    创建: {result.whois.creation_date or '(未知)'}")
            if result.whois.registrant_org:
                print(f"    组织: {result.whois.registrant_org}")
        else:
            print(f"    (查询失败或无数据)")

    # 2. DNS
    if check_dns:
        print(f"  [DNS] 收集记录...")
        result.dns_records = _query_dns(domain)
        print(f"    发现 {len(result.dns_records)} 条记录")
        by_type: dict[str, int] = {}
        for rec in result.dns_records:
            by_type[rec.type] = by_type.get(rec.type, 0) + 1
        for t, c in sorted(by_type.items()):
            print(f"      {t}: {c} 条")

    # 3. 证书透明度
    if check_certificates:
        print(f"  [crt.sh] 查询证书透明度...")
        result.certificates = _query_crtsh(domain)
        print(f"    发现 {len(result.certificates)} 张证书")

    # 4. Wayback Machine
    if check_wayback:
        print(f"  [Wayback] 查询历史快照...")
        result.wayback_snapshots = _query_wayback(domain, max_wayback)
        print(f"    发现 {len(result.wayback_snapshots)} 个快照")

    return result
