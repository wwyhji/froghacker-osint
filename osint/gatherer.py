"""OSINT Gatherer — automated open-source intelligence collection.

Capabilities:
  1. Domain/Email/IP/Username cross-platform search
  2. Google dorking query generation
  3. Breach database search URLs
  4. Social media profile discovery
  5. WHOIS + DNS + SSL certificate transparency
  6. Shodan/Censys search URL generation
  7. GitHub/StackOverflow code search

Usage:
    from osint.gatherer import OSINTGatherer, gather_intel
    gatherer = OSINTGatherer()
    report = gatherer.gather(domain="example.com", email="admin@example.com")
    print(report.summary())
"""

from __future__ import annotations

import hashlib
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class OSINTResult:
    """A single OSINT finding."""
    source: str
    category: str       # domain, email, ip, username, social, breach, cert, code, dork
    url: str
    title: str = ""
    description: str = ""
    confidence: str = "medium"  # high/medium/low


@dataclass
class OSINTReport:
    """Complete OSINT gathering report."""
    targets: Dict[str, str] = field(default_factory=dict)
    results: List[OSINTResult] = field(default_factory=list)
    generated_queries: List[str] = field(default_factory=list)

    def summary(self) -> str:
        lines = ["=" * 60, "  OSINT Report", "=" * 60]
        if self.targets:
            for k, v in self.targets.items():
                lines.append(f"  {k}: {v}")
        cats = {}
        for r in self.results:
            cats.setdefault(r.category, []).append(r)
        for cat, results in sorted(cats.items()):
            lines.append(f"  [{cat}] {len(results)} results")
        lines.append("=" * 60)
        return "\n".join(lines)


class OSINTGatherer:
    """Automated OSINT gathering across multiple public sources.

    All searches generate URLs only — no actual requests made.
    User opens URLs in browser to avoid rate limits and fingerprinting.
    """

    # ── Search URL generators ───────────────────────────────────────────

    @staticmethod
    def search_google(query: str) -> str:
        return f"https://www.google.com/search?q={urllib.parse.quote(query)}"

    @staticmethod
    def search_shodan(query: str) -> str:
        return f"https://www.shodan.io/search?query={urllib.parse.quote(query)}"

    @staticmethod
    def search_censys(query: str) -> str:
        return f"https://search.censys.io/search?resource=hosts&q={urllib.parse.quote(query)}"

    @staticmethod
    def search_crt_sh(domain: str) -> str:
        return f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}"

    @staticmethod
    def search_github(query: str) -> str:
        return f"https://github.com/search?q={urllib.parse.quote(query)}&type=code"

    @staticmethod
    def search_hunter(email_domain: str) -> str:
        return f"https://hunter.io/search/{urllib.parse.quote(email_domain)}"

    @staticmethod
    def search_haveibeenpwned(email: str) -> str:
        return f"https://haveibeenpwned.com/account/{urllib.parse.quote(email)}"

    @staticmethod
    def search_dehashed(email: str) -> str:
        return f"https://www.dehashed.com/search?query={urllib.parse.quote(email)}"

    @staticmethod
    def search_intelx(query: str) -> str:
        return f"https://intelx.io/?s={urllib.parse.quote(query)}"

    @staticmethod
    def search_wayback(target: str) -> str:
        return f"https://web.archive.org/web/*/{urllib.parse.quote(target)}"

    @staticmethod
    def search_virustotal(query: str) -> str:
        return f"https://www.virustotal.com/gui/search/{urllib.parse.quote(query)}"

    @staticmethod
    def search_urlscan(domain: str) -> str:
        return f"https://urlscan.io/search/#{urllib.parse.quote(domain)}"

    @staticmethod
    def search_securitytrails(domain: str) -> str:
        return f"https://securitytrails.com/domain/{urllib.parse.quote(domain)}"

    @staticmethod
    def search_alienvault(ip: str) -> str:
        return f"https://otx.alienvault.com/indicator/ip/{urllib.parse.quote(ip)}"

    @staticmethod
    def search_abuseipdb(ip: str) -> str:
        return f"https://www.abuseipdb.com/check/{urllib.parse.quote(ip)}"

    @staticmethod
    def search_greynoise(ip: str) -> str:
        return f"https://viz.greynoise.io/ip/{urllib.parse.quote(ip)}"

    @staticmethod
    def search_shodan_ip(ip: str) -> str:
        return f"https://www.shodan.io/host/{urllib.parse.quote(ip)}"

    @staticmethod
    def search_wigle(ssid: str) -> str:
        return f"https://wigle.net/search?ssid={urllib.parse.quote(ssid)}"

    @staticmethod
    def search_leakix(query: str) -> str:
        return f"https://leakix.net/search?q={urllib.parse.quote(query)}"

    @staticmethod
    def search_spiderfoot() -> str:
        return "python3 -m spiderfoot -l 127.0.0.1:5001  # Web UI for full OSINT automation"

    @staticmethod
    def search_theharvester(domain: str) -> str:
        return f"theHarvester -d {domain} -b google,linkedin,bing,github,shodan"

    @staticmethod
    def search_sherlock(username: str) -> str:
        return f"sherlock {username}"

    @staticmethod
    def search_holehe(email: str) -> str:
        return f"holehe {email}"

    @staticmethod
    def search_phoneinfoga(phone: str) -> str:
        return f"phoneinfoga scan -n {phone}"

    @staticmethod
    def search_trufflehog(target: str) -> str:
        return f"trufflehog github --repo={urllib.parse.quote(target)}"

    # ── 丁爸情报分析师工具箱 (OSINT 资源导航) ─────────────────────────

    @staticmethod
    def dingba_home() -> str:
        """丁爸主站 — OSINT 文章/工具/资源汇总导航。"""
        return "http://dingba.top/"

    @staticmethod
    def dingba_thinktanks() -> str:
        """丁爸全球智库导航。"""
        return "http://dingba.top/qqzk"

    @staticmethod
    def dingba_foreign_resources() -> str:
        """丁爸国外资源网页 — 100+ 国外搜索网站汇总。"""
        return "http://dingba.top/gwzyl"

    @staticmethod
    def dingba_osint_tools() -> str:
        """丁爸开源情报工具汇总 (按国家/社交媒体/暗网/GEOINT 等分类)。"""
        return "http://dingba.top/kyqbgjhzwz"

    # ── Google Dorks ─────────────────────────────────────────────────────

    DORKS: Dict[str, List[str]] = {
        "exposed_files": [
            'site:{domain} ext:log | ext:txt | ext:conf | ext:cfg | ext:ini',
            'site:{domain} ext:sql | ext:db | ext:sqlite | ext:backup',
            'site:{domain} ext:env | ext:yaml | ext:json "password"',
            'site:{domain} ext:pem | ext:key | ext:p12 | ext:pfx',
            'site:{domain} inurl:backup | inurl:dump | inurl:export',
        ],
        "exposed_admin": [
            'site:{domain} inurl:admin | inurl:login | inurl:dashboard',
            'site:{domain} intitle:"phpinfo" | intitle:"index of"',
            'site:{domain} inurl:phpmyadmin | inurl:phpPgAdmin',
        ],
        "credentials": [
            'site:{domain} "password" filetype:txt | filetype:log',
            'site:{domain} "DB_PASSWORD" | "DB_USER" | "DATABASE_URL"',
            'site:{domain} "api_key" | "api_secret" | "token" ext:py | ext:js',
        ],
        "vulnerabilities": [
            'site:{domain} "sql syntax" | "mysql_fetch" | "ORA-\\d{5}"',
            'site:{domain} "stack trace" | "traceback" | "debug"',
            'site:{domain} inurl:".git/config" | inurl:".svn/entries"',
            'site:{domain} inurl:".DS_Store" | inurl:"wp-config.php~"',
        ],
    }

    # ── Gather everything ───────────────────────────────────────────────

    def gather(
        self, domain: str = "", email: str = "", ip_addr: str = "",
        username: str = "", phone: str = "", name: str = "",
    ) -> OSINTReport:
        """Gather OSINT from all available sources.

        Args:
            domain: Target domain (e.g., "example.com").
            email: Target email address.
            ip_addr: Target IP address.
            username: Target username/handle.
            phone: Target phone number.
            name: Target person name.

        Returns:
            OSINTReport with all generated search URLs and queries.
        """
        report = OSINTReport()
        targets = {}
        if domain: targets["domain"] = domain
        if email: targets["email"] = email
        if ip_addr: targets["ip"] = ip_addr
        if username: targets["username"] = username
        report.targets = targets

        # Domain searches
        if domain:
            report.results += [
                OSINTResult("crt.sh", "cert", self.search_crt_sh(domain), f"SSL certs for {domain}"),
                OSINTResult("Wayback", "domain", self.search_wayback(domain), f"Archive for {domain}"),
                OSINTResult("SecurityTrails", "domain", self.search_securitytrails(domain)),
                OSINTResult("URLScan", "domain", self.search_urlscan(domain)),
                OSINTResult("Hunter.io", "email", self.search_hunter(domain), f"Emails @{domain}"),
                OSINTResult("VirusTotal", "domain", self.search_virustotal(domain)),
                OSINTResult("Shodan", "domain", self.search_shodan(f"hostname:{domain}")),
                OSINTResult("IntelX", "domain", self.search_intelx(domain)),
                OSINTResult("LeakIX", "domain", self.search_leakix(f'hostname:"{domain}"')),
            ]
            report.generated_queries.append(self.search_theharvester(domain))
            for dork_list in self.DORKS.values():
                for dork in dork_list:
                    query = dork.replace("{domain}", domain)
                    report.results.append(OSINTResult("Google Dork", "dork", self.search_google(query), query[:100]))

        # Email searches
        if email:
            report.results += [
                OSINTResult("HaveIBeenPwned", "breach", self.search_haveibeenpwned(email)),
                OSINTResult("DeHashed", "breach", self.search_dehashed(email)),
                OSINTResult("Hunter.io", "email", self.search_hunter(email.split("@")[1] if "@" in email else email)),
                OSINTResult("IntelX", "email", self.search_intelx(email)),
                OSINTResult("GitHub", "code", self.search_github(email)),
            ]
            report.generated_queries.append(self.search_holehe(email))

        # IP searches
        if ip_addr:
            report.results += [
                OSINTResult("Shodan", "ip", self.search_shodan_ip(ip_addr)),
                OSINTResult("AlienVault OTX", "ip", self.search_alienvault(ip_addr)),
                OSINTResult("AbuseIPDB", "ip", self.search_abuseipdb(ip_addr)),
                OSINTResult("GreyNoise", "ip", self.search_greynoise(ip_addr)),
                OSINTResult("Censys", "ip", self.search_censys(ip_addr)),
                OSINTResult("VirusTotal", "ip", self.search_virustotal(ip_addr)),
            ]

        # Username searches
        if username:
            report.results += [
                OSINTResult("GitHub", "social", self.search_github(username)),
                OSINTResult("DeHashed", "breach", self.search_dehashed(username)),
            ]
            report.generated_queries.append(self.search_sherlock(username))

        # Phone
        if phone:
            report.generated_queries.append(self.search_phoneinfoga(phone))

        # 丁爸 OSINT 资源导航 (通用参考, 任何目标均可用)
        report.results += [
            OSINTResult("丁爸情报主站", "resource", self.dingba_home(), "OSINT 资源导航", "丁爸情报分析师工具箱主站"),
            OSINTResult("丁爸全球智库", "resource", self.dingba_thinktanks(), "全球智库导航", "汇集全球主要智库链接"),
            OSINTResult("丁爸国外资源", "resource", self.dingba_foreign_resources(), "国外搜索网站汇总", "100+ 搜索引擎/人物/图像/网络安全查询"),
            OSINTResult("丁爸情报工具", "resource", self.dingba_osint_tools(), "开源情报工具汇总", "按国家/社交媒体/暗网/GEOINT 分类书签"),
        ]

        return report

    def quick_lookup(self, query: str, category: str = "domain") -> Dict[str, str]:
        """Quick lookup: generate all relevant search URLs for a single query."""
        lookup_map = {
            "domain": {
                "crt.sh": self.search_crt_sh(query),
                "Wayback": self.search_wayback(query),
                "SecurityTrails": self.search_securitytrails(query),
                "Shodan": self.search_shodan(f"hostname:{query}"),
                "Censys": self.search_censys(query),
                "theHarvester": self.search_theharvester(query),
            },
            "email": {
                "HIBP": self.search_haveibeenpwned(query),
                "DeHashed": self.search_dehashed(query),
                "Hunter": self.search_hunter(query.split("@")[-1] if "@" in query else query),
                "holehe": self.search_holehe(query),
            },
            "ip": {
                "Shodan": self.search_shodan_ip(query),
                "AlienVault": self.search_alienvault(query),
                "AbuseIPDB": self.search_abuseipdb(query),
                "GreyNoise": self.search_greynoise(query),
            },
            "username": {
                "sherlock": self.search_sherlock(query),
                "GitHub": self.search_github(query),
            },
        }
        return lookup_map.get(category, {})

    def dork_generator(self, domain: str, category: str = "all") -> List[str]:
        """Generate Google dorks for a domain."""
        dorks = []
        cats = list(self.DORKS.keys()) if category == "all" else [category]
        for cat in cats:
            for dork in self.DORKS.get(cat, []):
                dorks.append(dork.replace("{domain}", domain))
        return dorks


def gather_intel(domain: str = "", email: str = "", ip_addr: str = "",
                 username: str = "") -> OSINTReport:
    """One-shot OSINT gathering."""
    return OSINTGatherer().gather(domain=domain, email=email, ip_addr=ip_addr, username=username)
