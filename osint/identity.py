"""identity.py — 身份画像聚合 (网络 + 地理 + 域名 拼凑身份画像)。

输入自动检测类型, 输出统一 IdentityProfile:
  ip     -> 网络身份 (bgpview ASN/ORG + ip-api 地理定位)
  domain -> 域名身份 (WHOIS 注册地)
  email  -> 邮箱身份 (域名 WHOIS 反查)

注: 开源版剥离电信画像 (phone 号段库依赖主仓库 telecom_fraud, 不开源)。
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from .cache import cache, cache_key
from .graph_engine import detect_type
from .http_client import safe_get_json
from .rate_limiter import limiter


@dataclass
class IdentityProfile:
    target: str = ""
    target_type: str = ""
    telecom: dict = field(default_factory=dict)   # 电信身份 (phone)
    network: dict = field(default_factory=dict)   # 网络身份 (ip: asn/org/geo)
    domain: dict = field(default_factory=dict)    # 域名身份 (whois)
    email: dict = field(default_factory=dict)     # 邮箱身份 (域名 whois 反查)
    summary: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    def to_markdown(self) -> str:
        lines = ["# 身份画像", "", f"- 目标: `{self.target}`", f"- 类型: {self.target_type}"]
        for title, section in (
            ("电信身份", self.telecom),
            ("网络身份", self.network),
            ("域名身份", self.domain),
            ("邮箱身份", self.email),
        ):
            if section:
                lines += ["", f"## {title}"]
                for k, v in section.items():
                    if v:
                        lines.append(f"- {k}: {v}")
        if self.summary:
            lines += ["", "## 摘要", self.summary]
        return "\n".join(lines)


def _network_profile(ip: str) -> dict:
    from .sources.bgpview import BgpViewAdapter

    out: dict = {"ip": ip, "asn": "", "org": "", "country": "", "city": "", "isp": ""}
    bgp = BgpViewAdapter()
    for a in bgp.cached_collect(ip, entity_type="ip"):  # 缓存+贴限统一, 与 collect 共享
        if a.entity_type == "asn":
            out["asn"] = a.value
            out["org"] = a.raw.get("org") or out["org"]
            out["country"] = a.raw.get("country") or out["country"]
        elif a.entity_type == "org":
            out["org"] = out["org"] or a.value

    # ip-api: 45 req/min (official free tier, http only), 走缓存避免重复
    geo = cache.get(cache_key("ip", ip, "ip-api"))
    if geo is None:
        limiter.acquire("ip-api", (45, 60))
        geo = safe_get_json(f"http://ip-api.com/json/{ip}")
        if geo is not None:
            cache.set(cache_key("ip", ip, "ip-api"), geo)
    if isinstance(geo, dict) and geo.get("status") == "success":
        # bgpview 的 asn/org/country 优先 (更精确), ip-api 补 geo 缺失字段
        if not out["country"]:
            out["country"] = geo.get("country", "")
        if not out["org"]:
            out["org"] = geo.get("org", "")
        if not out["asn"]:
            out["asn"] = geo.get("as", "")
        out["city"] = geo.get("city") or out["city"]
        out["isp"] = geo.get("isp") or out["isp"]
    return out


def _domain_profile(domain: str) -> dict:
    from .domain_intel import _query_whois

    out: dict = {"domain": domain}
    info = _query_whois(domain)
    if info:
        out.update(
            registrar=info.registrar,
            registrant_name=info.registrant_name,
            registrant_org=info.registrant_org,
            registrant_email=info.registrant_email,
            creation_date=info.creation_date,
        )
    return out


def _email_profile(email: str) -> dict:
    from .domain_intel import _query_whois

    dom = email.split("@")[-1] if "@" in email else ""
    out: dict = {"email": email, "domain": dom}
    if dom:
        info = _query_whois(dom)
        if info:
            out.update(
                registrar=info.registrar,
                registrant_name=info.registrant_name,
                registrant_org=info.registrant_org,
            )
    return out


def _summarize(prof: IdentityProfile) -> str:
    def seg(*vals) -> str:
        return " ".join(str(v) for v in vals if v)

    parts = []
    if prof.target_type == "ip":
        n = prof.network
        s = seg(n.get("asn"), n.get("org"), n.get("country"), n.get("city"))
        if s:
            parts.append(f"网络: {s}")
    elif prof.target_type == "domain":
        d = prof.domain
        s = seg(d.get("registrar"), d.get("registrant_org"), d.get("registrant_name"))
        if s:
            parts.append(f"域名: {s}")
    elif prof.target_type == "email":
        e = prof.email
        s = seg(e.get("domain"), e.get("registrant_org"), e.get("registrant_name"))
        if s:
            parts.append(f"邮箱: {s}")
    return " | ".join(parts)


def identity_profile(target: str) -> IdentityProfile:
    """聚合网络/地理/域名身份, 输入自动检测类型。"""
    ttype = detect_type(target)
    prof = IdentityProfile(target=target, target_type=ttype)

    if ttype == "ip":
        prof.network = _network_profile(target)
    elif ttype == "domain":
        prof.domain = _domain_profile(target)
    elif ttype == "email":
        prof.email = _email_profile(target)

    prof.summary = _summarize(prof)
    return prof


__all__ = ["identity_profile", "IdentityProfile"]
