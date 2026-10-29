"""Tests for osint.identity — 身份画像聚合 (网络/域名/邮箱, 网络全 mock)。"""
from __future__ import annotations

from osint.domain_intel import WhoisInfo
from osint.identity import IdentityProfile, identity_profile


def test_identity_ip(monkeypatch):
    monkeypatch.setattr(
        "osint.sources.bgpview.safe_get_json",
        lambda *a, **k: {"data": {"prefixes": [
            {"prefix": "8.8.8.0/24",
             "asn": {"asn": 15169, "name": "GOOGLE", "country_code": "US"}},
        ]}},
    )
    monkeypatch.setattr(
        "osint.identity.safe_get_json",
        lambda *a, **k: {"status": "success", "country": "United States",
                         "city": "Mountain View", "isp": "Google LLC",
                         "org": "Google", "as": "AS15169 Google LLC"},
    )
    p = identity_profile("8.8.8.8")
    assert p.target_type == "ip"
    assert p.network.get("asn") == "as15169"     # bgpview 精确 ASN 优先 (normalize 小写)
    assert p.network.get("org") == "GOOGLE"
    assert p.network.get("country") == "US"
    assert p.network.get("city") == "Mountain View"
    assert p.network.get("isp") == "Google LLC"


def test_identity_domain(monkeypatch):
    info = WhoisInfo(domain="example.com", registrar="VeriSign",
                     registrant_org="ACME", registrant_name="John Doe")
    monkeypatch.setattr("osint.domain_intel._query_whois", lambda d: info)
    p = identity_profile("example.com")
    assert p.target_type == "domain"
    assert p.domain.get("registrar") == "VeriSign"
    assert p.domain.get("registrant_org") == "ACME"


def test_identity_email(monkeypatch):
    info = WhoisInfo(domain="example.com", registrar="VeriSign",
                     registrant_org="ACME", registrant_name="John Doe")
    monkeypatch.setattr("osint.domain_intel._query_whois", lambda d: info)
    p = identity_profile("admin@example.com")
    assert p.target_type == "email"
    assert p.email.get("domain") == "example.com"
    assert p.email.get("registrant_org") == "ACME"


def test_identity_profile_markdown():
    p = IdentityProfile(target="example.com", target_type="domain",
                        domain={"registrar": "VeriSign", "registrant_org": "ACME"},
                        summary="域名: VeriSign ACME")
    md = p.to_markdown()
    assert "# 身份画像" in md
    assert "VeriSign" in md
    assert p.to_dict()["target"] == "example.com"
