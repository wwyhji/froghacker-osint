"""Tests for osint.sources — 注册/启用降级/解析 (网络全 mock)。"""
from __future__ import annotations

import pytest

from osint import sources
from osint.artifacts import OsintArtifact
from osint.domain_intel import CertEntry, DNSRecord, WaybackEntry, WhoisInfo
from osint.email_lookup import EmailRepResult

EXPECTED = [
    "crtsh", "wayback", "dns", "whois", "emailrep",
    "hackertarget", "urlscan", "otx", "github_api",
]


def test_all_mvp_sources_registered():
    for name in EXPECTED:
        assert name in sources.list_sources()


def test_get_adapter_unknown_raises():
    with pytest.raises(KeyError):
        sources.get_adapter("no_such_source")


def test_paid_adapter_disabled_without_key(monkeypatch):
    class _Paid(sources.SourceAdapter):
        name = "_paid_test"
        entity_types = ("domain",)
        paid = True
        env_key = "NO_SUCH_KEY_FOR_TEST"

        def collect(self, target, entity_type="", limit=20):
            return []

    monkeypatch.delenv("NO_SUCH_KEY_FOR_TEST", raising=False)
    a = _Paid()
    assert a.enabled() is False
    monkeypatch.setenv("NO_SUCH_KEY_FOR_TEST", "x")
    assert a.enabled() is True


def test_collect_swallows_adapter_error(monkeypatch):
    class _Boom(sources.SourceAdapter):
        name = "_boom_test"
        entity_types = ("domain",)

        def collect(self, target, entity_type="", limit=20):
            raise RuntimeError("boom")

    monkeypatch.setitem(sources._REGISTRY, "_boom_test", _Boom)
    monkeypatch.setitem(sources._instances, "_boom_test", _Boom())

    out = sources.collect("example.com", entity_type="domain", sources=["_boom_test"])
    assert out == []


def test_crtsh_parses_canned(monkeypatch):
    cert = CertEntry(common_name="example.com", subdomains=["www.example.com", "api.example.com"])
    monkeypatch.setattr("osint.domain_intel._query_crtsh", lambda d: [cert])
    arts = sources.get_adapter("crtsh").collect("example.com")
    types = {x.entity_type for x in arts}
    assert "cert" in types and "subdomain" in types
    subs = [x.value for x in arts if x.entity_type == "subdomain"]
    assert "www.example.com" in subs


def test_wayback_parses_canned(monkeypatch):
    snap = WaybackEntry(
        url="https://example.com/old", timestamp="20200101",
        status_code=200, snapshot_url="https://web.archive.org/web/20200101/https://example.com/old",
    )
    monkeypatch.setattr("osint.domain_intel._query_wayback", lambda d, max_results=10: [snap])
    arts = sources.get_adapter("wayback").collect("example.com")
    assert arts and arts[0].entity_type == "url"
    assert arts[0].value == "https://example.com/old"


def test_dns_parses_canned(monkeypatch):
    rec = DNSRecord(type="A", value="1.2.3.4")
    monkeypatch.setattr("osint.domain_intel._query_dns", lambda d: [rec])
    arts = sources.get_adapter("dns").collect("example.com")
    assert arts[0].entity_type == "dns_record"
    assert arts[0].raw["record_type"] == "A"


def test_whois_parses_canned(monkeypatch):
    info = WhoisInfo(
        domain="example.com", registrant_name="John",
        registrant_org="ACME", registrant_email="admin@example.com",
    )
    monkeypatch.setattr("osint.domain_intel._query_whois", lambda d: info)
    arts = sources.get_adapter("whois").collect("example.com")
    types = {x.entity_type for x in arts}
    assert {"person", "org", "email"} <= types


def test_emailrep_parses_canned(monkeypatch):
    r = EmailRepResult(
        email="admin@example.com", reputation="high", suspicious=False,
        blacklisted=False, malicious=False, spam=False, details="ok",
    )
    monkeypatch.setattr("osint.email_lookup._check_emailrep", lambda e: r)
    arts = sources.get_adapter("emailrep").collect("admin@example.com")
    assert arts[0].entity_type == "email"
    assert arts[0].value == "admin@example.com"


def test_hackertarget_parses_canned(monkeypatch):
    text = "www.example.com,1.2.3.4\napi.example.com,5.6.7.8\n"
    monkeypatch.setattr("osint.sources.hackertarget.safe_get_text", lambda *a, **k: text)
    arts = sources.get_adapter("hackertarget").collect("example.com")
    subs = {x.value for x in arts if x.entity_type == "subdomain"}
    assert "www.example.com" in subs and "api.example.com" in subs


def test_urlscan_parses_canned(monkeypatch):
    data = {"results": [{"page": {"domain": "example.com", "ip": "1.2.3.4", "url": "https://example.com/"}}]}
    monkeypatch.setattr("osint.sources.urlscan.safe_get_json", lambda *a, **k: data)
    arts = sources.get_adapter("urlscan").collect("example.com")
    types = {x.entity_type for x in arts}
    assert "domain" in types and "ip" in types


def test_otx_parses_canned(monkeypatch):
    data = {"passive_dns": [{"hostname": "www.example.com", "address": "1.2.3.4", "record_type": "A"}]}
    monkeypatch.setattr("osint.sources.otx.safe_get_json", lambda *a, **k: data)
    arts = sources.get_adapter("otx").collect("example.com")
    assert any(x.entity_type == "ip" and x.value == "1.2.3.4" for x in arts)


def test_github_api_parses_canned(monkeypatch):
    data = {
        "login": "octocat", "name": "The Octocat",
        "company": "@github", "blog": "https://github.com",
    }
    monkeypatch.setattr("osint.sources.github_api.safe_get_json", lambda *a, **k: data)
    arts = sources.get_adapter("github_api").collect("octocat")
    types = {x.entity_type for x in arts}
    assert "username" in types and "person" in types and "org" in types


# ── P1: 付费源 ────────────────────────────────────────────────────

PAID = ["hibp", "hunter", "shodan", "abuseipdb", "securitytrails", "censys", "vt"]


def test_paid_sources_registered():
    for name in PAID:
        assert name in sources.list_sources()


def test_hibp_disabled_without_key(monkeypatch):
    monkeypatch.delenv("HIBP_API_KEY", raising=False)
    assert sources.get_adapter("hibp").enabled() is False
    monkeypatch.setenv("HIBP_API_KEY", "x")
    assert sources.get_adapter("hibp").enabled() is True


def test_censys_enabled_needs_both_keys(monkeypatch):
    monkeypatch.delenv("CENSYS_API_ID", raising=False)
    monkeypatch.delenv("CENSYS_API_SECRET", raising=False)
    a = sources.get_adapter("censys")
    assert a.enabled() is False
    monkeypatch.setenv("CENSYS_API_ID", "id")
    assert a.enabled() is False  # secret 缺失
    monkeypatch.setenv("CENSYS_API_SECRET", "sec")
    assert a.enabled() is True


def test_hibp_parses_canned(monkeypatch):
    canned = [{"Name": "Adobe", "Title": "Adobe breach", "Domain": "adobe.com"}]
    monkeypatch.setattr("osint.sources.hibp.safe_get_json", lambda *a, **k: canned)
    arts = sources.get_adapter("hibp").collect("admin@example.com")
    assert arts[0].entity_type == "breach"
    assert arts[0].value == "Adobe"


def test_shodan_domain_parses_canned(monkeypatch):
    monkeypatch.setattr("osint.sources.shodan.safe_get_json", lambda *a, **k: {"subdomains": ["www", "api"]})
    arts = sources.get_adapter("shodan").collect("example.com")
    subs = {x.value for x in arts if x.entity_type == "subdomain"}
    assert "www.example.com" in subs and "api.example.com" in subs


def test_hunter_parses_canned(monkeypatch):
    canned = {"data": {"emails": [{"value": "admin@example.com"}]}}
    monkeypatch.setattr("osint.sources.hunter.safe_get_json", lambda *a, **k: canned)
    arts = sources.get_adapter("hunter").collect("example.com")
    assert arts[0].entity_type == "email"
    assert arts[0].value == "admin@example.com"


def test_vt_domain_parses_canned(monkeypatch):
    canned = {"data": {"attributes": {"last_dns_records": [{"type": "A", "value": "1.2.3.4"}]}}}
    monkeypatch.setattr("osint.sources.vt.safe_get_json", lambda *a, **k: canned)
    arts = sources.get_adapter("vt").collect("example.com")
    assert arts[0].entity_type == "dns_record"
    assert arts[0].raw["record_type"] == "A"


# ── S-1: 泄露/暗网源 ─────────────────────────────────────────────

LEAK_SOURCES = ["greynoise", "leakix", "dehashed", "intelx"]


def test_leak_sources_registered():
    for name in LEAK_SOURCES:
        assert name in sources.list_sources()


def test_greynoise_parses_canned(monkeypatch):
    canned = {
        "ip": "1.2.3.4", "classification": "malicious",
        "metadata": {"organization": "Evil Corp"},
    }
    monkeypatch.setattr("osint.sources.greynoise.safe_get_json", lambda *a, **k: canned)
    arts = sources.get_adapter("greynoise").collect("1.2.3.4")
    types = {x.entity_type for x in arts}
    assert "ip" in types and "org" in types
    ip_art = next(x for x in arts if x.entity_type == "ip")
    assert ip_art.confidence == "high"


def test_leakix_parses_canned(monkeypatch):
    canned = {"items": [
        {"host": "api.example.com", "ip": "1.2.3.4", "event_type": "database"},
    ]}
    monkeypatch.setattr("osint.sources.leakix.safe_get_json", lambda *a, **k: canned)
    arts = sources.get_adapter("leakix").collect("example.com")
    types = {x.entity_type for x in arts}
    assert "subdomain" in types and "ip" in types


def test_dehashed_parses_canned_skips_credentials(monkeypatch):
    canned = {"entries": [{
        "email": "user@example.com", "username": "user",
        "name": "John", "ip_address": "1.2.3.4",
        "database_name": "Adobe", "password": "supersecret",
    }]}
    monkeypatch.setattr("osint.sources.dehashed.safe_get_json", lambda *a, **k: canned)
    arts = sources.get_adapter("dehashed").collect("user@example.com")
    types = {x.entity_type for x in arts}
    assert {"email", "username", "person", "ip"} <= types
    # 凭据字段不得进入任何 artifact
    for a in arts:
        assert "password" not in a.raw
        assert "supersecret" not in a.value


def test_dehashed_disabled_without_both_keys(monkeypatch):
    monkeypatch.delenv("DEHASHED_EMAIL", raising=False)
    monkeypatch.delenv("DEHASHED_API_KEY", raising=False)
    a = sources.get_adapter("dehashed")
    assert a.enabled() is False
    monkeypatch.setenv("DEHASHED_EMAIL", "x@y.z")
    assert a.enabled() is False
    monkeypatch.setenv("DEHASHED_API_KEY", "k")
    assert a.enabled() is True


def test_intelx_parses_canned(monkeypatch):
    monkeypatch.setattr(
        "osint.sources.intelx.safe_post_json",
        lambda *a, **k: {"id": "abc123"},
    )
    monkeypatch.setattr(
        "osint.sources.intelx.safe_get_json",
        lambda *a, **k: {"records": [{"bucket": "darkweb", "name": "leak_db"}]},
    )
    arts = sources.get_adapter("intelx").collect("user@example.com")
    assert arts[0].entity_type == "breach"
    assert arts[0].value == "leak_db"


# ── S-2: 电话 OSINT (开源版只保留国际区号解析) ──────────────────

def test_phone_source_registered():
    assert "phone" in sources.list_sources()


def test_phone_analyze_intl():
    from osint.sources.phone import analyze_phone
    info = analyze_phone("+44 20 7946 0958")
    assert info["valid"] and info["kind"] == "intl"
    assert info["country"] == "英国"


def test_phone_adapter_collects_phone_only():
    arts = sources.get_adapter("phone").collect("+44 20 7946 0958")
    types = {x.entity_type for x in arts}
    assert types == {"phone"}  # 开源版无运营商 org (剥离 telecom_fraud 号段库)
    phone_art = arts[0]
    assert phone_art.value == "+442079460958"  # normalize 去分隔符


# ── S-3: 区块链追踪 ─────────────────────────────────────────────

CRYPTO_SOURCES = ["blockchain", "etherscan", "chainabuse"]


def test_crypto_sources_registered():
    for name in CRYPTO_SOURCES:
        assert name in sources.list_sources()


def test_blockchain_parses_canned(monkeypatch):
    canned = {"final_balance": 100000000, "n_tx": 5,
              "total_received": 200000000, "total_sent": 100000000}
    monkeypatch.setattr("osint.sources.blockchain.safe_get_json", lambda *a, **k: canned)
    arts = sources.get_adapter("blockchain").collect("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
    assert arts[0].entity_type == "crypto_address"
    assert arts[0].raw["final_balance_btc"] == 1.0
    assert arts[0].raw["n_tx"] == 5


def test_etherscan_parses_canned(monkeypatch):
    canned = {"status": "1", "result": "1000000000000000000"}
    monkeypatch.setattr("osint.sources.etherscan.safe_get_json", lambda *a, **k: canned)
    arts = sources.get_adapter("etherscan").collect("0x" + "a" * 40)
    assert arts[0].raw["balance_eth"] == 1.0


def test_chainabuse_parses_canned(monkeypatch):
    canned = {"reports": [{"category": "ransomware"}]}
    monkeypatch.setattr("osint.sources.chainabuse.safe_get_json", lambda *a, **k: canned)
    arts = sources.get_adapter("chainabuse").collect("0x" + "b" * 40)
    types = {x.entity_type for x in arts}
    assert {"crypto_address", "breach"} <= types


# ── S-4: 社交平台深度 ───────────────────────────────────────────

def test_reddit_source_registered():
    assert "reddit" in sources.list_sources()


def test_reddit_parses_canned(monkeypatch):
    canned = {"data": {"link_karma": 100, "comment_karma": 50, "created_utc": 1234567890}}
    monkeypatch.setattr("osint.sources.reddit.safe_get_json", lambda *a, **k: canned)
    arts = sources.get_adapter("reddit").collect("someuser")
    assert arts[0].entity_type == "social_profile"
    assert arts[0].raw["link_karma"] == 100
    assert arts[0].raw["username"] == "someuser"


def test_username_platforms_expanded():
    from osint.username_search import PLATFORMS
    assert len(PLATFORMS) >= 35  # 原 29 + 6 补充 (含中文平台)


# ── key 管理 (统一入口) ───────────────────────────────────────

def test_key_status_lists_paid_sources():
    rows = sources.key_status()
    assert any(r["source"] == "shodan" for r in rows)
    assert any(r["source"] == "censys" for r in rows)
    censys = next(r for r in rows if r["source"] == "censys")
    assert len(censys["keys"]) == 2  # 双 key (ID + SECRET)
    assert all("configured" in k for k in censys["keys"])


def test_set_unset_env_key(tmp_path, monkeypatch):
    monkeypatch.setattr(sources, "_dotenv_path", lambda: tmp_path / ".env")
    assert sources.set_env_key("TEST_OSINT_KEY", "abc")
    assert "TEST_OSINT_KEY=abc" in (tmp_path / ".env").read_text()
    assert sources.set_env_key("TEST_OSINT_KEY", "xyz")  # 更新
    assert "TEST_OSINT_KEY=xyz" in (tmp_path / ".env").read_text()
    assert sources.unset_env_key("TEST_OSINT_KEY")
    assert "TEST_OSINT_KEY" not in (tmp_path / ".env").read_text()
    monkeypatch.delenv("TEST_OSINT_KEY", raising=False)


def test_set_env_key_rejects_bad_format(tmp_path, monkeypatch):
    monkeypatch.setattr(sources, "_dotenv_path", lambda: tmp_path / ".env")
    assert sources.set_env_key("BAD=KEY", "v") is False
    assert sources.set_env_key("", "v") is False


def test_load_dotenv_reads_kv(tmp_path, monkeypatch):
    from osint import http_client
    env = tmp_path / ".env"
    env.write_text("# comment\nTEST_DOTENV_K=hello\nQUOTED=\"v\"\n", encoding="utf-8")
    monkeypatch.setattr(http_client, "_ENV_PATH", env)
    monkeypatch.delenv("TEST_DOTENV_K", raising=False)
    http_client.load_dotenv(force=True)
    assert http_client.get_key("TEST_DOTENV_K") == "hello"
    assert http_client.get_key("QUOTED") == "v"
    monkeypatch.delenv("TEST_DOTENV_K", raising=False)
    monkeypatch.delenv("QUOTED", raising=False)


# ── P2: ASN/MAC 网络情报 ────────────────────────────────────────

def test_bgpview_ip_parses_canned(monkeypatch):
    canned = {"data": {"prefixes": [
        {"prefix": "8.8.8.0/24",
         "asn": {"asn": 15169, "name": "GOOGLE", "country_code": "US"}},
    ]}}
    monkeypatch.setattr("osint.sources.bgpview.safe_get_json", lambda *a, **k: canned)
    arts = sources.get_adapter("bgpview").collect("8.8.8.8", entity_type="ip")
    types = {x.entity_type for x in arts}
    assert {"ip", "asn", "org"} <= types
    asn = next(x for x in arts if x.entity_type == "asn")
    assert asn.value == "as15169"  # normalize asn 转小写
    org = next(x for x in arts if x.entity_type == "org")
    assert org.value == "GOOGLE"


def test_bgpview_asn_parses_canned(monkeypatch):
    def fake(url, *a, **k):
        if "/prefixes" in url:
            return {"data": {"ipv4_prefixes": [{"prefix": "8.8.8.0/24"}]}}
        return {"data": {"asn": 15169, "name": "GOOGLE", "country_code": "US"}}

    monkeypatch.setattr("osint.sources.bgpview.safe_get_json", fake)
    arts = sources.get_adapter("bgpview").collect("AS15169", entity_type="asn")
    types = {x.entity_type for x in arts}
    assert {"asn", "org"} <= types
    asn = next(x for x in arts if x.entity_type == "asn")
    assert asn.value == "as15169"  # normalize asn 转小写
    assert "8.8.8.0/24" in asn.raw.get("prefixes", [])


def test_bgpview_asn_empty_meta(monkeypatch):
    # meta 无 data 字段 (如 {"status":"error"}) 不应崩溃
    monkeypatch.setattr(
        "osint.sources.bgpview.safe_get_json",
        lambda url, *a, **k: ({"status": "error"} if "/prefixes" not in url else None),
    )
    arts = sources.get_adapter("bgpview").collect("AS999999", entity_type="asn")
    asn = next(x for x in arts if x.entity_type == "asn")
    assert asn.value == "as999999"
    assert asn.raw.get("org") == ""
    assert all(x.entity_type != "org" for x in arts)


def test_macvendor_parses_canned(monkeypatch):
    monkeypatch.setattr("osint.sources.macvendor.safe_get_text", lambda *a, **k: "Apple, Inc.")
    arts = sources.get_adapter("macvendor").collect("00:1A:2B:3C:4D:5E", entity_type="mac")
    types = {x.entity_type for x in arts}
    assert {"mac", "org"} <= types
    mac = next(x for x in arts if x.entity_type == "mac")
    assert mac.value == "001a2b3c4d5e"  # normalize 去冒号小写
    org = next(x for x in arts if x.entity_type == "org")
    assert org.value == "Apple, Inc."


def test_username_platforms_include_telegram_instagram():
    from osint.username_search import PLATFORMS
    cfg = {p[0]: p for p in PLATFORMS}
    assert "Telegram" in cfg and "Instagram" in cfg
    assert cfg["Telegram"][1] == "https://t.me/{username}"
    assert cfg["Instagram"][1] == "https://www.instagram.com/{username}/"


# ── P4: 并发顺序确定性 ──────────────────────────────────────────

def test_collect_concurrent_preserves_registration_order(monkeypatch):
    import time

    monkeypatch.setenv("OSINT_MAX_WORKERS", "3")
    sources.cache.clear()

    class _A(sources.SourceAdapter):
        name = "_ord_a"
        entity_types = ("_ord",)
        polite_delay = 0.0

        def collect(self, target, entity_type="", limit=20):
            return [OsintArtifact(source=self.name, entity_type="_ord", value="a")]

    class _B(sources.SourceAdapter):
        name = "_ord_b"
        entity_types = ("_ord",)
        polite_delay = 0.0

        def collect(self, target, entity_type="", limit=20):
            time.sleep(0.05)  # 最后完成, 验证结果仍按注册顺序重组
            return [OsintArtifact(source=self.name, entity_type="_ord", value="b")]

    class _C(sources.SourceAdapter):
        name = "_ord_c"
        entity_types = ("_ord",)
        polite_delay = 0.0

        def collect(self, target, entity_type="", limit=20):
            return [OsintArtifact(source=self.name, entity_type="_ord", value="c")]

    for cls in (_A, _B, _C):
        monkeypatch.setitem(sources._REGISTRY, cls.name, cls)
        monkeypatch.setitem(sources._instances, cls.name, cls())

    try:
        out = sources.collect("x", entity_type="_ord")
        assert [a.value for a in out] == ["a", "b", "c"]
    finally:
        sources.cache.clear()
