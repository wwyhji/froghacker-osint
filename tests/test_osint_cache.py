"""Tests for osint.cache — TTL 命中/过期/键规范化 + collect 缓存集成。"""
from __future__ import annotations

from osint import sources
from osint.artifacts import OsintArtifact
from osint.cache import TTLCache, cache_key


def test_cache_key_synonym_collision():
    # 形式归一化
    assert cache_key("domain", "Example.COM.", "dns") == ("domain:example.com", "dns")
    assert cache_key("mac", "00:1A:2B:3C:4D:5E", "macvendor") == ("mac:001a2b3c4d5e", "macvendor")
    # 同义撞击: email/url → domain
    assert cache_key("email", "admin@example.com", "s") == ("domain:example.com", "s")
    assert cache_key("url", "https://example.com/a", "s") == ("domain:example.com", "s")
    # email 的域名 = 直接 domain (同一底层实体撞同一键)
    assert cache_key("email", "admin@example.com", "s") == cache_key("domain", "example.com", "s")


def test_cache_hit():
    c = TTLCache(ttl=100)
    c.set("k", "v")
    assert c.get("k") == "v"


def test_cache_miss_returns_none():
    c = TTLCache(ttl=100)
    assert c.get("missing") is None


def test_cache_expiry():
    c = TTLCache(ttl=0)  # ttl=0 -> 立即过期
    c.set("k", "v")
    assert c.get("k") is None
    assert "k" not in c._store  # 过期项被惰性删除


def test_cache_clear():
    c = TTLCache(ttl=100)
    c.set("k", "v")
    c.clear()
    assert c.get("k") is None


def test_collect_hits_cache(monkeypatch):
    calls = {"n": 0}

    class _Cached(sources.SourceAdapter):
        name = "_cached_test"
        entity_types = ("domain",)
        polite_delay = 0.0

        def collect(self, target, entity_type="", limit=20):
            calls["n"] += 1
            return [OsintArtifact(source=self.name, entity_type="domain", value=target)]

    monkeypatch.setitem(sources._REGISTRY, "_cached_test", _Cached)
    monkeypatch.setitem(sources._instances, "_cached_test", _Cached())
    monkeypatch.setenv("OSINT_MAX_WORKERS", "1")  # 串行, 确定性强

    sources.cache.clear()
    try:
        out1 = sources.collect("example.com", entity_type="domain", sources=["_cached_test"])
        out2 = sources.collect("example.com", entity_type="domain", sources=["_cached_test"])
        assert len(out1) == 1 and len(out2) == 1
        assert calls["n"] == 1  # 第二次命中缓存, 不再请求网络
    finally:
        sources.cache.clear()


def test_cached_collect_shared_between_collect_and_direct(monkeypatch):
    # cache 下沉到 SourceAdapter 后, 直调 (identity 场景) 与 collect() 共享缓存
    calls = {"n": 0}

    class _Shared(sources.SourceAdapter):
        name = "_shared_test"
        entity_types = ("domain",)
        polite_delay = 0.0

        def collect(self, target, entity_type="", limit=20):
            calls["n"] += 1
            return [OsintArtifact(source=self.name, entity_type="domain", value=target)]

    monkeypatch.setitem(sources._REGISTRY, "_shared_test", _Shared)
    monkeypatch.setitem(sources._instances, "_shared_test", _Shared())
    monkeypatch.setenv("OSINT_MAX_WORKERS", "1")

    sources.cache.clear()
    try:
        a = sources.get_adapter("_shared_test")
        a.cached_collect("example.com", entity_type="domain")   # 直调, 打网络
        a.cached_collect("example.com", entity_type="domain")   # 直调, 命中缓存
        sources.collect("example.com", entity_type="domain", sources=["_shared_test"])  # collect 也命中
        assert calls["n"] == 1
    finally:
        sources.cache.clear()
