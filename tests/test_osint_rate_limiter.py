"""Tests for osint.rate_limiter — per-source token bucket 贴限。"""
from __future__ import annotations

import pytest

from osint import sources
from osint.artifacts import OsintArtifact
from osint.rate_limiter import RateLimiter, TokenBucket, limiter


# ── TokenBucket ──────────────────────────────────────────────────

def test_token_bucket_depletes_and_refills():
    t = [0.0]
    tb = TokenBucket(requests=2, seconds=60, clock=lambda: t[0])
    assert tb.try_acquire() is True
    assert tb.try_acquire() is True
    assert tb.try_acquire() is False          # 耗尽
    t[0] += 30.0                               # 前进 30s -> refill 1 token (2/60)
    assert tb.try_acquire() is True
    assert tb.try_acquire() is False


def test_token_bucket_capacity_capped():
    t = [0.0]
    tb = TokenBucket(requests=2, seconds=60, clock=lambda: t[0])
    t[0] += 1000.0                             # 长时间空闲, 不应超容量
    assert tb.try_acquire() is True
    assert tb.try_acquire() is True
    assert tb.try_acquire() is False           # 容量封顶 = requests


def test_token_bucket_invalid_rate():
    with pytest.raises(ValueError):
        TokenBucket(requests=0, seconds=60)
    with pytest.raises(ValueError):
        TokenBucket(requests=1, seconds=0)


# ── RateLimiter ──────────────────────────────────────────────────

def test_limiter_no_limit_returns_immediately():
    rl = RateLimiter()
    rl.acquire("x", None)
    rl.acquire("x", ())
    assert rl._buckets == {}                   # 不限流不建 bucket


def test_limiter_reset_clears_buckets():
    rl = RateLimiter()
    rl.acquire("x", (1, 1))
    assert "x" in rl._buckets
    rl.reset()
    assert rl._buckets == {}


# ── collect 集成 ─────────────────────────────────────────────────

def test_collect_acquires_limiter(monkeypatch):
    calls = []

    class _Limited(sources.SourceAdapter):
        name = "_limited_test"
        entity_types = ("domain",)
        polite_delay = 0.0
        rate_limit = (1, 1)

        def collect(self, target, entity_type="", limit=20):
            return [OsintArtifact(source=self.name, entity_type="domain", value=target)]

    monkeypatch.setitem(sources._REGISTRY, "_limited_test", _Limited)
    monkeypatch.setitem(sources._instances, "_limited_test", _Limited())
    monkeypatch.setattr(sources.limiter, "acquire", lambda name, rl: calls.append((name, rl)))
    monkeypatch.setenv("OSINT_MAX_WORKERS", "1")

    sources.cache.clear()
    try:
        sources.collect("example.com", entity_type="domain", sources=["_limited_test"])
        assert ("_limited_test", (1, 1)) in calls
    finally:
        sources.cache.clear()
        limiter.reset()


def test_free_sources_declare_rate_limit():
    # 高置信查证源必须声明限流, 防止批量/多跳触 429
    expected = {
        "macvendor": (1, 1),
        "github_api": (60, 3600),
        "hackertarget": (50, 86400),
        "urlscan": (20, 60),
        "bgpview": (2, 1),
    }
    for name, rl in expected.items():
        a = sources.get_adapter(name)
        assert a.rate_limit == rl, f"{name} rate_limit 未声明或错误: {a.rate_limit}"
