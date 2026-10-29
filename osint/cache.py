"""cache.py — OSINT 内存 TTL 缓存 (敏感数据不落盘, 仅进程内降频)。

OSINT 结果含邮箱/泄露/身份信息, 因此只存内存 TTL, 不写盘。
collect() 与 graph BFS 共享同一进程级单例, 重复查询命中缓存。
"""

from __future__ import annotations

import os
import time

from .artifacts import synonym_key

_DEFAULT_TTL = 300.0


def _env_ttl() -> float:
    """默认 TTL 300s, 可被 OSINT_CACHE_TTL 覆盖。"""
    try:
        return float(os.environ.get("OSINT_CACHE_TTL", str(_DEFAULT_TTL)))
    except ValueError:
        return _DEFAULT_TTL


def cache_key(entity_type: str, value: str, source_name: str) -> tuple:
    """构造缓存键: (synonym_key(entity_type, value), source_name)。

    synonym_key 做同义撞击 (email/url → domain), 让同义实体共享缓存。
    """
    return (synonym_key(entity_type or "", value), source_name)


class TTLCache:
    """dict[key -> (expire_ts, value)] 的进程内 TTL 缓存。"""

    def __init__(self, ttl: float | None = None):
        self.ttl = ttl if ttl is not None else _env_ttl()
        self._store: dict = {}

    def get(self, key):
        item = self._store.get(key)
        if item is None:
            return None
        expire_ts, value = item
        if time.monotonic() < expire_ts:
            return value
        del self._store[key]
        return None

    def set(self, key, value, ttl: float | None = None) -> None:
        t = ttl if ttl is not None else self.ttl
        self._store[key] = (time.monotonic() + t, value)

    def clear(self) -> None:
        self._store.clear()

    def __len__(self) -> int:
        return len(self._store)


# 进程级单例 (collect / graph BFS 共享)
cache = TTLCache()


__all__ = ["TTLCache", "cache", "cache_key"]
