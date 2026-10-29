"""rate_limiter.py — per-source 声明式 token bucket 限流器 (跨调用共享, 贴限)。

免费 OSINT API 限额按源/按时间窗各不相同 (macvendors 1/s, ip-api 45/min,
hackertarget 50/day, urlscan 20/min...)。模块级单例 limiter 跨 collect 调用
共享额度, 避免批量/多跳/轮询时触 429。不落盘 (同 cache)。
"""

from __future__ import annotations

import threading
import time


class TokenBucket:
    """令牌桶: 容量=requests, 恒定速率 refill (requests/seconds)。"""

    def __init__(self, requests: float, seconds: float, clock=time.monotonic):
        if requests <= 0 or seconds <= 0:
            raise ValueError(f"invalid rate_limit ({requests}, {seconds})")
        self.rate = requests / seconds            # token/秒
        self.capacity = float(requests)
        self._tokens = self.capacity
        self._last = clock()
        self._clock = clock
        self._lock = threading.Lock()

    def _refill(self) -> None:
        now = self._clock()
        self._tokens = min(self.capacity, self._tokens + (now - self._last) * self.rate)
        self._last = now

    def try_acquire(self) -> bool:
        """非阻塞取 1 token, 有则扣并返回 True (测试友好)。"""
        with self._lock:
            self._refill()
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return True
            return False

    def acquire(self) -> None:
        """阻塞直到取到 1 token。"""
        while not self.try_acquire():
            with self._lock:
                self._refill()
                need = (1.0 - self._tokens) / self.rate
            time.sleep(max(0.0, need))


class RateLimiter:
    """per-source token bucket 注册表, 跨 collect 调用共享额度。"""

    def __init__(self):
        self._buckets: dict[str, TokenBucket] = {}
        self._lock = threading.Lock()

    def acquire(self, name: str, rate_limit: tuple | None) -> None:
        """按 name + rate_limit 取 token; rate_limit 为空 (不限流) 直接返回。"""
        if not rate_limit:
            return
        bucket = self._buckets.get(name)
        if bucket is None:
            with self._lock:
                bucket = self._buckets.get(name)
                if bucket is None:
                    bucket = TokenBucket(rate_limit[0], rate_limit[1])
                    self._buckets[name] = bucket
        bucket.acquire()

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()


# 模块级单例 (collect / identity 共享)
limiter = RateLimiter()


__all__ = ["TokenBucket", "RateLimiter", "limiter"]
