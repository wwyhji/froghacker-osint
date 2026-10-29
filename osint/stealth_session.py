"""Stealth HTTP session — drop-in requests.Session with polite anti-crawl.

Polite-collection subset (non-adversarial):
  - Rotates standard browser User-Agent / Sec-CH-* headers per request
  - Random delay between requests (configurable per-domain)
  - Exponential backoff retry on 429/503, respects Retry-After
  - Detects WAF/CAPTCHA challenges; returns the response as-is (does not bypass)

Omitted from the open-source build (adversarial, kept in the main repo):
  - ProxyPool (proxy rotation to evade IP blocks)
  - BrowserStealth (Playwright/CDP fingerprint patching)

Usage:
    session = StealthSession(profile="chrome_win")
    resp = session.get("https://target.com/page")
    # Behaves like requests.Session, with polite throttling applied transparently.
"""

from __future__ import annotations

import random
import time
import threading
from typing import Optional
from urllib.parse import urlparse

import requests

from .header_spoofer import HeaderSpoofer
from .challenge_detector import ChallengeDetected, ChallengeDetector


class StealthSession(requests.Session):
    """Drop-in requests.Session replacement with polite anti-crawl throttling.

    Features:
      - Rotates User-Agent and Sec-CH-* headers per request
      - Random delay between requests (configurable per-domain)
      - Exponential backoff retry on 429 (Rate Limit) and 503 (Service Unavailable)
      - Respects Retry-After header
      - Detects WAF/CAPTCHA pages; by default returns the response as-is
        (no bypass). Set raise_on_challenge=True to raise ChallengeDetected instead.

    All normal requests.Session behavior (cookies, headers, auth, hooks)
    remains intact.
    """

    def __init__(
        self,
        profile: str | None = None,
        min_delay: float = 0.5,
        max_delay: float = 2.0,
        max_retries: int = 3,
        backoff_base: float = 2.0,
        max_backoff: float = 60.0,
        raise_on_challenge: bool = False,
    ) -> None:
        """Initialize stealth session.

        Args:
            profile: Browser profile name (e.g. "chrome_win", "firefox_mac").
                     None selects a random profile per request.
            min_delay: Minimum delay in seconds between requests to same domain.
            max_delay: Maximum delay in seconds between requests to same domain.
            max_retries: Max retry attempts on 429/503.
            backoff_base: Base multiplier for exponential backoff.
            max_backoff: Maximum backoff wait time in seconds.
            raise_on_challenge: If True, raises ChallengeDetected on WAF/CAPTCHA.
                                If False (default), returns the response as-is.
        """
        super().__init__()
        self._spoofer = HeaderSpoofer()
        self._profile = profile
        self._min_delay = min_delay
        self._max_delay = max_delay
        self._max_retries = max_retries
        self._backoff_base = backoff_base
        self._max_backoff = max_backoff
        self._raise_on_challenge = raise_on_challenge

        # Per-domain tracking
        self._last_request: dict[str, float] = {}
        self._domain_delays: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

        # Apply initial headers
        self._apply_headers()

    # ── Public API ──────────────────────────────────────────────────────────

    def domain_delay(self, domain: str, min_s: float, max_s: float) -> None:
        """Configure per-domain delay range.

        Args:
            domain: Domain name (e.g. "example.com").
            min_s: Minimum delay in seconds.
            max_s: Maximum delay in seconds.
        """
        self._domain_delays[domain] = (min_s, max_s)

    def export_cookies(self) -> dict:
        """Export cookies as a dict suitable for sharing between sessions."""
        return requests.utils.dict_from_cookiejar(self.cookies)

    def import_cookies(self, cookies: dict) -> None:
        """Import cookies from a dict."""
        for name, value in cookies.items():
            self.cookies.set(name, value)

    # ── Core request override ───────────────────────────────────────────────

    def request(self, method: str | bytes, url: str | bytes,
                *args, **kwargs) -> requests.Response:
        """Override Session.request() with polite throttling.

        Transparent to callers: same signature as requests.Session.request().
        """
        # Serialize method/url (requests passes them as str or bytes)
        method_str = method.decode("utf-8") if isinstance(method, bytes) else method
        url_str = url.decode("utf-8") if isinstance(url, bytes) else url

        domain = self._get_domain(url_str)

        # Apply rate limiting delay
        self._apply_delay(domain)

        # Rotate headers for a fresh profile
        self._apply_headers()

        # Retry loop
        last_exc: Optional[Exception] = None
        for attempt in range(self._max_retries + 1):
            try:
                resp = super().request(method_str, url_str, *args, **kwargs)

                # Detect anti-bot challenge (report or return as-is, never bypass)
                if ChallengeDetector.is_blocked(resp):
                    challenge_type, detail = ChallengeDetector.detect_with_detail(resp)
                    if self._raise_on_challenge:
                        raise ChallengeDetected(
                            url=url_str,
                            challenge_type=challenge_type or "unknown",
                            status_code=resp.status_code,
                            detail=detail,
                        )
                    # Default: return the blocked response unchanged
                    return resp

                # Retry on rate limit / service unavailable
                if resp.status_code in (429, 503) and attempt < self._max_retries:
                    wait = self._get_retry_after(resp, attempt)
                    time.sleep(wait)
                    continue

                # Track success
                with self._lock:
                    self._last_request[domain] = time.time()

                return resp

            except ChallengeDetected:
                raise
            except requests.RequestException as e:
                last_exc = e
                if attempt < self._max_retries:
                    wait = self._backoff_base ** attempt
                    wait = min(wait, self._max_backoff)
                    time.sleep(wait)
                continue

        # All retries exhausted
        if last_exc:
            raise last_exc
        # Should not reach here, but satisfy type checker
        return super().request(method_str, url_str, *args, **kwargs)

    # ── Internal helpers ────────────────────────────────────────────────────

    def _apply_headers(self) -> None:
        """Replace session headers with a fresh browser-consistent set.

        Preserves any user-set custom headers (Authorization, etc.).
        """
        profile = self._profile
        if profile is None:
            # Random profile each time
            profile = random.choice(list(self._spoofer.profiles.keys()))

        new_headers = self._spoofer.get_headers(profile)

        # Merge: user-set headers take priority over spoofed ones
        existing = dict(self.headers)
        # Remove default headers that we want to spoof
        for key in list(existing.keys()):
            if key.lower() in {
                "user-agent", "accept", "accept-language", "accept-encoding",
                "sec-ch-ua", "sec-ch-ua-platform", "sec-ch-ua-mobile",
                "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest",
                "sec-fetch-user", "cache-control",
                "upgrade-insecure-requests",
            }:
                del existing[key]

        # Apply spoofed headers, then restore user-set ones
        self.headers.clear()
        self.headers.update(new_headers)
        self.headers.update(existing)

    def _apply_delay(self, domain: str) -> None:
        """Sleep for a random delay based on domain configuration."""
        min_d, max_d = self._domain_delays.get(domain, (self._min_delay, self._max_delay))

        with self._lock:
            last = self._last_request.get(domain, 0)
            elapsed = time.time() - last
            if elapsed < min_d:
                # Still within minimum delay window
                delay = random.uniform(min_d - elapsed, max_d)
                delay = max(0, delay)
            else:
                delay = random.uniform(0, max_d - min_d) if max_d > min_d else 0

        if delay > 0:
            time.sleep(delay)

    @staticmethod
    def _get_domain(url: str) -> str:
        """Extract domain from URL for per-domain tracking."""
        try:
            return urlparse(url).netloc.split(":")[0]
        except Exception:
            return url

    @staticmethod
    def _get_retry_after(response, attempt: int) -> float:
        """Determine wait time from Retry-After header or exponential backoff."""
        retry_after = response.headers.get("Retry-After", "")
        if retry_after:
            try:
                return float(retry_after)
            except ValueError:
                pass

        # Exponential backoff: 1s, 2s, 4s, ...
        wait = 2 ** attempt
        # Add jitter (±25%)
        jitter = wait * 0.25 * random.uniform(-1, 1)
        return max(0.5, wait + jitter)

    def __repr__(self) -> str:
        profile = self._profile or "random"
        return f"StealthSession(profile={profile!r}, delay={self._min_delay}-{self._max_delay}s)"
