"""Challenge detector — identifies anti-bot challenges in HTTP responses.

Detects common WAF and CAPTCHA challenges from response body content.
Detection only: reports what it sees, never bypasses the challenge.

Usage:
    detector = ChallengeDetector()
    result = detector.detect(html_content)   # → "cloudflare" | None
    if ChallengeDetector.is_blocked(response):
        # handle blocked response yourself (e.g. back off), do not bypass
"""

from __future__ import annotations

import re
from typing import Optional


class ChallengeDetected(Exception):
    """Raised when a response contains an anti-bot challenge."""

    def __init__(self, url: str, challenge_type: str, status_code: int = 200,
                 detail: str = "") -> None:
        self.url = url
        self.challenge_type = challenge_type
        self.status_code = status_code
        self.detail = detail
        super().__init__(
            f"Challenge detected at {url}: {challenge_type}"
            + (f" — {detail}" if detail else "")
        )


class ChallengeDetector:
    """Detects anti-bot challenges from HTTP response content and status codes."""

    # Patterns are checked case-insensitively against response body
    PATTERNS: dict[str, list[str]] = {
        "cloudflare": [
            r"challenge-platform",
            r"cf-browser-verification",
            r"cf-chl-",
            r"cferror",
            r"cf-ray",
            r"/cdn-cgi/l/challenges",
            r"Checking your browser before accessing",
            r"Just a moment\.\.\.",
            r"Please stand by, while we are checking your browser",
            r"Attention Required! \| Cloudflare",
        ],
        "akamai": [
            r"akamai-bot-manager",
            r"reference #\d+\.\w+",
            r"Access Denied.*Akamai",
        ],
        "datadome": [
            r"datadome",
            r"geo\.captcha-delivery\.com",
        ],
        "captcha": [
            r"g-recaptcha",
            r"h-captcha",
            r"hcaptcha\.com",
            r"funcaptcha",
            r"arkoselabs\.com",
            r"google\.com/recaptcha",
            r"captcha-delivery",
        ],
        "waf_block": [
            r"access denied",
            r"request blocked",
            r"request rejected",
            r"your request has been blocked",
            r"your request has been denied",
            r"您(的)?(请求|访问)已(被)?(拦截|拒绝|阻止)",
            r"检测到异常(访问|请求)",
            r"请不要(使用|尝试).*(爬虫|自动化|脚本)",
            r"blocked by",
            r"waf.*blocked",
            r"security block",
        ],
        "rate_limit": [
            r"too many requests",
            r"rate limit exceeded",
            r"请求过于频繁",
            r"访问频率过高",
            r"请稍后再试",
            r"操作太频繁",
        ],
    }

    # Status codes that typically indicate blocking
    BLOCK_STATUSES: set[int] = {403, 429, 503}

    @classmethod
    def detect(cls, html_or_response) -> Optional[str]:
        """Detect the type of anti-bot challenge in a response.

        Args:
            html_or_response: HTML string, requests.Response, or None.

        Returns:
            Challenge type string (e.g. "cloudflare", "captcha"), or None.
        """
        if html_or_response is None:
            return None

        html = cls._extract_html(html_or_response)

        if not html:
            return None

        html_lower = html.lower()

        for challenge_type, patterns in cls.PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, html_lower, re.IGNORECASE):
                    return challenge_type

        return None

    @classmethod
    def is_blocked(cls, response) -> bool:
        """Check if a response indicates the request was blocked.

        Strategy:
        - 403: always blocked (explicit denial)
        - 429: always blocked (rate limiting)
        - 503: only blocked if body contains challenge patterns
        - Other statuses: only blocked if body contains challenge patterns
        """
        if response is None:
            return False

        status = getattr(response, "status_code", 0)

        # 403 and 429 are definitive blocks
        if status in (403, 429):
            return True

        # 503 only counts if body confirms it's a WAF block
        if status == 503:
            body_challenge = cls.detect(response)
            return body_challenge is not None

        # For any other status, check body content
        return cls.detect(response) is not None

    @classmethod
    def detect_with_detail(cls, html_or_response) -> tuple[Optional[str], str]:
        """Like detect() but returns (type, detail) for richer error reporting."""
        challenge_type = cls.detect(html_or_response)
        if challenge_type is None:
            return None, ""

        html = cls._extract_html(html_or_response)
        detail = cls._extract_detail(html, challenge_type)
        return challenge_type, detail

    @staticmethod
    def _extract_html(response_or_html) -> str:
        """Normalize input to a string."""
        if isinstance(response_or_html, str):
            return response_or_html
        if hasattr(response_or_html, "text"):
            return getattr(response_or_html, "text", "")
        if hasattr(response_or_html, "content"):
            content = getattr(response_or_html, "content", b"")
            if isinstance(content, bytes):
                try:
                    return content.decode("utf-8", errors="replace")
                except Exception:
                    return ""
        return str(response_or_html)

    @classmethod
    def _extract_detail(cls, html: str, challenge_type: str) -> str:
        """Extract a human-readable snippet from the challenge page."""
        # Strip HTML tags for cleaner output
        text = re.sub(r"<[^>]+>", " ", html)
        text = re.sub(r"\s+", " ", text).strip()

        # Try to find the most relevant sentence
        patterns = cls.PATTERNS.get(challenge_type, [])
        for pattern in patterns:
            m = re.search(pattern, text, re.IGNORECASE)
            if m:
                start = max(0, m.start() - 40)
                end = min(len(text), m.end() + 80)
                snippet = text[start:end].strip()
                return snippet

        # Fallback: return page title
        title_m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE)
        if title_m:
            return title_m.group(1).strip()

        return text[:200]
