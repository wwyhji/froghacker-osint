"""Header spoofer — standard browser header profiles for HTTP requests.

Provides BrowserProfile presets (Chrome/Firefox/Edge × Windows/macOS)
and a HeaderSpoofer that rotates user-agents and headers per request.

Usage:
    spoofer = HeaderSpoofer()
    headers = spoofer.get_headers("chrome_win")
    ua = spoofer.get_random_ua()
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field


@dataclass
class BrowserProfile:
    """Browser profile configuration for a specific browser + OS combo."""
    name: str                    # "chrome_126_win"
    user_agents: list = field(default_factory=list)
    sec_ch_ua: str = ""          # "Chromium";v="126", ...
    platform: str = ""           # "Windows" | "macOS" | "Linux"
    accept_language: str = "zh-CN,zh;q=0.9,en;q=0.8"
    accept: str = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
    accept_encoding: str = "gzip, deflate, br"
    sec_fetch_site: str = "none"
    sec_fetch_mode: str = "navigate"
    sec_fetch_dest: str = "document"
    sec_fetch_user: str = "?1"
    upgrade_insecure_requests: str = "1"
    cache_control: str = "max-age=0"


# ── Preset profiles ───────────────────────────────────────────────────────────

PROFILES: dict[str, BrowserProfile] = {
    "chrome_win": BrowserProfile(
        name="chrome_win",
        platform="Windows",
        sec_ch_ua='"Chromium";v="134", "Not:A-Brand";v="24", "Google Chrome";v="134"',
        user_agents=[
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
        ],
    ),
    "chrome_mac": BrowserProfile(
        name="chrome_mac",
        platform="macOS",
        sec_ch_ua='"Chromium";v="134", "Not:A-Brand";v="24", "Google Chrome";v="134"',
        user_agents=[
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
        ],
    ),
    "firefox_win": BrowserProfile(
        name="firefox_win",
        platform="Windows",
        sec_ch_ua="",
        user_agents=[
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:134.0) Gecko/20100101 Firefox/134.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
        ],
    ),
    "firefox_mac": BrowserProfile(
        name="firefox_mac",
        platform="macOS",
        sec_ch_ua="",
        user_agents=[
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:136.0) Gecko/20100101 Firefox/136.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:135.0) Gecko/20100101 Firefox/135.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:134.0) Gecko/20100101 Firefox/134.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:132.0) Gecko/20100101 Firefox/132.0",
        ],
    ),
    "edge_win": BrowserProfile(
        name="edge_win",
        platform="Windows",
        sec_ch_ua='"Chromium";v="134", "Not:A-Brand";v="24", "Microsoft Edge";v="134"',
        user_agents=[
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 Edg/132.0.0.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
        ],
    ),
    "edge_mac": BrowserProfile(
        name="edge_mac",
        platform="macOS",
        sec_ch_ua='"Chromium";v="134", "Not:A-Brand";v="24", "Microsoft Edge";v="134"',
        user_agents=[
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 Edg/132.0.0.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
        ],
    ),
}


class HeaderSpoofer:
    """Manages multiple browser profiles and rotates headers per request.

    Usage:
        spoofer = HeaderSpoofer()
        headers = spoofer.get_headers()          # random profile
        headers = spoofer.get_headers("firefox_win")
        ua = spoofer.get_random_ua()
        headers = spoofer.rotate()                # different profile each call
    """

    def __init__(self, profiles: dict[str, BrowserProfile] | None = None) -> None:
        self.profiles = profiles or PROFILES
        self._last_profile: str | None = None

    def get_random_ua(self, profile_name: str | None = None) -> str:
        """Return a random User-Agent string from the given or random profile."""
        profile = self._pick_profile(profile_name)
        return random.choice(profile.user_agents)

    def get_headers(self, profile_name: str | None = None) -> dict:
        """Build a full set of HTTP request headers for the given profile.

        Returns a dict ready to pass as `headers=` to requests.
        """
        profile = self._pick_profile(profile_name)
        headers = {
            "User-Agent": random.choice(profile.user_agents),
            "Accept": profile.accept,
            "Accept-Language": profile.accept_language,
            "Accept-Encoding": profile.accept_encoding,
            "Cache-Control": profile.cache_control,
            "Upgrade-Insecure-Requests": profile.upgrade_insecure_requests,
            "Sec-Fetch-Site": profile.sec_fetch_site,
            "Sec-Fetch-Mode": profile.sec_fetch_mode,
            "Sec-Fetch-Dest": profile.sec_fetch_dest,
            "Sec-Fetch-User": profile.sec_fetch_user,
        }
        if profile.sec_ch_ua:
            headers["Sec-CH-UA"] = profile.sec_ch_ua
            headers["Sec-CH-UA-Platform"] = f'"{profile.platform}"'
        return headers

    def rotate(self) -> dict:
        """Return headers with a different profile than last call.

        Guarantees profile rotation to simulate multi-browser traffic.
        """
        available = [k for k in self.profiles if k != self._last_profile]
        if not available:
            available = list(self.profiles.keys())
        profile_name = random.choice(available)
        self._last_profile = profile_name
        return self.get_headers(profile_name)

    def _pick_profile(self, profile_name: str | None = None) -> BrowserProfile:
        if profile_name and profile_name in self.profiles:
            return self.profiles[profile_name]
        if profile_name:
            # Unknown profile → fall back to first matching prefix
            for k, v in self.profiles.items():
                if k.startswith(profile_name):
                    return v
        return random.choice(list(self.profiles.values()))

    def list_profiles(self) -> list[str]:
        """Return available profile names."""
        return sorted(self.profiles.keys())
