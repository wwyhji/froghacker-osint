"""人物聚合搜索 — Maigret 集成 (数千站点) + 内置降级。

复现 pipl / spokeo / peekyou 的人物聚合业务逻辑：跨平台用户名存在性检测。
优先调用开源工具 Maigret (``pip install maigret``, 覆盖数千站点)；未安装时
自动降级到内置的 username_search (30+ 平台)。

用法:
    from osint.person_search import person_search
    result = person_search("johndoe")           # 自动选择后端
    result = person_search("johndoe", deep=False)  # 强制内置 30+ 平台
"""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import List, Optional

from .username_search import username_search


def _maigret_cli() -> Optional[str]:
    """Return the maigret executable path, or None if not installed."""
    return shutil.which("maigret")


def _run_maigret(cli: str, username: str, timeout: int) -> dict:
    """Run maigret and parse its JSON output (tolerant to schema drift)."""
    try:
        proc = subprocess.run(
            [cli, username, "--json", "simple", "--timeout", str(timeout)],
            capture_output=True, text=True, timeout=timeout + 60,
        )
    except subprocess.TimeoutExpired:
        return {"backend": "maigret", "username": username, "sites": [],
                "found": 0, "error": "maigret 超时"}
    except OSError as e:
        return {"backend": "maigret", "username": username, "sites": [],
                "found": 0, "error": str(e)}

    raw = proc.stdout.strip()
    data = {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        # maigret may print progress to stdout; fall back to empty on parse failure
        data = {}

    sites: List[dict] = []
    found = 0
    for s in data.get("sites", []):
        entry = {
            "name": s.get("name") or s.get("site", ""),
            "url": s.get("url_user") or s.get("url_main") or s.get("url", ""),
            "exists": bool(s.get("exists", False)),
        }
        if entry["exists"]:
            found += 1
        sites.append(entry)

    return {"backend": "maigret", "username": username,
            "sites": sites, "found": found,
            "checked": len(sites), "error": ""}


def _builtin_fallback(username: str) -> dict:
    """Fall back to the built-in 30+ platform scanner."""
    r = username_search(username)
    sites: List[dict] = []
    for pr in r.found_on:
        sites.append({"name": pr.platform, "url": pr.profile_url, "exists": True})
    for pr in r.not_found_on:
        sites.append({"name": pr.platform, "url": pr.profile_url, "exists": False})
    return {
        "backend": "builtin(30+)",
        "username": username,
        "sites": sites,
        "found": r.total_found,
        "checked": r.total_checked,
        "hint": "安装 maigret (pip install maigret) 可将覆盖扩展到数千站点",
        "error": "",
    }


def person_search(username: str, deep: bool = True, timeout: int = 30) -> dict:
    """Search for a username across platforms (Maigret if available, else built-in).

    Args:
        username:  Username/handle to search.
        deep:      Use Maigret (thousands of sites) when installed.
        timeout:   Per-site HTTP timeout (seconds).

    Returns a dict: {backend, username, sites, found, checked, ...}.
    """
    if deep:
        cli = _maigret_cli()
        if cli:
            return _run_maigret(cli, username, timeout)
    return _builtin_fallback(username)
