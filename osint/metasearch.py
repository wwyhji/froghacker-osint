"""元搜索聚合 — 并发查询多个搜索引擎并聚合去重。

复现 searx / dogpile / carrot2 的核心业务逻辑：把同一个查询并发发往
多个引擎，解析各自结果，按 URL 去重后合并返回。

支持的引擎 (自动探测可用性):
  - bing          (HTML 解析, 国内可达)
  - searx         (自建实例 JSON API, 通过 SEARX_URL 环境变量配置)

用法:
    from osint.metasearch import metasearch
    results = metasearch("froghacker osint")
"""

from __future__ import annotations

import os
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Optional

import requests

_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
_DEFAULT_ENGINES = ["bing"]


@dataclass
class SearchResult:
    title: str
    url: str
    engine: str
    snippet: str = ""

    def to_dict(self) -> dict:
        return {"title": self.title, "url": self.url,
                "engine": self.engine, "snippet": self.snippet}


def _strip_tags(html: str) -> str:
    return re.sub(r"<[^>]+>", "", html).strip()


def _search_bing(query: str, max_results: int, timeout: int) -> List[SearchResult]:
    url = "https://www.bing.com/search"
    params = {"q": query, "count": max_results}
    try:
        resp = requests.get(url, params=params, headers={"User-Agent": _UA},
                            timeout=timeout)
        if resp.status_code != 200:
            return []
        html = resp.text
    except Exception:
        return []

    results: List[SearchResult] = []
    # Bing result blocks: <li class="b_algo">...<h2><a href="...">title</a></h2>...<p>snippet</p>
    # Each block has two <a> tags: a favicon link (.1) and the real title link (.2 in h2).
    for block in re.findall(r'<li class="b_algo".*?</li>', html, re.S):
        m = re.search(r'<h2[^>]*>\s*<a[^>]+href="([^"]+)"[^>]*>(.*?)</a>', block, re.S)
        if not m:
            continue
        link, title = m.group(1), _strip_tags(m.group(2))
        if not link.startswith("http") or not title:
            continue
        snip = re.search(r'<p[^>]*>(.*?)</p>', block, re.S)
        snippet = _strip_tags(snip.group(1)) if snip else ""
        results.append(SearchResult(title=title, url=link, engine="bing", snippet=snippet))
        if len(results) >= max_results:
            break
    return results


def _search_searx(query: str, max_results: int, timeout: int) -> List[SearchResult]:
    base = os.environ.get("SEARX_URL", "").rstrip("/")
    if not base:
        return []
    try:
        resp = requests.get(f"{base}/search",
                            params={"q": query, "format": "json"},
                            headers={"User-Agent": _UA}, timeout=timeout)
        if resp.status_code != 200:
            return []
        data = resp.json()
    except Exception:
        return []

    results: List[SearchResult] = []
    for item in data.get("results", [])[:max_results]:
        results.append(SearchResult(
            title=item.get("title", ""),
            url=item.get("url", ""),
            engine="searx",
            snippet=item.get("content", ""),
        ))
    return results


_ENGINE_FUNCS = {
    "bing": _search_bing,
    "searx": _search_searx,
}


def metasearch(
    query: str,
    engines: Optional[List[str]] = None,
    max_per_engine: int = 10,
    timeout: int = 12,
) -> List[SearchResult]:
    """Query multiple engines concurrently, dedupe by URL, merge results.

    Args:
        query:          Search query.
        engines:        Engine names ("bing", "searx"). Default: bing (+ searx
                        if SEARX_URL is set).
        max_per_engine: Max results to keep from each engine.
        timeout:        Per-engine request timeout in seconds.

    Returns:
        Merged, de-duplicated list of SearchResult.
    """
    names = engines or _DEFAULT_ENGINES
    if not engines and os.environ.get("SEARX_URL"):
        names = _DEFAULT_ENGINES + ["searx"]

    merged: List[SearchResult] = []
    seen: set = set()

    def _norm(u: str) -> str:
        return re.sub(r"^https?://(www\.)?", "", u).rstrip("/")

    with ThreadPoolExecutor(max_workers=len(names)) as pool:
        futs = {pool.submit(_ENGINE_FUNCS[n], query, max_per_engine, timeout): n
                for n in names if n in _ENGINE_FUNCS}
        for fut in as_completed(futs):
            for r in fut.result():
                key = _norm(r.url)
                if key in seen:
                    continue
                seen.add(key)
                merged.append(r)

    return merged
