"""公司注册数据查询 — opencorporates API.

复现 opencorporates / companycheck 的核心业务逻辑：查官方公司注册库。
免费 API 需 token (环境变量 OPCORPORATES_TOKEN)；无 token 时降级为生成
opencorporates 搜索页 URL，用户浏览器打开查询。

用法:
    from osint.company_lookup import search_company
    results = search_company("acme", jurisdiction="us")
"""

from __future__ import annotations

import os
import urllib.parse
from dataclasses import dataclass, field
from typing import List, Optional

import requests

API_BASE = "https://api.opencorporates.com/v0.4"
SITE_SEARCH = "https://opencorporates.com/companies"


@dataclass
class CompanyResult:
    name: str
    company_number: str = ""
    jurisdiction: str = ""
    status: str = ""
    incorporation_date: str = ""
    registered_address: str = ""
    url: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "company_number": self.company_number,
            "jurisdiction": self.jurisdiction,
            "status": self.status,
            "incorporation_date": self.incorporation_date,
            "registered_address": self.registered_address,
            "url": self.url,
        }


def _token() -> str:
    return os.environ.get("OPCORPORATES_TOKEN", "")


def search_url(query: str, jurisdiction: str = "") -> str:
    """Fallback: generate the OpenCorporates search page URL (no API call)."""
    q = f"{query} ({jurisdiction})" if jurisdiction else query
    return f"{SITE_SEARCH}?q={urllib.parse.quote(q)}"


def search_company(
    query: str,
    jurisdiction: str = "",
    per_page: int = 10,
) -> List[CompanyResult]:
    """Search OpenCorporates for companies by name.

    Requires OPCORPORATES_TOKEN for live results; otherwise returns [] and the
    caller should fall back to `search_url`.
    """
    token = _token()
    if not token:
        return []

    params: dict = {"q": query, "per_page": per_page}
    if jurisdiction:
        params["jurisdiction_code"] = jurisdiction
    headers = {"User-Agent": "froghacker-osint/5.0", "Authorization": f"Token {token}"}

    try:
        resp = requests.get(f"{API_BASE}/companies/search", params=params,
                            headers=headers, timeout=15)
        if resp.status_code != 200:
            return []
        data = resp.json()
    except Exception:
        return []

    results: List[CompanyResult] = []
    for item in data.get("results", {}).get("companies", []):
        c = item.get("company", {})
        addr = c.get("registered_address_in_full", "") or ""
        results.append(CompanyResult(
            name=c.get("name", ""),
            company_number=c.get("company_number", ""),
            jurisdiction=c.get("jurisdiction_code", ""),
            status=c.get("current_status", "") or c.get("company_status", ""),
            incorporation_date=c.get("incorporation_date", ""),
            registered_address=addr,
            url=c.get("opencorporates_url", ""),
        ))
    return results


def company_profile(company_number: str, jurisdiction: str = "") -> Optional[CompanyResult]:
    """Fetch a single company profile by registration number."""
    token = _token()
    if not token:
        return None
    jc = f"{jurisdiction}/" if jurisdiction else ""
    url = f"{API_BASE}/companies/{jc}{urllib.parse.quote(company_number)}"
    headers = {"User-Agent": "froghacker-osint/5.0", "Authorization": f"Token {token}"}
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code != 200:
            return None
        c = resp.json().get("results", {}).get("company", {})
    except Exception:
        return None
    if not c:
        return None
    return CompanyResult(
        name=c.get("name", ""),
        company_number=c.get("company_number", ""),
        jurisdiction=c.get("jurisdiction_code", ""),
        status=c.get("current_status", "") or c.get("company_status", ""),
        incorporation_date=c.get("incorporation_date", ""),
        registered_address=c.get("registered_address_in_full", "") or "",
        url=c.get("opencorporates_url", ""),
    )
