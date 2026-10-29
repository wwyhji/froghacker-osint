"""加密货币地址追踪 — 聚合查询 (余额/交易/欺诈报告)。

聚合 sources 里所有 crypto_address 适配器 (blockchain/etherscan/chainabuse)。

用法:
    from osint.crypto_search import crypto_search
    result = crypto_search("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
"""
from __future__ import annotations

from . import sources


def crypto_search(address: str, limit: int = 20) -> dict:
    """Query a crypto wallet address across free sources.

    Returns dict: {address, balances[], reports[], artifacts[]}.
    """
    arts = sources.collect(address, entity_type="crypto_address", limit=limit)
    result: dict = {
        "address": address,
        "balances": [],
        "reports": [],
        "artifacts": [a.to_dict() for a in arts],
    }
    for a in arts:
        if a.entity_type == "crypto_address" and a.raw.get("chain"):
            result["balances"].append({
                "chain": a.raw["chain"], "source": a.source, "raw": a.raw,
            })
        elif a.entity_type == "breach":
            result["reports"].append(a.value)
    return result
