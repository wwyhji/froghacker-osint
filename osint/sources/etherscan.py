"""etherscan — Ethereum 地址余额查询 (免费注册 key ETHERSCAN_API_KEY)。

GET https://api.etherscan.io/api?module=account&action=balance&address=<addr>&apikey=<key>
返回 result 为 wei 单位余额。
"""
from __future__ import annotations

from . import SourceAdapter, register
from ..artifacts import OsintArtifact
from ..http_client import get_key, safe_get_json


@register
class EtherscanAdapter(SourceAdapter):
    name = "etherscan"
    entity_types = ("crypto_address",)
    paid = True
    env_key = "ETHERSCAN_API_KEY"
    polite_delay = 1.0

    def collect(self, target, entity_type="", limit=20):
        data = safe_get_json(
            "https://api.etherscan.io/api",
            params={
                "module": "account", "action": "balance",
                "address": target, "tag": "latest",
                "apikey": get_key(self.env_key),
            },
        )
        if not isinstance(data, dict) or data.get("status") != "1":
            return []
        wei = int(data.get("result", 0))
        return [OsintArtifact(
            source=self.name, entity_type="crypto_address", value=target, label=target,
            raw={"chain": "ethereum", "balance_wei": wei, "balance_eth": wei / 1e18},
            evidence=f"etherscan {target}",
            confidence="high",
        )]
