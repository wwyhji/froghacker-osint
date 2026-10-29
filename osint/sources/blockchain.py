"""blockchain — Bitcoin 地址余额/交易查询 (免费无 key, blockchain.info)。

GET https://blockchain.info/rawaddr/{address} -> final_balance/n_tx/total_received/...
"""
from __future__ import annotations

from . import SourceAdapter, register
from ..artifacts import OsintArtifact
from ..http_client import safe_get_json


@register
class BlockchainAdapter(SourceAdapter):
    name = "blockchain"
    entity_types = ("crypto_address",)
    paid = False
    polite_delay = 1.0
    rate_limit = (1, 1)  # unverified, conservative 1/s

    def collect(self, target, entity_type="", limit=20):
        data = safe_get_json(f"https://blockchain.info/rawaddr/{target}")
        if not isinstance(data, dict):
            return []
        bal_sat = data.get("final_balance", 0)
        return [OsintArtifact(
            source=self.name, entity_type="crypto_address", value=target, label=target,
            raw={
                "chain": "bitcoin",
                "n_tx": data.get("n_tx", 0),
                "total_received_sat": data.get("total_received", 0),
                "total_sent_sat": data.get("total_sent", 0),
                "final_balance_sat": bal_sat,
                "final_balance_btc": bal_sat / 1e8,
            },
            evidence=f"blockchain.info/rawaddr/{target}",
            confidence="high",
        )]
