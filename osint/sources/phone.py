"""phone — 电话国家/地区解析 (免费无 key, 纯本地)。

国际 E.164 (+国家码) 本地解析国家/地区。不含运营商/省份/城市号段库
(开源版剥离, 对应蛙客主仓库的 telecom_fraud 电信反诈能力)。
"""
from __future__ import annotations

import re

from . import SourceAdapter, register
from ..artifacts import OsintArtifact, normalize

# 常见国际区号 → 国家/地区
_COUNTRY = {
    "1": "美国/加拿大", "7": "俄罗斯", "33": "法国", "34": "西班牙",
    "39": "意大利", "44": "英国", "49": "德国", "52": "墨西哥",
    "55": "巴西", "61": "澳大利亚", "64": "新西兰", "65": "新加坡",
    "81": "日本", "82": "韩国", "86": "中国", "91": "印度",
    "852": "中国香港", "853": "中国澳门", "886": "中国台湾",
}


def analyze_phone(number: str) -> dict:
    """解析电话号, 返回 {normalized, valid, kind, country}。

    kind: intl (国际 +区号) | unknown。开源版不含号段库, 不解析运营商/省市。
    """
    compact = normalize("phone", number)
    out: dict = {"normalized": compact, "valid": False, "kind": "unknown", "country": ""}
    if compact.startswith("+"):
        digits = compact[1:]
        cc = ""
        for width in (3, 2, 1):  # 优先匹配已知 3 位区号 (852/886), 再 2 位, 再 1 位
            if len(digits) > width and digits[:width] in _COUNTRY:
                cc = digits[:width]
                break
        if not cc:
            cc = digits[:2] if len(digits) > 2 else digits[:1]
        out.update(valid=True, kind="intl", country=_COUNTRY.get(cc, f"+{cc}"))
    return out


@register
class PhoneAdapter(SourceAdapter):
    name = "phone"
    entity_types = ("phone",)
    paid = False
    polite_delay = 0.0  # 纯本地解析, 无网络

    def collect(self, target, entity_type="", limit=20):
        info = analyze_phone(target)
        if not info["valid"]:
            return []
        return [OsintArtifact(
            source=self.name, entity_type="phone", value=target, label=target,
            raw=info,
            evidence=f"本地区号解析: {info.get('country', '')}",
            confidence="high",
        )]
