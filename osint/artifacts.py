"""artifacts.py — OSINT 统一证据模型 (参照 forensics/iot/iot_pipeline.py::IoTArtifact)。

entity_type 取值:
  person / username / email / org / domain / subdomain / ip / asn / mac /
  url / cert / breach / dns_record / social_profile / phone

图 schema 对齐 forensics/phone_graph.parse() 输出:
  {"nodes":[{id,name,type,label,path}], "edges":[{source,target,rel}], "stats":{}}
节点 id = f"{entity_type}:{normalize(value)}" 确定性去重。
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

# 合法实体类型全集
ENTITY_TYPES: tuple[str, ...] = (
    "person", "username", "email", "org", "domain", "subdomain", "ip", "asn", "mac",
    "url", "cert", "breach", "dns_record", "social_profile", "phone",
    "crypto_address",
)

# 大小写不敏感类型 (normalize 时转小写)
_CASE_INSENSITIVE: frozenset[str] = frozenset(
    {"domain", "subdomain", "email", "ip", "username", "url", "asn", "mac"}
)

# 可枢轴实体 (BFS 可继续扩展)
PIVOT_TYPES: frozenset[str] = frozenset(
    {"domain", "subdomain", "ip", "email", "username", "org", "person", "phone",
     "crypto_address", "asn", "mac"}
)


def _strip_ip_port(v: str) -> str:
    """IPv4:port → IPv4。"""
    m = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}$", v)
    return m.group(1) if m else v


def normalize(entity_type: str, value: object) -> str:
    """按实体类型归一化 value (去尾点/小写/去空格/去端口)。"""
    if value is None:
        return ""
    v = str(value).strip()
    if entity_type in _CASE_INSENSITIVE:
        v = v.lower()
    if entity_type in ("domain", "subdomain"):
        v = v.rstrip(".")
    elif entity_type == "email":
        v = v.replace(" ", "")
    elif entity_type == "ip":
        v = _strip_ip_port(v)
    elif entity_type == "url":
        v = v.rstrip("/")
    elif entity_type == "phone":
        v = re.sub(r"[\s\-().]", "", v)
        v = re.sub(r"^\+86", "", v)  # 中国 +86 国家码 → 本地号 (确定性同义)
    elif entity_type == "crypto_address":
        v = re.sub(r"\s+", "", v)  # 保留大小写 (BTC 大小写敏感 / ETH EIP-55 checksum)
    elif entity_type == "mac":
        v = re.sub(r"[:-]", "", v).lower()  # 去冒号/横线, 统一小写
    return v


def now_iso() -> str:
    """当前 UTC 时间 ISO8601 字符串 (证据时间戳)。"""
    return datetime.now(timezone.utc).isoformat()


def synonym_key(entity_type: str, value: object) -> str:
    """同义撞击键: 让指向同一底层实体的表达撞到同一规范键 (跨类型去重)。

    email/url 归约到域名 (100% 确定性); 其余 = f"{entity_type}:{normalize(value)}"。
    用于 cache 与图节点的跨类型同义去重。
    """
    v = normalize(entity_type, value)
    if entity_type == "email":
        dom = v.split("@")[-1] if "@" in v else ""
        return f"domain:{dom}" if dom else f"email:{v}"
    if entity_type == "url":
        from urllib.parse import urlparse
        host = urlparse(v).hostname or ""
        return f"domain:{host}" if host else f"url:{v}"
    return f"{entity_type}:{v}"


@dataclass
class OsintArtifact:
    """单条 OSINT 证据。evidence 为反幻觉回溯依据 (原始文本/URL)。"""

    source: str = ""          # adapter 注册名
    entity_type: str = ""     # person/username/email/org/domain/...
    value: str = ""           # 归一化值 (normalize())
    label: str = ""
    raw: dict = field(default_factory=dict)   # 源返回原始 payload (证据)
    evidence: str = ""        # 证明 value 的原始文本/URL (反幻觉关键)
    confidence: str = "medium"  # high/medium/low
    fetched_at: str = ""      # ISO8601

    def __post_init__(self) -> None:
        self.value = normalize(self.entity_type, self.value)

    def node_id(self) -> str:
        return f"{self.entity_type}:{self.value}"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class OsintGraph:
    """关联图谱 (确定性节点/边去重)。"""

    nodes: dict = field(default_factory=dict)  # id -> node
    edges: dict = field(default_factory=dict)  # (src,tgt,rel) -> edge
    stats: dict = field(default_factory=dict)

    def add_node(
        self,
        entity_type: str,
        value: object,
        label: str = "",
        source: str = "",
        confidence: str = "medium",
        evidence: str = "",
        **extra,
    ) -> str:
        etype = entity_type or "unknown"
        val = normalize(etype, value)
        if not val:
            return ""
        nid = f"{etype}:{val}"
        if nid not in self.nodes:
            self.nodes[nid] = {
                "id": nid,
                "name": val,
                "type": etype,
                "label": label or val,
                "path": evidence or source,
                "confidence": confidence,
                **extra,
            }
        return nid

    def add_edge(self, source_id: str, target_id: str, rel: str, confidence: float = 1.0) -> bool:
        if not source_id or not target_id or source_id == target_id:
            return False
        key = (source_id, target_id, rel)
        if key in self.edges:
            self.edges[key]["confidence"] = max(self.edges[key]["confidence"], confidence)
            return False
        self.edges[key] = {
            "source": source_id, "target": target_id, "rel": rel, "confidence": confidence,
        }
        return True

    def to_dict(self) -> dict:
        return {
            "nodes": list(self.nodes.values()),
            "edges": list(self.edges.values()),
            "stats": dict(self.stats),
        }


__all__ = [
    "ENTITY_TYPES", "PIVOT_TYPES", "normalize", "now_iso", "synonym_key",
    "OsintArtifact", "OsintGraph",
]
