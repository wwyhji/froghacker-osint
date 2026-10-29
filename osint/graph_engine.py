"""graph_engine.py — OSINT 实体抽取 + 多跳 BFS 关联图谱。

关系类型:
  resolves_to   domain → ip          (A/AAAA)
  has_subdomain subdomain → domain   (crt.sh SAN / hostsearch)
  cert_san      cert → subdomain
  registered_to domain → person/org/email (whois)
  email_of      email → domain
  hosts_on      ip → domain/subdomain (PTR/反查)
  dns_record    domain → nameserver/mx (MX/NS)
  cname         domain → cname target
  has_profile   username → social_profile
"""

from __future__ import annotations

import re
import sys

from .artifacts import OsintArtifact, OsintGraph, PIVOT_TYPES, normalize

REL_RESOLVES = "resolves_to"
REL_SUBDOMAIN = "has_subdomain"
REL_CERT_SAN = "cert_san"
REL_REGISTERED = "registered_to"
REL_EMAIL_OF = "email_of"
REL_HOSTS_ON = "hosts_on"
REL_DNS = "dns_record"
REL_CNAME = "cname"
REL_PROFILE = "has_profile"
REL_ASN = "belongs_to"


def detect_type(value: str) -> str:
    """启发式检测种子类型 (email/ip/phone/crypto/asn/mac/domain, 其余 username)。"""
    v = (value or "").strip()
    if re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", v):
        return "email"
    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", v):
        return "ip"
    if _looks_phone(v):
        return "phone"
    if _looks_crypto(v):
        return "crypto_address"
    if re.match(r"^AS\d+$", v, re.IGNORECASE):
        return "asn"
    if re.match(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$", v):
        return "mac"
    if re.match(r"^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$", v):
        return "domain"
    return "username"


def _looks_ip(v: str) -> bool:
    return bool(re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", v))


def _looks_phone(v: str) -> bool:
    """宽松电话识别: 中国 11 位手机号 或 国际 +国家码。"""
    compact = re.sub(r"[\s\-().]", "", v)
    if re.match(r"^1[3-9]\d{9}$", compact):
        return True
    if re.match(r"^\+[1-9]\d{6,14}$", compact):
        return True
    return False


def _looks_crypto(v: str) -> bool:
    """钱包地址识别: BTC legacy / bech32 + ETH (0x + 40 hex)。"""
    if re.match(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$", v):
        return True
    if re.match(r"^bc1[ac-hj-np-z02-9]{11,71}$", v):
        return True
    if re.match(r"^0x[a-fA-F0-9]{40}$", v):
        return True
    return False


def _domain_of_email(email: str) -> str:
    at = email.rfind("@")
    return email[at + 1:] if at > 0 else ""


def _node_from_artifact(a: OsintArtifact) -> dict:
    return {
        "id": a.node_id(),
        "name": a.value,
        "type": a.entity_type,
        "label": a.label or a.value,
        "path": a.evidence or a.source,
        "confidence": a.confidence,
    }


def extract_entities(
    artifacts: list[OsintArtifact],
    seed_type: str = "",
    seed_value: str = "",
) -> tuple[list[dict], list[dict]]:
    """从 artifacts 抽取实体节点 + 关系边 (确定性, 不请求网络)。"""
    nodes: dict = {}
    edges: dict = {}

    def add_node(a: OsintArtifact) -> None:
        nodes.setdefault(a.node_id(), _node_from_artifact(a))

    def add_entity(etype: str, val: object, label: str = "", path: str = "") -> str:
        """物化一个 (可能隐含的) 实体节点, 返回节点 id (空值返回空串)。"""
        v = normalize(etype, val)
        if not v:
            return ""
        nid = f"{etype}:{v}"
        nodes.setdefault(nid, {
            "id": nid, "name": v, "type": etype,
            "label": label or v, "path": path, "confidence": "medium",
        })
        return nid

    def add_edge(src_id: str, tgt_id: str, rel: str, conf: float = 1.0) -> None:
        if src_id and tgt_id and src_id != tgt_id:
            edges.setdefault(
                (src_id, tgt_id, rel),
                {"source": src_id, "target": tgt_id, "rel": rel, "confidence": conf},
            )

    for a in artifacts:
        if not a.value:
            continue
        add_node(a)
        et = a.entity_type
        raw = a.raw or {}

        if et == "email":
            dom = _domain_of_email(a.value)
            if dom:
                add_edge(a.node_id(), add_entity("domain", dom), REL_EMAIL_OF)

        elif et == "subdomain":
            parent = raw.get("parent") or seed_value or ""
            if parent:
                add_edge(a.node_id(), add_entity("domain", parent), REL_SUBDOMAIN)
            ip = raw.get("ip")
            if ip:
                add_edge(a.node_id(), add_entity("ip", ip), REL_RESOLVES)

        elif et == "domain":
            ip = raw.get("ip")
            rev = raw.get("reverse_ip")
            if ip:
                add_edge(a.node_id(), add_entity("ip", ip), REL_RESOLVES)
            elif rev:
                add_edge(add_entity("ip", rev), a.node_id(), REL_HOSTS_ON)

        elif et == "cert":
            for s in raw.get("subdomains", []) or []:
                add_edge(a.node_id(), add_entity("subdomain", s), REL_CERT_SAN)
            cn = raw.get("common_name")
            if cn:
                add_edge(a.node_id(), add_entity("subdomain", cn), REL_CERT_SAN)

        elif et == "dns_record":
            dom_nid = add_entity("domain", raw.get("domain", "") or seed_value)
            rt = (raw.get("record_type") or "").upper()
            val = a.value
            if rt in ("A", "AAAA") and _looks_ip(val):
                add_edge(dom_nid, add_entity("ip", val), REL_RESOLVES)
            elif rt in ("MX", "NS"):
                add_edge(dom_nid, add_entity("domain", val), REL_DNS)
            elif rt == "CNAME":
                add_edge(dom_nid, add_entity("domain", val), REL_CNAME)

        elif et in ("person", "org"):
            dom_nid = add_entity("domain", raw.get("domain", ""))
            if dom_nid:
                add_edge(dom_nid, a.node_id(), REL_REGISTERED)

        elif et == "ip":
            hn = raw.get("hostname")
            dom = raw.get("domain")
            asn = raw.get("asn")
            if hn:
                add_edge(a.node_id(), add_entity("subdomain", hn), REL_HOSTS_ON)
            elif dom:
                add_edge(a.node_id(), add_entity("domain", dom), REL_HOSTS_ON)
            if asn:
                add_edge(a.node_id(), add_entity("asn", asn), REL_ASN)

        elif et == "asn":
            org = raw.get("org") or raw.get("name")
            if org:
                add_edge(a.node_id(), add_entity("org", org), REL_REGISTERED)

        elif et == "mac":
            org = raw.get("org") or raw.get("vendor")
            if org:
                add_edge(a.node_id(), add_entity("org", org), REL_REGISTERED)

        elif et == "social_profile":
            un = raw.get("username") or seed_value
            if un:
                add_edge(add_entity("username", un), a.node_id(), REL_PROFILE)

        elif et == "phone":
            carrier = raw.get("carrier")
            if carrier:
                add_edge(a.node_id(), add_entity("org", carrier), REL_REGISTERED)

        elif et == "crypto_address":
            tag = raw.get("tag") or raw.get("category")
            if tag:
                add_edge(a.node_id(), add_entity("breach", tag), REL_REGISTERED)

    return list(nodes.values()), list(edges.values())


def _degree(graph: OsintGraph) -> dict:
    """节点度中心性 (连接边数)。"""
    deg: dict = {}
    for (s, t, _rel) in graph.edges:
        deg[s] = deg.get(s, 0) + 1
        deg[t] = deg.get(t, 0) + 1
    return deg


def expand(
    seed: str,
    entity_type: str = "",
    max_depth: int = 2,
    max_nodes: int = 150,
    confidence_decay: float = 0.85,
    pivot_limit: int = 0,
) -> OsintGraph:
    """多跳 BFS 展开关联图谱。

    逐跳对 frontier 各节点 collect, (type, normalize(value)) 去重,
    边置信度乘 decay。终止于 max_depth / max_nodes / 无新节点。
    叶节点 (cert/url/breach/dns_record 等) 不扩展。
    pivot_limit>0 时按度中心性只扩展 top-N 高连接度枢轴节点。
    """
    from . import sources

    graph = OsintGraph()
    if not entity_type:
        entity_type = detect_type(seed)

    seed_key = (entity_type, normalize(entity_type, seed))
    # 种子自身也作为节点 (保证关联边有锚点)
    graph.add_node(entity_type, seed, label=seed, source="seed", confidence="high")
    visited: set = set()
    frontier: list = [seed_key]
    conf = 1.0
    depth = 0

    for depth in range(max_depth + 1):
        if not frontier or len(graph.nodes) >= max_nodes:
            break
        print(f"[osint] 跳 {depth}/{max_depth}: 扩展 {len(frontier)} 节点", file=sys.stderr)
        next_frontier: list = []
        for (etype, val) in frontier:
            key = (etype, val)
            if key in visited:
                continue
            visited.add(key)

            arts = sources.collect(val, entity_type=etype, limit=20)
            n_entities, n_edges = extract_entities(arts, seed_type=etype, seed_value=val)

            for n in n_entities:
                graph.add_node(
                    n["type"], n["name"], label=n.get("label", ""),
                    source=n.get("path", ""), confidence=n.get("confidence", "medium"),
                    evidence=n.get("path", ""),
                )
            for e in n_edges:
                graph.add_edge(e["source"], e["target"], e["rel"], confidence=conf)

            for n in n_entities:
                if n["type"] in PIVOT_TYPES:
                    nk = (n["type"], normalize(n["type"], n["name"]))
                    if nk not in visited:
                        next_frontier.append(nk)

            if len(graph.nodes) >= max_nodes:
                break

        if depth >= max_depth:
            break
        frontier = _dedupe(next_frontier)
        if pivot_limit and len(frontier) > pivot_limit:
            deg = _degree(graph)
            frontier.sort(key=lambda k: deg.get(f"{k[0]}:{k[1]}", 0), reverse=True)
            frontier = frontier[:pivot_limit]
        conf *= confidence_decay

    graph.stats = {
        "nodes": len(graph.nodes),
        "edges": len(graph.edges),
        "depth": depth,
        "sources": len(sources.list_sources()),
    }
    return graph


def _dedupe(items: list) -> list:
    seen: set = set()
    out: list = []
    for it in items:
        if it not in seen:
            seen.add(it)
            out.append(it)
    return out


__all__ = ["extract_entities", "expand", "detect_type"]
