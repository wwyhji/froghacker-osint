"""Tests for osint.graph_engine — 实体抽取 + 多跳 BFS。"""
from __future__ import annotations

from osint.artifacts import OsintArtifact
from osint.graph_engine import detect_type, extract_entities, expand


def _art(**kw):
    return OsintArtifact(**kw)


def _edge_set(edges):
    return {(e["source"], e["target"], e["rel"]) for e in edges}


def test_email_edge():
    arts = [_art(source="s", entity_type="email", value="admin@example.com",
                 evidence="emailrep.io/admin@example.com")]
    nodes, edges = extract_entities(arts)
    ids = {n["id"] for n in nodes}
    assert "email:admin@example.com" in ids
    assert "domain:example.com" in ids  # 隐含域名节点被物化
    assert ("email:admin@example.com", "domain:example.com", "email_of") in _edge_set(edges)


def test_subdomain_edge():
    arts = [_art(source="s", entity_type="subdomain", value="www.example.com",
                 raw={"parent": "example.com"})]
    _, edges = extract_entities(arts)
    assert ("subdomain:www.example.com", "domain:example.com", "has_subdomain") in _edge_set(edges)


def test_cert_san_edge():
    arts = [_art(source="s", entity_type="cert", value="example.com",
                 raw={"subdomains": ["a.example.com"]})]
    nodes, edges = extract_entities(arts)
    assert "subdomain:a.example.com" in {n["id"] for n in nodes}
    assert ("cert:example.com", "subdomain:a.example.com", "cert_san") in _edge_set(edges)


def test_dns_resolves_edge():
    arts = [_art(source="s", entity_type="dns_record", value="1.2.3.4",
                 raw={"domain": "example.com", "record_type": "A"})]
    nodes, edges = extract_entities(arts)
    assert "ip:1.2.3.4" in {n["id"] for n in nodes}
    assert ("domain:example.com", "ip:1.2.3.4", "resolves_to") in _edge_set(edges)


def test_whois_registered_edge():
    arts = [_art(source="s", entity_type="person", value="John Doe",
                 raw={"domain": "example.com"})]
    _, edges = extract_entities(arts)
    assert ("domain:example.com", "person:John Doe", "registered_to") in _edge_set(edges)


def test_detect_type_phone():
    assert detect_type("13800138000") == "phone"
    assert detect_type("+44 20 7946 0958") == "phone"


def test_phone_carrier_edge():
    arts = [_art(source="phone", entity_type="phone", value="13800138000",
                 raw={"carrier": "中国移动"})]
    nodes, edges = extract_entities(arts)
    assert "org:中国移动" in {n["id"] for n in nodes}
    assert ("phone:13800138000", "org:中国移动", "registered_to") in _edge_set(edges)


def test_detect_type_crypto():
    assert detect_type("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa") == "crypto_address"
    assert detect_type("0x" + "a" * 40) == "crypto_address"


def test_crypto_tag_edge():
    addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    arts = [_art(source="chainabuse", entity_type="crypto_address", value=addr,
                 raw={"category": "ransomware"})]
    nodes, edges = extract_entities(arts)
    assert "breach:ransomware" in {n["id"] for n in nodes}
    assert (f"crypto_address:{addr}", "breach:ransomware", "registered_to") in _edge_set(edges)


def test_expand_seed_node_and_dedup(monkeypatch):
    def fake_collect(target, entity_type="", limit=20):
        if target == "example.com":
            return [
                _art(source="dns", entity_type="dns_record", value="1.2.3.4",
                     raw={"domain": "example.com", "record_type": "A"}),
                _art(source="crtsh", entity_type="subdomain", value="www.example.com",
                     raw={"parent": "example.com"}),
            ]
        if target == "www.example.com":
            return [
                _art(source="dns", entity_type="dns_record", value="5.6.7.8",
                     raw={"domain": "www.example.com", "record_type": "A"}),
            ]
        return []

    monkeypatch.setattr("osint.sources.collect", fake_collect)
    g = expand("example.com", entity_type="domain", max_depth=2)
    d = g.to_dict()
    ids = [n["id"] for n in d["nodes"]]
    assert "domain:example.com" in ids      # 种子节点
    assert "subdomain:www.example.com" in ids
    assert "ip:1.2.3.4" in ids
    assert "ip:5.6.7.8" in ids              # 第二跳
    assert len(ids) == len(set(ids))        # 去重


def test_expand_confidence_decay(monkeypatch):
    def fake_collect(target, entity_type="", limit=20):
        if target == "example.com":
            return [_art(source="dns", entity_type="dns_record", value="1.2.3.4",
                         raw={"domain": "example.com", "record_type": "A"})]
        if target == "1.2.3.4":
            return [_art(source="hackertarget", entity_type="domain", value="other.com",
                         raw={"reverse_ip": "1.2.3.4"})]
        return []

    monkeypatch.setattr("osint.sources.collect", fake_collect)
    g = expand("example.com", entity_type="domain", max_depth=2, confidence_decay=0.5)
    confs = {e["rel"]: e["confidence"] for e in g.to_dict()["edges"]}
    assert confs.get("resolves_to") == 1.0   # 第一跳
    assert confs.get("hosts_on") == 0.5      # 第二跳 (置信度衰减)


def test_expand_max_depth_terminates(monkeypatch):
    calls = []

    def fake_collect(target, entity_type="", limit=20):
        calls.append(target)
        return [_art(source="s", entity_type="subdomain", value=f"a.{target}",
                     raw={"parent": target})]

    monkeypatch.setattr("osint.sources.collect", fake_collect)
    g = expand("example.com", entity_type="domain", max_depth=1)
    # 只应采集 seed + 1 跳 frontier (a.example.com), 不继续 a.a.example.com
    assert calls.count("example.com") == 1
    assert "a.a.example.com" not in calls
    assert g.stats["depth"] == 1


def test_expand_centrality_pivot(monkeypatch):
    calls = []

    def fake_collect(target, entity_type="", limit=20):
        calls.append(target)
        if target == "example.com":
            return [
                _art(source="crtsh", entity_type="subdomain", value="hub.example.com",
                     raw={"parent": "example.com", "ip": "1.2.3.4"}),
                _art(source="crtsh", entity_type="subdomain", value="leaf1.example.com",
                     raw={"parent": "example.com"}),
                _art(source="crtsh", entity_type="subdomain", value="leaf2.example.com",
                     raw={"parent": "example.com"}),
            ]
        return []

    monkeypatch.setattr("osint.sources.collect", fake_collect)
    expand("example.com", entity_type="domain", max_depth=2, pivot_limit=1)
    # hub 带 ip 边 → 度中心性最高, 只扩展 hub
    assert "hub.example.com" in calls
    assert "leaf1.example.com" not in calls
    assert "leaf2.example.com" not in calls


# ── P3: mac/asn 检测与图边 ──────────────────────────────────────

def test_detect_type_mac():
    assert detect_type("00:1A:2B:3C:4D:5E") == "mac"
    assert detect_type("00-1A-2B-3C-4D-5E") == "mac"


def test_detect_type_asn():
    assert detect_type("AS13335") == "asn"
    assert detect_type("as13335") == "asn"
    assert detect_type("13335") != "asn"  # 纯数字不误判为 asn


def test_asn_org_edge():
    arts = [_art(source="bgpview", entity_type="asn", value="AS15169", raw={"org": "GOOGLE"})]
    nodes, edges = extract_entities(arts)
    assert "org:GOOGLE" in {n["id"] for n in nodes}
    assert ("asn:as15169", "org:GOOGLE", "registered_to") in _edge_set(edges)


def test_mac_org_edge():
    arts = [_art(source="macvendor", entity_type="mac", value="00:1A:2B:3C:4D:5E",
                 raw={"vendor": "Apple, Inc."})]
    nodes, edges = extract_entities(arts)
    assert "org:Apple, Inc." in {n["id"] for n in nodes}
    assert ("mac:001a2b3c4d5e", "org:Apple, Inc.", "registered_to") in _edge_set(edges)


def test_ip_asn_edge():
    arts = [_art(source="bgpview", entity_type="ip", value="8.8.8.8", raw={"asn": "AS15169"})]
    nodes, edges = extract_entities(arts)
    assert "asn:as15169" in {n["id"] for n in nodes}
    assert ("ip:8.8.8.8", "asn:as15169", "belongs_to") in _edge_set(edges)
