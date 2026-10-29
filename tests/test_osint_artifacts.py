"""Tests for osint.artifacts — normalize + OsintArtifact + OsintGraph。"""
from __future__ import annotations

from osint.artifacts import OsintArtifact, OsintGraph, normalize, synonym_key


def test_normalize_domain():
    assert normalize("domain", "Example.COM.") == "example.com"


def test_normalize_email():
    assert normalize("email", "  Admin@Example.COM ") == "admin@example.com"


def test_normalize_ip_strips_port():
    assert normalize("ip", "1.2.3.4:443") == "1.2.3.4"
    assert normalize("ip", "1.2.3.4") == "1.2.3.4"


def test_normalize_url_strips_slash():
    assert normalize("url", "https://example.com/") == "https://example.com"


def test_normalize_subdomain():
    assert normalize("subdomain", "WWW.Example.COM.") == "www.example.com"


def test_normalize_preserves_person_case():
    assert normalize("person", "  John Doe ") == "John Doe"


def test_artifact_node_id_deterministic():
    a = OsintArtifact(source="s", entity_type="domain", value="Example.COM.")
    assert a.value == "example.com"
    assert a.node_id() == "domain:example.com"


def test_graph_add_node_dedup():
    g = OsintGraph()
    nid1 = g.add_node("domain", "Example.COM.", label="example.com")
    nid2 = g.add_node("domain", "example.com", label="dup")
    assert nid1 == nid2 == "domain:example.com"
    assert len(g.nodes) == 1


def test_graph_add_edge_self_loop_skipped():
    g = OsintGraph()
    assert g.add_edge("domain:x", "domain:x", "rel") is False
    assert g.edges == {}


def test_graph_add_edge_confidence_max():
    g = OsintGraph()
    assert g.add_edge("a", "b", "r", confidence=0.8) is True
    assert g.add_edge("a", "b", "r", confidence=1.0) is False  # dup, 保留 max
    assert g.edges[("a", "b", "r")]["confidence"] == 1.0


def test_graph_to_dict_schema():
    g = OsintGraph()
    g.add_node("domain", "example.com")
    g.add_edge("domain:example.com", "ip:1.2.3.4", "resolves_to")
    d = g.to_dict()
    assert set(d.keys()) == {"nodes", "edges", "stats"}
    assert d["nodes"][0]["id"] == "domain:example.com"
    assert d["edges"][0]["rel"] == "resolves_to"


# ── 同义撞击 (synonym_key) ──────────────────────────────────────

def test_synonym_key_email_to_domain():
    assert synonym_key("email", "Admin@Example.COM") == "domain:example.com"


def test_synonym_key_url_to_host():
    assert synonym_key("url", "https://Example.COM:443/path") == "domain:example.com"


def test_synonym_key_passthrough():
    assert synonym_key("ip", "1.2.3.4") == "ip:1.2.3.4"
    assert synonym_key("domain", "Example.COM.") == "domain:example.com"
    assert synonym_key("asn", "AS15169") == "asn:as15169"


def test_normalize_phone_strips_country_code():
    assert normalize("phone", "+86 138-0013-8000") == "13800138000"
    assert normalize("phone", "+44 20 7946 0958") == "+442079460958"  # 非 +86 不变
