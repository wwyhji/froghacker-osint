"""Tests for osint.osint_agent + verify — confidence 排序 + 反幻觉 + 冒烟。"""
from __future__ import annotations

from osint.artifacts import OsintArtifact
from osint.osint_agent import _rank, run_agent
from osint.verify import verify_claims


def test_rank_confidence_order():
    arts = [
        OsintArtifact(source="a", entity_type="domain", value="low.com", confidence="low"),
        OsintArtifact(source="b", entity_type="domain", value="high.com", confidence="high"),
        OsintArtifact(source="c", entity_type="domain", value="med.com", confidence="medium"),
    ]
    ranked = _rank(arts, "anything")
    assert [a.confidence for a in ranked] == ["high", "medium", "low"]


def test_verify_claims_verified_and_unsupported():
    a1 = OsintArtifact(
        source="dns", entity_type="dns_record", value="1.2.3.4",
        raw={"domain": "example.com", "value": "1.2.3.4"},
        evidence="DNS A example.com", fetched_at="2026-01-01T00:00:00+00:00",
    )
    a2 = OsintArtifact(source="s", entity_type="domain", value="example.com")  # 无 evidence
    out = verify_claims([a1, a2])
    assert out[0]["status"] == "verified"
    assert out[1]["status"] == "unsupported"


def test_run_agent_smoke(monkeypatch):
    monkeypatch.setattr(
        "osint.sources.collect",
        lambda target, entity_type="", limit=20: [
            OsintArtifact(source="dns", entity_type="dns_record", value="1.2.3.4",
                          raw={"domain": target, "record_type": "A", "value": "1.2.3.4"},
                          evidence=f"DNS A {target} -> 1.2.3.4", fetched_at="t"),
        ],
    )

    r = run_agent("example.com", max_depth=1, top_k=5)
    assert r.target == "example.com"
    assert r.target_type == "domain"
    assert r.stats["collected"] == 1
    assert r.stats["verified"] == 1
    assert "example.com" in r.report


# ── P1: LLM judge ────────────────────────────────────────────────


def test_verify_claims_llm_offline_returns_empty(monkeypatch):
    import urllib.request
    from osint.verify import verify_claims_llm

    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: (_ for _ in ()).throw(OSError("offline")))
    arts = [OsintArtifact(source="s", entity_type="domain", value="example.com")]
    assert verify_claims_llm(arts) == []


def test_verify_claims_llm_parses_verdict(monkeypatch):
    import json
    import urllib.request
    from osint.verify import verify_claims_llm

    class _Resp:
        def read(self):
            return json.dumps({"response": json.dumps([{"i": 0, "ok": False}])}).encode()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: _Resp())
    arts = [OsintArtifact(source="s", entity_type="domain", value="example.com")]
    out = verify_claims_llm(arts)
    assert out[0]["status"] == "unsupported"
