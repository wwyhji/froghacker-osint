"""osint_agent.py — OSINT 搜索 agent (harness 风格六阶段编排)。

六阶段: Route → Collect → Graph → Rank → Verify → Report。
Rank 用 confidence 降序 (开源版剥离语义排序, 避免数学引擎依赖)。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import sources

_CONF_RANK = {"high": 0, "medium": 1, "low": 2}


@dataclass
class OsintAgentResult:
    target: str = ""
    target_type: str = ""
    artifacts: list = field(default_factory=list)
    graph: dict = field(default_factory=dict)
    verified: list = field(default_factory=list)
    report: str = ""
    stats: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "target_type": self.target_type,
            "artifacts": [a.to_dict() for a in self.artifacts],
            "graph": self.graph,
            "verified": self.verified,
            "report": self.report,
            "stats": self.stats,
        }


def run_agent(
    target: str,
    target_type: str = "auto",
    max_depth: int = 2,
    top_k: int = 10,
    verify: bool = True,
    llm_judge: bool = False,
) -> OsintAgentResult:
    """运行六阶段 OSINT 搜索 agent。

    llm_judge: 额外用本地 Ollama 做反幻觉复核 (离线自动跳过)。
    """
    from .graph_engine import expand, detect_type
    from . import verify as verifier

    # 1. Route
    if target_type == "auto":
        target_type = detect_type(target)

    # 2. Collect
    artifacts = sources.collect(target, entity_type=target_type)

    # 3. Graph
    graph = expand(target, entity_type=target_type, max_depth=max_depth) if max_depth > 0 else {}

    # 4. Rank
    ranked = _rank(artifacts, target)[:top_k]

    # 5. Verify (规则 + 可选 LLM judge)
    verified = verifier.verify_claims(ranked) if verify else []
    if verify and llm_judge:
        llm = verifier.verify_claims_llm(ranked)
        for v in llm:
            i = v.get("index", -1)
            if 0 <= i < len(verified) and v["status"] == "unsupported":
                verified[i]["status"] = "unsupported"
                verified[i]["reason"] = v["reason"]

    # 6. Report
    report = _report(target, target_type, ranked, verified, graph)

    g = graph.to_dict() if hasattr(graph, "to_dict") else graph
    return OsintAgentResult(
        target=target,
        target_type=target_type,
        artifacts=ranked,
        graph=g,
        verified=verified,
        report=report,
        stats={
            "collected": len(artifacts),
            "ranked": len(ranked),
            "verified": sum(1 for v in verified if v["status"] == "verified"),
            "unsupported": sum(1 for v in verified if v["status"] == "unsupported"),
            "depth": max_depth,
        },
    )


def _rank(artifacts: list, query: str) -> list:
    """confidence 降序排序 (开源版剥离语义排序)。"""
    return _rank_by_confidence(artifacts)


def _rank_by_confidence(artifacts: list) -> list:
    return sorted(artifacts, key=lambda a: _CONF_RANK.get(a.confidence, 1))


def _report(target: str, target_type: str, artifacts: list, verified: list, graph) -> str:
    lines = ["# OSINT 情报报告", "", f"- 目标: `{target}`", f"- 类型: {target_type}"]
    if hasattr(graph, "to_dict"):
        g = graph.to_dict()
        lines.append(f"- 关联图谱: {len(g.get('nodes', []))} 节点 / {len(g.get('edges', []))} 边")
    lines += ["", "## 采集结果"]
    for a in artifacts:
        lines.append(f"- **{a.entity_type}** `{a.value}` (src={a.source}, conf={a.confidence})")
    lines += ["", "## 验证"]
    for v in verified:
        mark = "✓" if v["status"] == "verified" else "✗"
        lines.append(f"- {mark} [{v['entity_type']}] `{v['value']}` — {v['status']}")
    return "\n".join(lines)


__all__ = ["run_agent", "OsintAgentResult"]
