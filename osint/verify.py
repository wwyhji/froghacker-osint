"""verify.py — artifact-first 反幻觉验证 (MVP 纯规则)。

每条 claim 必须回溯到: fetched_at 非空 + evidence 非空 + normalize(value)
出现在 evidence/raw 中 → verified; 否则 unsupported。LLM judge 留 P1。
"""

from __future__ import annotations

import json

from .artifacts import normalize


def verify_claims(artifacts) -> list[dict]:
    """对 artifacts 逐条做可回溯性验证, 返回 [{source,entity_type,value,status,reason}]。"""
    out: list[dict] = []
    for a in artifacts:
        v = normalize(a.entity_type, a.value)
        raw_json = json.dumps(a.raw or {}, ensure_ascii=False)
        has_evidence = bool(a.fetched_at) and bool(a.evidence)
        traceable = bool(v) and (v in (a.evidence or "") or v in raw_json)
        status = "verified" if (has_evidence and traceable) else "unsupported"
        if status == "verified":
            reason = "ok"
        elif not has_evidence:
            reason = "缺少 fetched_at/evidence"
        else:
            reason = "value 无法回溯到 evidence/raw"
        out.append({
            "source": a.source,
            "entity_type": a.entity_type,
            "value": a.value,
            "status": status,
            "reason": reason,
        })
    return out


def verify_claims_llm(
    artifacts,
    model: str = "qwen2.5",
    endpoint: str = "http://localhost:11434/api/generate",
) -> list[dict]:
    """LLM judge 反幻觉复核 (Ollama 本地)。离线不可用返回 []。

    返回 [{index, entity_type, value, status, reason}], status 与 verify_claims 一致;
    LLM 判定该条无法回溯到证据时 status='unsupported'。
    """
    if not artifacts:
        return []
    lines = []
    for i, a in enumerate(artifacts):
        lines.append(
            f"{i}. [{a.entity_type}] {a.value} — 来源:{a.source} 证据:{a.evidence[:120]}"
        )
    prompt = (
        "你是OSINT情报验证官。逐条判断下面情报是否能回溯到其证据(证据文本包含该值或来源可信)。"
        '仅输出 JSON 数组, 每项形如 {"i": 序号, "ok": true/false}, 不要输出其它内容:\n'
        + "\n".join(lines)
    )
    try:
        import urllib.request

        req = urllib.request.Request(
            endpoint,
            data=json.dumps({
                "model": model, "prompt": prompt, "stream": False, "format": "json",
            }).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            out = json.loads(resp.read().decode()).get("response", "")
        verdicts = json.loads(out) if isinstance(out, str) else out
        if not isinstance(verdicts, list):
            return []
    except Exception:
        return []

    by_idx = {v.get("i", -1): v.get("ok", True) for v in verdicts if isinstance(v, dict)}
    results: list[dict] = []
    for i, a in enumerate(artifacts):
        ok = by_idx.get(i, True)
        results.append({
            "index": i,
            "entity_type": a.entity_type,
            "value": a.value,
            "status": "verified" if ok else "unsupported",
            "reason": "llm judge" if ok else "llm: 无法回溯到证据",
        })
    return results


__all__ = ["verify_claims", "verify_claims_llm"]
