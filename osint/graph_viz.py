"""graph_viz.py — OSINT 关联网可视化 (自包含 HTML, 零 CDN, 零外部依赖)。

开源版剥离 forensics/phone_graph 依赖, 用纯 HTML 内联渲染节点/边。
"""
from __future__ import annotations

from html import escape
from pathlib import Path

ENTITY_COLORS: dict[str, str] = {
    "person": "#4C78A8", "username": "#54A24B", "email": "#F58518",
    "org": "#B279A2", "domain": "#E45756", "subdomain": "#72B7B2",
    "ip": "#FF9DA6", "asn": "#9D755D", "url": "#79706E",
    "cert": "#BAB0AC", "breach": "#D62728", "dns_record": "#1F77B4",
    "social_profile": "#9467BD", "phone": "#8C564B", "mac": "#E377C2",
}

ENTITY_LABELS: dict[str, str] = {
    "person": "人物", "username": "用户名", "email": "邮箱", "org": "组织",
    "domain": "域名", "subdomain": "子域名", "ip": "IP", "asn": "ASN",
    "url": "URL", "cert": "证书", "breach": "泄露", "dns_record": "DNS记录",
    "social_profile": "社交账号", "phone": "电话", "mac": "MAC",
}


def render(
    graph,
    output: str,
    title: str = "OSINT 关联分析图谱",
    colors: dict | None = None,
    legend: list | None = None,
) -> str:
    """渲染 OsintGraph (或 graph dict) → 自包含 HTML, 返回输出路径。"""
    colors = colors or ENTITY_COLORS
    legend = legend or [(t, ENTITY_LABELS.get(t, t)) for t in ENTITY_COLORS]
    g = graph.to_dict() if hasattr(graph, "to_dict") else graph
    html = _build_html(title, g.get("nodes", []), g.get("edges", []), colors, legend)
    out = str(output)
    Path(out).write_text(html, encoding="utf-8")
    return out


def _build_html(title: str, nodes: list, edges: list, colors: dict, legend: list) -> str:
    def color_of(node: dict) -> str:
        return colors.get(node.get("type", ""), "#888")

    node_rows = "\n".join(
        f'<li style="margin:3px 0;"><span style="display:inline-block;width:12px;height:12px;'
        f'background:{color_of(n)};border-radius:2px;margin-right:6px;"></span>'
        f'<code>{escape(str(n.get("type", "")))}</code> '
        f'<b>{escape(str(n.get("label") or n.get("name", "")))}</b>'
        f'<span style="color:#888"> ({escape(str(n.get("confidence", "")))})</span></li>'
        for n in nodes
    )
    edge_rows = "\n".join(
        f'<li style="margin:2px 0;"><code>{escape(str(e.get("source", "")))}</code> '
        f'<span style="color:#c00">--{escape(str(e.get("rel", "")))}--&gt;</span> '
        f'<code>{escape(str(e.get("target", "")))}</code></li>'
        for e in edges
    )
    legend_rows = "\n".join(
        f'<span style="display:inline-block;margin:2px 10px 2px 0;"><span style="display:inline-block;'
        f'width:12px;height:12px;background:{colors.get(t, "#888")};border-radius:2px;margin-right:4px;">'
        f'</span>{escape(str(lbl))}</span>'
        for t, lbl in legend
    )
    return f"""<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8">
<title>{escape(title)}</title>
<style>
 body {{ font-family: -apple-system, "Segoe UI", "Microsoft YaHei", sans-serif; margin: 24px; }}
 h1 {{ font-size: 20px; }} h2 {{ font-size: 15px; margin-top: 24px; }}
 ul {{ list-style: none; padding-left: 8px; }}
 code {{ font-family: "SFMono-Regular", Consolas, monospace; font-size: 12px; }}
</style>
</head>
<body>
<h1>{escape(title)}</h1>
<p>{len(nodes)} 节点 / {len(edges)} 边</p>
<div>{legend_rows}</div>
<h2>节点</h2>
<ul>{node_rows}</ul>
<h2>边</h2>
<ul>{edge_rows}</ul>
</body>
</html>
"""


__all__ = ["render", "ENTITY_COLORS", "ENTITY_LABELS"]
