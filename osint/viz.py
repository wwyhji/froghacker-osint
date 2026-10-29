"""viz.py — live 情报地图可视化。

将 LiveIntelResult 渲染为自包含 Leaflet HTML 地图：
  航班/地震/灾害事件按经纬度标记 (可缩放、点标记弹详情)
  C2/太空天气/卫星汇总到侧边栏

依赖 Leaflet + OpenStreetMap (CDN 联网加载)。

用法:
    from osint.viz import render_live
    html = render_live(result, "live_map.html")
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>蛙客 · 实时态势地图</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<style>
  html, body { height: 100%; margin: 0; font-family: -apple-system, "Microsoft YaHei", sans-serif; }
  #map { position: absolute; inset: 0; background: #0d1117; }
  #panel { position: absolute; top: 12px; right: 12px; z-index: 1000; width: 300px;
           max-height: calc(100% - 24px); overflow-y: auto; background: rgba(16,18,24,0.94);
           color: #e6e6e6; border-radius: 10px; padding: 14px 16px; font-size: 13px;
           box-shadow: 0 4px 20px rgba(0,0,0,0.45); }
  #panel h1 { font-size: 16px; margin: 0 0 4px; color: #fff; }
  #panel .ts { color: #8a93a5; font-size: 11px; margin-bottom: 10px; word-break: break-all; }
  #panel .row { display: flex; justify-content: space-between; padding: 5px 0;
                border-bottom: 1px solid rgba(255,255,255,0.07); }
  #panel .dot { display: inline-block; width: 9px; height: 9px; border-radius: 50%; margin-right: 6px; }
  #panel h3 { font-size: 12px; color: #7f8ea3; margin: 14px 0 5px; }
  #panel .c2 { font-family: ui-monospace, Consolas, monospace; font-size: 11px;
               padding: 2px 0; }
  #panel .online { color: #5fd38a; }
  #panel .offline { color: #e06c75; }
  .legend { position: absolute; bottom: 22px; left: 12px; z-index: 1000;
            background: rgba(16,18,24,0.88); color: #d5dae3; border-radius: 8px;
            padding: 8px 12px; font-size: 12px; }
</style>
</head>
<body>
<div id="map"></div>
<div id="panel"></div>
<div class="legend" id="legend"></div>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script>
const DATA = __DATA_PLACEHOLDER__;

const map = L.map('map', { worldCopyJump: true }).setView([20, 0], 2);
L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', {
  maxZoom: 18,
  attribution: '&copy; OpenStreetMap contributors'
}).addTo(map);

const groups = {
  flights: L.layerGroup().addTo(map),
  earthquakes: L.layerGroup().addTo(map),
  events: L.layerGroup().addTo(map),
};

// 航班 (蓝点)
(DATA.flights || []).forEach(f => {
  L.circleMarker([f.lat, f.lon], { radius: 4, color: '#1E88E5', weight: 1,
    fillColor: '#1E88E5', fillOpacity: 0.75 })
    .bindPopup(`<b>${f.callsign || '(无呼号)'}</b><br>${f.country || ''}<br>高度 ${Math.round(f.altitude)} m`)
    .addTo(groups.flights);
});

// 地震 (红点, 半径随震级)
(DATA.earthquakes || []).forEach(q => {
  L.circleMarker([q.lat, q.lon], { radius: 3 + q.magnitude * 1.5, color: '#E53935', weight: 1,
    fillColor: '#E53935', fillOpacity: 0.5 })
    .bindPopup(`<b>M${q.magnitude}</b> ${q.place}<br>${q.time}`)
    .addTo(groups.earthquakes);
});

// 灾害事件 (橙点)
(DATA.events || []).forEach(e => {
  L.circleMarker([e.lat, e.lon], { radius: 6, color: '#FB8C00', weight: 1,
    fillColor: '#FB8C00', fillOpacity: 0.65 })
    .bindPopup(`<b>[${e.category || '未知'}]</b> ${e.title}`)
    .addTo(groups.events);
});

L.control.layers(null, {
  '航班': groups.flights,
  '地震': groups.earthquakes,
  '灾害事件': groups.events,
}, { collapsed: false }).addTo(map);

const sw = DATA.space_weather;
const c2 = DATA.malware || [];
document.getElementById('panel').innerHTML = `
  <h1>实时态势</h1>
  <div class="ts">${DATA.timestamp}</div>
  <div class="row"><span><span class="dot" style="background:#1E88E5"></span>航班</span><b>${(DATA.flights||[]).length}</b></div>
  <div class="row"><span><span class="dot" style="background:#E53935"></span>地震</span><b>${(DATA.earthquakes||[]).length}</b></div>
  <div class="row"><span><span class="dot" style="background:#FB8C00"></span>灾害事件</span><b>${(DATA.events||[]).length}</b></div>
  <div class="row"><span><span class="dot" style="background:#8E24AA"></span>恶意软件 C2</span><b>${c2.length}</b></div>
  ${sw ? `<div class="row"><span><span class="dot" style="background:#00ACC1"></span>Kp 指数</span><b>${sw.kp_index}</b></div>` : ''}
  <div class="row"><span><span class="dot" style="background:#757575"></span>活跃卫星</span><b>${DATA.satellites || '未知'}</b></div>
  <h3>C2 服务器</h3>
  ${c2.map(m => `<div class="c2 ${m.status === 'online' ? 'online' : 'offline'}">${m.ip}:${m.port} ${m.malware || ''} (${m.status})</div>`).join('') || '<div class="c2" style="color:#8a93a5">无</div>'}
`;

document.getElementById('legend').innerHTML = `
  <span class="dot" style="background:#1E88E5"></span>航班 &nbsp;
  <span class="dot" style="background:#E53935"></span>地震 &nbsp;
  <span class="dot" style="background:#FB8C00"></span>灾害事件
`;
</script>
</body>
</html>
"""


def render_live(result, output: Optional[str] = None) -> str:
    """将 live 快照渲染为 Leaflet HTML 地图。

    Args:
        result: LiveIntelResult 或 to_dict() 输出 (dict)
        output: 输出文件路径 (提供时写入 UTF-8)

    Returns HTML 字符串。
    """
    data = result.to_dict() if hasattr(result, "to_dict") else result
    # 防 </script> 注入
    payload = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    html = HTML_TEMPLATE.replace("__DATA_PLACEHOLDER__", payload)
    if output:
        Path(output).write_text(html, encoding="utf-8")
    return html


def main() -> None:
    """从 JSON 文件渲染地图 (供独立运行)。"""
    import argparse

    parser = argparse.ArgumentParser(description="live 情报 JSON -> HTML 地图")
    parser.add_argument("json_file", help="live 快照 JSON 文件路径")
    parser.add_argument("--output", default="live_map.html", help="输出 HTML 路径")
    args = parser.parse_args()

    with open(args.json_file, encoding="utf-8") as f:
        data = json.load(f)
    render_live(data, args.output)
    print(f"地图已生成: {args.output}")


if __name__ == "__main__":
    main()
