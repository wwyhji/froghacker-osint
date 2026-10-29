"""live.py — 实时全球态势 OSINT 情报采集。

直连免费公开数据源 (无 API key、不经第三方聚合站)，产出全球动态快照。

数据源:
  1. 航班      — OpenSky Network  (states/all)
  2. 地震      — USGS FDSN Event   (GeoJSON)
  3. 灾害/台风 — NASA EONET        (火山/山火/风暴等)
  4. 恶意软件  — Abuse.ch Feodo    (C2 IP 黑名单)
  5. 太空天气  — NOAA SWPC         (行星 Kp 指数)
  6. 卫星      — Celestrak         (活跃卫星 TLE)

明确跳过 (无稳定免费统一公开 API): CCTV / 海事 AIS / 辐射 / 核设施。

蛙客的情报触角伸向互联网的每一个角落.

用法:
    from osint.live import live_intel
    result = live_intel(domains=["flights", "malware"])

    python -m osint.live --domain flights,earthquakes --json
"""

from __future__ import annotations

import argparse
import json
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import requests

_REQUEST_HEADERS = {
    "User-Agent": "FrogHackerOSINT/1.0",
    "Accept": "application/json",
}

# Celestrak 对非浏览器 UA 不友好，需浏览器 UA
_BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "application/json",
}

# 可采集的域 (与 LiveIntelResult 字段一一对应)
_DOMAINS = (
    "flights",
    "earthquakes",
    "events",
    "malware",
    "space_weather",
    "satellites",
)


# ── Data Classes ────────────────────────────────────────────────


@dataclass
class FlightState:
    """单架航班状态。"""
    callsign: str = ""
    country: str = ""
    lon: float = 0.0
    lat: float = 0.0
    altitude: float = 0.0
    on_ground: bool = False

    def to_dict(self) -> dict:
        return {
            "callsign": self.callsign,
            "country": self.country,
            "lon": self.lon,
            "lat": self.lat,
            "altitude": self.altitude,
            "on_ground": self.on_ground,
        }


@dataclass
class Earthquake:
    """单次地震事件。"""
    magnitude: float = 0.0
    place: str = ""
    lon: float = 0.0
    lat: float = 0.0
    time: str = ""
    time_ms: int = 0  # 原始毫秒时间戳，用于增量游标

    def to_dict(self) -> dict:
        return {
            "magnitude": self.magnitude,
            "place": self.place,
            "lon": self.lon,
            "lat": self.lat,
            "time": self.time,
            "time_ms": self.time_ms,
        }


@dataclass
class EonetEvent:
    """台风/火山/山火等自然灾害事件。"""
    title: str = ""
    category: str = ""
    lon: float = 0.0
    lat: float = 0.0

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "category": self.category,
            "lon": self.lon,
            "lat": self.lat,
        }


@dataclass
class MalwareC2:
    """恶意软件 C2 服务器。"""
    ip: str = ""
    port: int = 0
    malware: str = ""
    status: str = ""
    asn: str = ""

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "port": self.port,
            "malware": self.malware,
            "status": self.status,
            "asn": self.asn,
        }


@dataclass
class SpaceWeather:
    """行星 Kp 指数。"""
    kp_index: float = 0.0
    time: str = ""

    def to_dict(self) -> dict:
        return {"kp_index": self.kp_index, "time": self.time}


@dataclass
class SatelliteTle:
    """单颗卫星 TLE 条目。"""
    name: str = ""
    norad_id: str = ""

    def to_dict(self) -> dict:
        return {"name": self.name, "norad_id": self.norad_id}


@dataclass
class LiveIntelResult:
    """聚合的实时态势快照。"""
    timestamp: str = ""
    domains: list[str] = field(default_factory=list)
    flights: list[FlightState] = field(default_factory=list)
    earthquakes: list[Earthquake] = field(default_factory=list)
    events: list[EonetEvent] = field(default_factory=list)
    malware: list[MalwareC2] = field(default_factory=list)
    space_weather: Optional[SpaceWeather] = None
    satellites: int = 0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "domains": self.domains,
            "flights": [f.to_dict() for f in self.flights],
            "earthquakes": [q.to_dict() for q in self.earthquakes],
            "events": [e.to_dict() for e in self.events],
            "malware": [m.to_dict() for m in self.malware],
            "space_weather": self.space_weather.to_dict() if self.space_weather else None,
            "satellites": self.satellites,
            "errors": self.errors,
        }


# ── Internal Helpers ────────────────────────────────────────────


def _read_json_resp(resp: requests.Response, timeout: int) -> dict | list:
    """流式读取响应体并解析 JSON，带硬截止时间。

    requests 的 read timeout 只约束块间隔，无法约束"持续慢速滴流"的总时长
    (如 OpenSky 1.4MB 载荷在某些网络下龟速下载)，故用 deadline 兜底。
    """
    deadline = time.time() + timeout
    chunks: list[bytes] = []
    for chunk in resp.iter_content(65536):
        if time.time() > deadline:
            resp.close()
            raise TimeoutError(f"下载超时 ({timeout}s)")
        chunks.append(chunk)
    resp.close()
    return json.loads(b"".join(chunks).decode("utf-8", errors="replace"))


def _get_json(url: str, timeout: int) -> dict | list:
    resp = requests.get(url, headers=_REQUEST_HEADERS, timeout=(5, timeout), stream=True)
    try:
        resp.raise_for_status()
        return _read_json_resp(resp, timeout)
    except Exception:
        resp.close()
        raise


def _parse_flight_state(s: list) -> Optional[FlightState]:
    # OpenSky state vector: [icao24, callsign, origin_country, time, last_contact,
    #                        lon, lat, baro_altitude, on_ground, ...]
    if s[5] is None or s[6] is None:
        return None  # 无位置数据，跳过
    return FlightState(
        callsign=(s[1] or "").strip(),
        country=s[2] or "",
        lon=float(s[5]),
        lat=float(s[6]),
        altitude=float(s[7]) if s[7] is not None else 0.0,
        on_ground=bool(s[8]),
    )


def _fetch_flights(timeout: int, max_per_domain: int) -> list[FlightState]:
    """流式截断: 只下载前 max_per_domain 条 state 就中止。

    OpenSky states/all 返回 1.4MB 全量且无 limit 参数，某些网络下龟速下载。
    这里边下边定位 "states" 数组，凑满 N 条即截断补全 JSON，110s -> ~3s。
    """
    url = "https://opensky-network.org/api/states/all"
    resp = requests.get(url, headers=_REQUEST_HEADERS, timeout=(5, timeout), stream=True)
    try:
        resp.raise_for_status()
        deadline = time.time() + timeout
        buf = b""
        marker = b'"states":['
        while marker not in buf:
            chunk = next(resp.iter_content(65536), None)
            if chunk is None:
                return []  # 响应结束仍未找到 states
            if time.time() > deadline:
                raise TimeoutError(f"下载超时 ({timeout}s)")
            buf += chunk

        i = buf.index(marker) + len(marker)  # 指向第一个 state 的 '['
        depth = 0
        count = 0
        while count < max_per_domain:
            while i < len(buf) and count < max_per_domain:
                c = buf[i]
                i += 1
                if c == 0x5B:  # '['
                    depth += 1
                elif c == 0x5D:  # ']'
                    depth -= 1
                    if depth == 0:
                        count += 1
            if count >= max_per_domain:
                break
            chunk = next(resp.iter_content(65536), None)
            if chunk is None:
                break  # 响应结束，不足 max_per_domain
            if time.time() > deadline:
                raise TimeoutError(f"下载超时 ({timeout}s)")
            buf += chunk

        data = json.loads((buf[:i] + b"]}").decode("utf-8", errors="replace"))
        states = data.get("states", []) if isinstance(data, dict) else []
        flights: list[FlightState] = []
        for s in states:
            f = _parse_flight_state(s)
            if f:
                flights.append(f)
        return flights
    finally:
        resp.close()


def _fetch_earthquakes(
    timeout: int,
    max_per_domain: int,
    min_magnitude: float,
    starttime: Optional[str] = None,
) -> list[Earthquake]:
    """USGS 地震。starttime 提供时只拉该时间之后的地震 (增量)。"""
    params: dict = {
        "format": "geojson",
        "minmagnitude": min_magnitude,
        "limit": max_per_domain,
        "orderby": "time",
    }
    if starttime:
        params["starttime"] = starttime
    resp = requests.get(
        "https://earthquake.usgs.gov/fdsnws/event/1/query",
        params=params, headers=_REQUEST_HEADERS, timeout=(5, timeout), stream=True,
    )
    try:
        resp.raise_for_status()
        data = _read_json_resp(resp, timeout)
    except Exception:
        resp.close()
        raise
    features = data.get("features", []) if isinstance(data, dict) else []
    quakes: list[Earthquake] = []
    for f in features[:max_per_domain]:
        props = f.get("properties", {}) or {}
        geom = (f.get("geometry") or {})
        coords = geom.get("coordinates", [0.0, 0.0, 0.0]) or [0.0, 0.0, 0.0]
        ts_ms = props.get("time", 0) or 0
        quakes.append(Earthquake(
            magnitude=float(props.get("mag", 0.0) or 0.0),
            place=props.get("place", ""),
            lon=float(coords[0]),
            lat=float(coords[1]),
            time=datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc).isoformat() if ts_ms else "",
            time_ms=int(ts_ms),
        ))
    quakes.sort(key=lambda q: q.time_ms, reverse=True)  # 最新在前
    return quakes


def _extract_lon_lat(geom: Optional[dict]) -> tuple[float, float]:
    """从 EONET geometry 对象提取 [lon, lat]。"""
    coords = (geom.get("coordinates", []) or []) if geom else []
    if not coords:
        return 0.0, 0.0
    if isinstance(coords[0], (int, float)):
        return float(coords[0]), float(coords[1]) if len(coords) > 1 else 0.0
    # Polygon: 嵌套坐标
    try:
        ring = coords[0]
        if isinstance(ring[0], (int, float)):
            return float(ring[0]), float(ring[1])
        return float(ring[0][0]), float(ring[0][1])
    except (IndexError, TypeError):
        return 0.0, 0.0


def _fetch_events(timeout: int, max_per_domain: int) -> list[EonetEvent]:
    url = f"https://eonet.gsfc.nasa.gov/api/v3/events?status=open&limit={max_per_domain}"
    data = _get_json(url, timeout)
    raw_events = data.get("events", []) if isinstance(data, dict) else []
    events: list[EonetEvent] = []
    for ev in raw_events[:max_per_domain]:
        cats = ev.get("categories", []) or []
        category = cats[0].get("title", "") if cats else ""
        geom = (ev.get("geometry") or [{}])[0] if ev.get("geometry") else None
        lon, lat = _extract_lon_lat(geom)
        events.append(EonetEvent(
            title=ev.get("title", ""),
            category=category,
            lon=lon,
            lat=lat,
        ))
    return events


def _fetch_malware(timeout: int, max_per_domain: int) -> list[MalwareC2]:
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
    data = _get_json(url, timeout)
    entries = data if isinstance(data, list) else []
    result: list[MalwareC2] = []
    for e in entries[:max_per_domain]:
        asn = e.get("as_number", "") or e.get("asn", "") or ""
        result.append(MalwareC2(
            ip=e.get("ip_address", ""),
            port=int(e.get("port", 0) or 0),
            malware=e.get("malware", ""),
            status=e.get("status", ""),
            asn=str(asn),
        ))
    return result


def _fetch_space_weather(timeout: int) -> Optional[SpaceWeather]:
    url = "https://services.swpc.noaa.gov/json/planetary_k_index_1m.json"
    data = _get_json(url, timeout)
    if not isinstance(data, list) or not data:
        return None
    last = data[-1]
    # 每项为 dict: {"time_tag": "...", "kp_index": 3, "estimated_kp": 2.67, ...}
    if not isinstance(last, dict):
        return None
    kp = last.get("kp_index", 0) or 0
    return SpaceWeather(kp_index=float(kp), time=str(last.get("time_tag", "")))


_satellite_cache: dict = {"count": 0, "ts": 0.0}


def _fetch_satellites(timeout: int, max_per_domain: int) -> int:
    """活跃卫星总数。

    Celestrak 数据每 2 小时才更新一次，短时重复请求返回 403 "数据未更新"
    (非拦截)，此时复用进程内缓存。进程内缓存对 --watch 轮询有效。
    """
    url = "https://celestrak.org/NORAD/elements/gp.php?GROUP=active&FORMAT=json"
    resp = requests.get(url, headers=_BROWSER_HEADERS, timeout=(5, timeout), stream=True)
    try:
        if resp.status_code == 200:
            data = _read_json_resp(resp, timeout)
            count = len(data) if isinstance(data, list) else 0
            _satellite_cache["count"] = count
            _satellite_cache["ts"] = time.time()
            return count
        if resp.status_code == 403 and b"not updated" in (resp.content or b""):
            return _satellite_cache["count"]  # 数据未更新，复用缓存
        resp.raise_for_status()
        return 0
    finally:
        resp.close()


# ── Public API ──────────────────────────────────────────────────


def live_intel(
    domains: Optional[list[str]] = None,
    timeout: int = 15,
    max_per_domain: int = 20,
    min_magnitude: float = 4.0,
    earthquake_since: Optional[str] = None,
) -> LiveIntelResult:
    """采集实时全球态势快照。

    Args:
        domains:        要采集的域列表 (默认: 全部); 可含 "flights"/"earthquakes"/
                        "events"/"malware"/"space_weather"/"satellites"
        timeout:        单域请求超时 (秒)
        max_per_domain: 每域最大条目数
        min_magnitude:  地震最小震级阈值
        earthquake_since: 只拉该时间之后的地震 (ISO 时间，增量模式)

    Returns LiveIntelResult。单域失败不拖垮整体，错误记入 errors。
    """
    if domains is None:
        domains = list(_DOMAINS)
    else:
        domains = [d.strip().lower() for d in domains]

    result = LiveIntelResult(
        timestamp=datetime.now(timezone.utc).isoformat(),
        domains=domains,
    )

    fetchers = {
        "flights": lambda: _fetch_flights(timeout, max_per_domain),
        "earthquakes": lambda: _fetch_earthquakes(timeout, max_per_domain, min_magnitude, earthquake_since),
        "events": lambda: _fetch_events(timeout, max_per_domain),
        "malware": lambda: _fetch_malware(timeout, max_per_domain),
        "space_weather": lambda: _fetch_space_weather(timeout),
        "satellites": lambda: _fetch_satellites(timeout, max_per_domain),
    }

    valid: list[str] = []
    for d in domains:
        if d in fetchers:
            valid.append(d)
        else:
            result.errors.append(f"未知域: {d}")

    def _run(dom: str) -> tuple:
        try:
            return dom, fetchers[dom](), None
        except Exception as e:  # noqa: BLE001 — 单域失败不拖垮整体
            return dom, None, e

    # 各域 I/O 密集，并发采集，总耗时 = 最慢域而非逐域累加
    with ThreadPoolExecutor(max_workers=len(valid) or 1) as ex:
        for dom, value, err in ex.map(_run, valid):
            if err is not None:
                result.errors.append(f"{dom} 采集失败: {err}")
            else:
                setattr(result, dom, value)

    return result


def format_live(result: LiveIntelResult) -> str:
    """将快照格式化为人类可读文本。"""
    lines: list[str] = []
    lines.append(f"实时态势快照 — {result.timestamp}")
    lines.append("=" * 56)
    lines.append(f"航班: {len(result.flights)} 架")
    for f in result.flights[:5]:
        lines.append(f"  - {f.callsign or '(无呼号)':<10} {f.country:<4} "
                     f"({f.lat:.2f},{f.lon:.2f}) 高度{f.altitude:.0f}m")
    lines.append(f"地震: {len(result.earthquakes)} 起")
    for q in result.earthquakes[:5]:
        lines.append(f"  M{q.magnitude:.1f}  {q.place}")
    lines.append(f"灾害事件: {len(result.events)} 起")
    for e in result.events[:5]:
        lines.append(f"  [{e.category or '未知'}] {e.title}")
    lines.append(f"恶意软件 C2: {len(result.malware)} 个")
    for m in result.malware[:5]:
        lines.append(f"  {m.ip}:{m.port}  {m.malware or '未知'}  ({m.status})")
    if result.space_weather:
        lines.append(f"太空天气 Kp: {result.space_weather.kp_index} "
                     f"({result.space_weather.time})")
    lines.append(f"活跃卫星: {result.satellites} 颗" if result.satellites else "活跃卫星: 未知")
    if result.errors:
        lines.append(f"错误: {len(result.errors)}")
        for e in result.errors:
            lines.append(f"  - {e}")
    return "\n".join(lines)


def diff_live(prev: LiveIntelResult, curr: LiveIntelResult) -> list[str]:
    """比较两次快照，返回变化描述列表 (用于 --watch 增量输出)。"""
    changes: list[str] = []

    # 地震 — 事件流只增不减，仅报新增
    seen_q = {q.time for q in prev.earthquakes if q.time}
    for q in curr.earthquakes:
        if q.time and q.time not in seen_q:
            changes.append(f"[地震] M{q.magnitude:.1f} {q.place}")

    # 航班 — 新增/消失
    prev_f = {f.callsign for f in prev.flights if f.callsign}
    curr_f = {f.callsign for f in curr.flights if f.callsign}
    for cs in sorted(curr_f - prev_f):
        changes.append(f"[航班+] {cs}")
    for cs in sorted(prev_f - curr_f):
        changes.append(f"[航班-] {cs}")

    # 灾害事件 — 新增/结束
    prev_e = {e.title for e in prev.events}
    curr_e = {e.title for e in curr.events}
    for t in curr_e - prev_e:
        changes.append(f"[事件+] {t}")
    for t in prev_e - curr_e:
        changes.append(f"[事件-] {t}")

    # C2 — 新增/下线/状态变化
    prev_m = {m.ip: m for m in prev.malware if m.ip}
    curr_m = {m.ip: m for m in curr.malware if m.ip}
    for ip in curr_m.keys() - prev_m.keys():
        m = curr_m[ip]
        changes.append(f"[C2+] {ip}:{m.port} {m.malware}")
    for ip in prev_m.keys() - curr_m.keys():
        changes.append(f"[C2-] {ip}")
    for ip in prev_m.keys() & curr_m.keys():
        if prev_m[ip].status != curr_m[ip].status:
            changes.append(f"[C2~] {ip} {prev_m[ip].status}->{curr_m[ip].status}")

    # 太空天气 — Kp 变化
    if prev.space_weather and curr.space_weather:
        if prev.space_weather.kp_index != curr.space_weather.kp_index:
            changes.append(f"[Kp] {prev.space_weather.kp_index}->{curr.space_weather.kp_index}")
    elif curr.space_weather and not prev.space_weather:
        changes.append(f"[Kp] {curr.space_weather.kp_index}")

    # 卫星 — 数量变化
    if prev.satellites and curr.satellites and prev.satellites != curr.satellites:
        changes.append(f"[卫星] {prev.satellites}->{curr.satellites}")

    return changes


def run_live(
    domains: Optional[list[str]] = None,
    timeout: int = 15,
    max_per_domain: int = 20,
    min_magnitude: float = 4.0,
    watch: Optional[int] = None,
    as_json: bool = False,
    html_output: Optional[str] = None,
) -> None:
    """轮询快照并输出: 首轮打印全量基线，后续只报增量变化。

    地震域启用时间增量 (earthquake_since 游标)，其余域全量 diff。
    html_output 提供时，每轮把快照渲染为 HTML 地图写入该路径。
    """
    if html_output:
        from .viz import render_live

    prev: Optional[LiveIntelResult] = None
    eq_since: Optional[str] = None
    while True:
        result = live_intel(
            domains=domains, timeout=timeout, max_per_domain=max_per_domain,
            min_magnitude=min_magnitude, earthquake_since=eq_since,
        )
        if html_output:
            render_live(result, html_output)
        if prev is None:
            if as_json:
                print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
            else:
                print(format_live(result))
        else:
            changes = diff_live(prev, result)
            if as_json:
                print(json.dumps({"timestamp": result.timestamp, "changes": changes},
                                 ensure_ascii=False, indent=2))
            elif changes:
                print(f"\n--- {result.timestamp} ({len(changes)} 处变化) ---")
                for c in changes:
                    print(f"  {c}")
            else:
                print(f"\n--- {result.timestamp} 无变化 ---")
        prev = result
        if result.earthquakes:
            latest_ms = result.earthquakes[0].time_ms  # 已排序，[0] 最新
            eq_since = datetime.fromtimestamp(
                max(latest_ms - 1000, 0) / 1000, tz=timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%S")
        if watch is None:
            break
        time.sleep(watch)


# ── Standalone CLI ──────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="osint-live",
        description="实时全球态势 OSINT 采集 (航班/地震/灾害/恶意软件/太空天气/卫星)",
    )
    parser.add_argument("--domain", help="域列表，逗号分隔 (默认: 全部)")
    parser.add_argument("--timeout", type=int, default=15, help="请求超时 (秒)")
    parser.add_argument("--max", type=int, default=20, help="每域最大条目数")
    parser.add_argument("--min-magnitude", type=float, default=4.0, help="地震最小震级")
    parser.add_argument("--watch", type=int, help="每 N 秒轮询一次")
    parser.add_argument("--json", action="store_true", help="JSON 输出")
    parser.add_argument("--html", help="输出 HTML 地图文件路径 (Leaflet)")
    args = parser.parse_args()

    domains = args.domain.split(",") if args.domain else None
    run_live(
        domains=domains,
        timeout=args.timeout,
        max_per_domain=args.max,
        min_magnitude=args.min_magnitude,
        watch=args.watch,
        as_json=args.json,
        html_output=args.html,
    )


if __name__ == "__main__":
    main()
