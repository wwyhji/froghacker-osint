# froghacker-osint v0.1.0

蛙客「开源情报（OSINT）分析」模块的首个开源版 —— 27 个数据源聚合、实体关联图谱、
身份画像、并发采集 + TTL 缓存 + per-source 贴限。Apache-2.0。

## 核心能力

- **多源聚合** `collect`：27 源适配器（WHOIS / DNS / crt.sh / emailrep / hackertarget /
  urlscan / OTX / GitHub / bgpview / macvendor …），`ThreadPoolExecutor` 并发 + 按注册序重组
- **关联图谱** `expand_graph`：多跳 BFS 展开，16 种边类型（resolves_to / has_subdomain /
  registered_to / belongs_to …），度中心性枢轴截断
- **身份画像** `identity_profile`：ip → bgpview(ASN/ORG) + ip-api(geo)；domain/email → WHOIS
- **缓存 + 贴限**：内存 TTL 缓存（`synonym_key` 同义撞击去重）+ per-source token bucket 限流，
  跨调用共享额度
- **六阶段 agent** `run_agent`：Route → Collect → Graph → Rank → Verify → Report

## 技术要点

- **同义撞击去重** `synonym_key`：email/url 归约到域名、phone 去 +86 国家码，让同义实体撞同一缓存键
- **cache 下沉** `SourceAdapter.cached_collect`：collect 与 identity 直调共享缓存，避免重复网络采集
- **per-source 贴限**：macvendors 1/s、ip-api 45/min、github 60/h、hackertarget 50/day、
  urlscan 20/min、bgpview 2/s（查证值，低置信源取保守 1/s）

## 剥离说明

本仓库从蛙客主仓库 `tools/osint/` 剥离，移除电信反诈号段库（攻击侧）、视觉取证、AlphaLoop
摄入、语义排序（专利数学引擎）等，详见 MANIFEST.md。

## 许可与合规

- Apache License 2.0，专利保留声明见 NOTICE
- 仅查询公开数据源，不进行任何攻击；请遵守目标服务 ToS 与当地法律

---

# froghacker-osint v0.1.0

The first open-source release of FrogHacker's OSINT module — 27 data-source aggregation,
entity relationship graph, identity profiling, concurrent collection + TTL cache +
per-source rate limiting. Apache-2.0.

## Highlights

- **Multi-source aggregation** `collect`: 27 adapters, `ThreadPoolExecutor` concurrency,
  deterministic ordering
- **Relationship graph** `expand_graph`: multi-hop BFS, 16 edge types, degree-centrality pivoting
- **Identity profiling** `identity_profile`: ip → bgpview + ip-api; domain/email → WHOIS
- **Cache + rate limiting**: in-memory TTL cache (`synonym_key` collision dedup) +
  per-source token bucket, shared across calls
- **Six-stage agent** `run_agent`: Route → Collect → Graph → Rank → Verify → Report

## License & compliance

Apache-2.0 (see LICENSE/NOTICE). Queries public data sources only — no offensive capability.
Respect target ToS and local law.
