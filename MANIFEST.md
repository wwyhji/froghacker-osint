# MANIFEST — 开源剥离清单

本仓库（osint-oss）从蛙客主仓库 `tools/osint/` 剥离而来，按「四不碰」边界（攻击侧 / 专利数学引擎 / 检材案例 / 身份密钥）做了以下裁剪。

## 开源内容

- **数据模型** `artifacts.py`：`OsintArtifact` / `OsintGraph` / `ENTITY_TYPES` / `normalize` / `synonym_key`（同义撞击）
- **基础设施**：`cache.py`（TTL 缓存）、`rate_limiter.py`（per-source token bucket 贴限）、`reporter.py`（进度/格式化）、`http_client.py`（thread-local requests.Session）
- **图引擎**：`graph_engine.py`（detect_type / extract_entities / expand BFS 多跳）、`graph_viz.py`（自包含 HTML 渲染）
- **27 源适配器** `sources/`：crtsh / wayback / dns / whois / emailrep / hackertarget / urlscan / otx / github_api / blockchain / chainabuse / reddit / phone(简化) / bgpview / macvendor + 12 付费源（需 key）
- **能力模块**：email_lookup / username_search / domain_intel / social_lookup / breach_check / company_lookup / metasearch / person_search / crypto_search / verify / report / live / viz / gatherer
- **编排**：runner / osint_agent（confidence 排序）/ identity（网络·地理·域名画像）

## 剥离项

| 剥离项 | 原因 |
|--------|------|
| `cli.py` | CLIRegistry 平台耦合 |
| `phone_search.py` | 电信画像（phoneinfoga + 号段库，攻击侧） |
| `geolocation.py` | 视觉取证后端（vision.image_forensics + core.backends） |
| `sources/phone.py` 的 cn_mobile 分支 | telecom_fraud 号段库（攻击侧），仅保留国际区号→国家映射 |
| `identity.py` 的 `_telecom_profile` | telecom_fraud 依赖 |
| `runner.py` / `osint_agent.py` 的 AlphaLoop 摄入 | 知识库自充飞轮（平台耦合 + 专利） |
| `osint_agent.py` 的语义排序 `_embed` | kb.semantic_retriever + analytics.semantic_layer（数学引擎） |
| `graph_viz.py` 的 `render_html` | forensics.phone_graph（取证域），重写为自包含 HTML |
| `http_client.py` 的 `StealthSession` | anti_crawl（反爬对抗），换标准 requests.Session |
| `swallow_trap` | 平台日志，try/except 兜底 |

## 依赖

- 必需：`requests`
- 可选：`dnspython`（`domain_intel` 的 DNS 查询，缺失时静默跳过）
