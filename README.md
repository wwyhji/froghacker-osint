# froghacker-osint

蛙客「开源情报（OSINT）分析」模块的开源版 —— 27 个数据源聚合、实体关联图谱、身份画像、
并发采集 + TTL 缓存 + per-source 贴限。Apache-2.0。

## 核心能力

| 能力 | 说明 |
|------|------|
| **多源聚合** `collect` | 27 源适配器（WHOIS/DNS/crt.sh/emailrep/hackertarget/urlscan/OTX/GitHub/bgpview/macvendor…），`ThreadPoolExecutor` 并发 + 按注册序重组 |
| **关联图谱** `expand_graph` | 多跳 BFS 展开，16 种边类型（resolves_to/has_subdomain/registered_to/belongs_to…），度中心性枢轴截断 |
| **身份画像** `identity_profile` | ip → bgpview(ASN/ORG) + ip-api(geo)；domain/email → WHOIS |
| **缓存 + 贴限** | 内存 TTL 缓存（`synonym_key` 同义撞击去重）+ per-source token bucket 限流，跨调用共享额度 |
| **六阶段 agent** `run_agent` | Route → Collect → Graph → Rank → Verify → Report |

## 安装

```bash
pip install -e .            # 或 pip install froghacker-osint
pip install -e ".[dns]"     # 可选：DNS 记录查询（dnspython）
```

## 快速上手

```python
from osint import collect, expand_graph, run_agent, identity_profile, list_sources

# 1. 聚合采集（免费源，付费源需 key）
arts = collect("example.com", entity_type="domain")
for a in arts:
    print(f"[{a.source}] {a.entity_type}: {a.value}")

# 2. 多跳关联图谱
graph = expand_graph("example.com", entity_type="domain", max_depth=2)
print(f"{len(graph.nodes)} 节点 / {len(graph.edges)} 边")

# 3. 身份画像（网络/地理/域名）
prof = identity_profile("8.8.8.8")
print(prof.to_markdown())

# 4. 六阶段搜索 agent
result = run_agent("example.com")
print(result.report)

# 5. 列出所有源
print(list_sources())
```

## 源列表

**免费（无 key）**：crtsh, wayback, dns, whois, emailrep, hackertarget, urlscan, otx,
github_api, blockchain, chainabuse, reddit, phone, bgpview, macvendor

**付费（需 API key）**：hibp, hunter, shodan, abuseipdb, securitytrails, censys, vt,
greynoise, leakix, dehashed, intelx, etherscan —— key 通过环境变量注入（如 `SHODAN_API_KEY`）。

## 礼貌采集（可选）

`StealthSession` 提供 drop-in `requests.Session` 的**礼貌采集层（非对抗）**：

- 标准浏览器 UA / Sec-CH-* 头轮换（避免默认 python-requests UA 被拦）
- per-domain 随机延迟 + 429/503 指数退避 + 尊重 `Retry-After`
- WAF/CAPTCHA **检测**（`ChallengeDetector`）——只识别不绕过，默认返回原始响应

```python
from osint import StealthSession, ChallengeDetector

s = StealthSession(profile="chrome_win")
resp = s.get("https://target.com/page")
if ChallengeDetector.is_blocked(resp):
    print("被 WAF/验证码拦截，已如实返回，不绕过")
```

对抗部分（代理池轮换规避封禁、浏览器指纹伪装）未开源，保留在主仓库，详见 [MANIFEST.md](MANIFEST.md)。

## 架构

四层架构：入口/编排 → 采集 → 图引擎 → 基础设施。详见 [docs/osint-architecture.md](docs/osint-architecture.md)。

## 许可与合规

- 依据 **Apache License 2.0** 授权（见 [LICENSE](LICENSE)），专利保留声明见 [NOTICE](NOTICE)。
- 本工具只查询**公开数据源**，不进行任何攻击。请遵守目标服务的使用条款与当地法律，仅用于授权的安全评估、研究与防御。

## 剥离说明

本仓库从蛙客主仓库 `tools/osint/` 剥离而来，移除了电信反诈号段库（攻击侧）、视觉取证、
AlphaLoop 摄入、语义排序（专利数学引擎）等，详见 [MANIFEST.md](MANIFEST.md)。
