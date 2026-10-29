"""sources — OSINT 主动采集适配器注册表 (镜像 harness/checkers/registry)。

每个源一个 SourceAdapter 子类, @register 注册。
付费源 env_key 缺失时 enabled()=False → collect() 记录 skipped 不抛异常。
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from pathlib import Path

from ..artifacts import OsintArtifact, normalize
from ..cache import cache, cache_key
from ..rate_limiter import limiter
from ..reporter import Progress

_REGISTRY: dict[str, type] = {}
_instances: dict[str, "SourceAdapter"] = {}

# 付费源 key 一览 (env_key -> 描述)
KNOWN_KEYS: dict[str, str] = {
    "HIBP_API_KEY": "HaveIBeenPwned",
    "HUNTERIO_API_KEY": "Hunter.io",
    "SHODAN_API_KEY": "Shodan",
    "ABUSEIPDB_API_KEY": "AbuseIPDB",
    "SECURITYTRAILS_API_KEY": "SecurityTrails",
    "CENSYS_API_ID": "Censys API ID",
    "CENSYS_API_SECRET": "Censys API Secret",
    "VT_API_KEY": "VirusTotal",
    "GREYNOISE_API_KEY": "GreyNoise (社区版免费)",
    "LEAKIX_API_KEY": "LeakIX (免费注册)",
    "DEHASHED_API_KEY": "DeHashed",
    "DEHASHED_EMAIL": "DeHashed 账号邮箱",
    "INTELX_API_KEY": "Intelligence X",
    "ETHERSCAN_API_KEY": "Etherscan (免费注册)",
}


class SourceAdapter(ABC):
    """OSINT 源适配器基类。"""

    name: str = ""                # 注册名 (collect 时用)
    entity_types: tuple = ()      # 该源可采集的实体类型
    paid: bool = False            # True 表示需 key
    env_key: str = ""             # 付费源的主 key 环境变量名
    extra_keys: tuple = ()        # 额外需要的 env key (双 key 源, 如 censys/dehashed)
    polite_delay: float = 1.0     # 源间礼貌延迟 (秒, 已由 rate_limit 取代, 保留兼容)
    rate_limit: tuple = ()        # 免费源限流 (requests, seconds), 空 = 不限

    def required_keys(self) -> tuple:
        """该源需要的全部 env key (主 key + 额外 key)。"""
        return (self.env_key,) + tuple(self.extra_keys)

    def enabled(self) -> bool:
        """付费源缺任一 key → False。"""
        if not self.paid:
            return True
        return all(os.environ.get(k, "") for k in self.required_keys())

    def cached_collect(self, target: str, entity_type: str = "", limit: int = 20) -> list[OsintArtifact]:
        """带缓存 + 贴限的采集入口 (collect 与 identity 直调共用, 避免重复网络)。"""
        key = cache_key(entity_type or "", target, self.name)
        cached = cache.get(key)
        if cached is not None:
            return cached
        limiter.acquire(self.name, self.rate_limit)
        arts = self.collect(target, entity_type=entity_type, limit=limit)
        cache.set(key, arts)
        return arts

    @abstractmethod
    def collect(self, target: str, entity_type: str = "", limit: int = 20) -> list[OsintArtifact]:
        ...


def register(cls):
    """装饰器: 注册 adapter 类 (类属性 name 必填)。"""
    if not cls.name:
        raise ValueError(f"adapter missing name: {cls!r}")
    _REGISTRY[cls.name] = cls
    return cls


def get_adapter(name: str) -> "SourceAdapter":
    """按注册名取 adapter 实例, 未知名抛 KeyError。"""
    if name not in _REGISTRY:
        raise KeyError(f"unknown osint source: {name}")
    inst = _instances.get(name)
    if inst is None:
        inst = _REGISTRY[name]()
        _instances[name] = inst
    return inst


def adapters_for(entity_type: str = "") -> list["SourceAdapter"]:
    """返回可采集某实体类型的 adapter 列表 (entity_type 为空返回全部)。"""
    out: list["SourceAdapter"] = []
    for name in _REGISTRY:
        a = get_adapter(name)
        if not entity_type or entity_type in a.entity_types:
            out.append(a)
    return out


def list_sources() -> list[str]:
    """已注册源名列表。"""
    return list(_REGISTRY.keys())


def _dotenv_path() -> Path:
    """项目根 .env 路径 (tools/osint/sources -> 项目根)。"""
    return Path(__file__).resolve().parents[3] / ".env"


def key_status() -> list[dict]:
    """列出所有付费源的 key 配置状态。

    Returns [{source, enabled, keys: [{name, description, configured}]}]。
    """
    from ..http_client import load_dotenv
    load_dotenv()
    out: list[dict] = []
    for name in sorted(_REGISTRY):
        a = get_adapter(name)
        if not a.paid:
            continue
        keys = [
            {
                "name": k,
                "description": KNOWN_KEYS.get(k, ""),
                "configured": bool(os.environ.get(k, "")),
            }
            for k in a.required_keys()
        ]
        out.append({"source": name, "enabled": a.enabled(), "keys": keys})
    return out


def set_env_key(key: str, value: str) -> bool:
    """写入 KEY=VALUE 到项目根 .env (gitignore 保护), 并立即生效。"""
    if not key or "=" in key or "\n" in key or "\n" in value:
        return False
    env_path = _dotenv_path()
    lines = env_path.read_text(encoding="utf-8").splitlines() if env_path.exists() else []
    updated = False
    for i, line in enumerate(lines):
        if line.split("=", 1)[0].strip() == key:
            lines[i] = f"{key}={value}"
            updated = True
            break
    if not updated:
        lines.append(f"{key}={value}")
    try:
        env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        os.environ[key] = value
        return True
    except OSError:
        return False


def unset_env_key(key: str) -> bool:
    """从项目根 .env 移除 KEY, 并立即生效。"""
    env_path = _dotenv_path()
    if not env_path.exists():
        return False
    lines = env_path.read_text(encoding="utf-8").splitlines()
    kept = [l for l in lines if l.split("=", 1)[0].strip() != key]
    try:
        env_path.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")
        os.environ.pop(key, None)
        return True
    except OSError:
        return False


def _resolve_workers(n_adapters: int) -> int:
    """解析并发 worker 数: 默认 min(n, 8), OSINT_MAX_WORKERS 覆盖。

    osint 面向外部免费 API, 克制并发 (不复用 recon 的 cap-200)。
    """
    if n_adapters <= 1:
        return 1
    env = os.environ.get("OSINT_MAX_WORKERS", "").strip()
    if env:
        try:
            return max(1, int(env))
        except ValueError:
            pass
    return min(n_adapters, 8)


def _collect_one(adapter: "SourceAdapter", target: str, entity_type: str, limit: int):
    """采集单源 (经 cached_collect 缓存+贴限), 异常捕获返回 ([], err)。"""
    try:
        return adapter.cached_collect(target, entity_type=entity_type, limit=limit), None
    except Exception as e:  # 单源失败不中断
        return [], str(e)


def collect(
    target: str,
    entity_type: str = "",
    sources=None,
    limit: int = 20,
    return_errors: bool = False,
) -> list[OsintArtifact]:
    """聚合所有(或指定)适配器采集结果; 并发 + TTL 缓存, 单源失败不中断。

    并发结果按 adapter 注册顺序重组, 保证确定性; 缓存命中跳过网络。
    return_errors=True 时返回 (arts, errors), errors 为 {source_name: err}。
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    wanted = set(sources) if sources else None
    adapters: list["SourceAdapter"] = []
    for a in adapters_for(entity_type):
        if wanted is not None and a.name not in wanted:
            continue
        if not a.enabled():
            print(f"[osint] 跳过 {a.name}: 缺少 {a.env_key}")
            continue
        adapters.append(a)

    out: list[OsintArtifact] = []
    errors: dict[str, str] = {}
    if not adapters:
        return (out, errors) if return_errors else out

    results: dict[str, list] = {}
    n_workers = _resolve_workers(len(adapters))
    progress = Progress(len(adapters), what="采集")

    if n_workers <= 1:
        # 串行: cached_collect 内部处理缓存+贴限
        for a in adapters:
            arts, err = _collect_one(a, target, entity_type, limit)
            if err:
                errors[a.name] = err
            results[a.name] = arts
            progress.step(a.name)
    else:
        # 并发: worker 池限流, cached_collect 内部处理缓存+贴限
        with ThreadPoolExecutor(max_workers=n_workers) as pool:
            futs = {pool.submit(_collect_one, a, target, entity_type, limit): a.name for a in adapters}
            for fut in as_completed(futs):
                name = futs[fut]
                try:
                    arts, err = fut.result()
                except Exception as e:  # 防御: future 意外异常
                    arts, err = [], str(e)
                if err:
                    errors[name] = err
                results[name] = arts
                progress.step(name)

    progress.done()

    # 按 adapter 注册顺序重组, 保证测试稳定
    for a in adapters:
        if a.name in results:
            out.extend(results[a.name])

    if return_errors:
        return out, errors
    return out


# 导入各源模块触发 @register 注册
from . import (  # noqa: E402,F401
    crtsh, wayback, dns, whois, emailrep,
    hackertarget, urlscan, otx, github_api,
    hibp, hunter, shodan, abuseipdb, securitytrails, censys, vt,
    greynoise, leakix, dehashed, intelx, phone,
    blockchain, etherscan, chainabuse, reddit,
    bgpview, macvendor,
)

__all__ = [
    "SourceAdapter", "register", "get_adapter", "adapters_for",
    "list_sources", "collect", "KNOWN_KEYS",
    "key_status", "set_env_key", "unset_env_key",
]
