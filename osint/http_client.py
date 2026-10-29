"""http_client.py — OSINT HTTP 客户端层。

thread-local requests.Session (并发安全), 对外只暴露安全 API:
缺 key 返回 None、遇错返回 None 不抛异常。
"""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from typing import Optional

import requests

# 线程本地 session (并发下共享进程级单例不安全)
_local = threading.local()

# .env 路径 (当前工作目录)
_ENV_PATH = Path.cwd() / ".env"
_dotenv_loaded = False

_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"


def load_dotenv(force: bool = False) -> None:
    """加载项目根 .env 到 os.environ (幂等, 不覆盖已存在的变量)。

    轻量手写解析 (KEY=VALUE / 注释 # / 双引号), 不依赖 python-dotenv。
    """
    global _dotenv_loaded
    if _dotenv_loaded and not force:
        return
    _dotenv_loaded = True
    if not _ENV_PATH.exists():
        return
    try:
        for line in _ENV_PATH.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = val
    except OSError:
        pass


def get_session() -> requests.Session:
    """线程本地 requests.Session (并发下每个线程独立 session, 避免状态竞争)。"""
    s = getattr(_local, "session", None)
    if s is None:
        s = requests.Session()
        s.headers.update({"User-Agent": _UA})
        _local.session = s
    return s


def get_key(name: str) -> str:
    """读取环境变量 key, 缺失返回空串。"""
    return os.environ.get(name, "")


# 模块导入时加载一次 .env (使 osint 源能读到项目根 .env 里的 key)
load_dotenv()


def safe_get_json(
    url: str,
    *,
    session=None,
    timeout: float = 15,
    headers: Optional[dict] = None,
    params: Optional[dict] = None,
    key_name: str = "",
    key_header: str = "",
    auth: Optional[tuple] = None,
) -> Optional[object]:
    """GET JSON, 任何异常/非 200 返回 None (不抛)。key_name 存在时经 key_header 头携带。"""
    s = session or get_session()
    hdrs = dict(headers or {})
    if key_name:
        key = get_key(key_name)
        if not key:
            return None
        if key_header:
            hdrs[key_header] = key
    try:
        resp = s.get(url, params=params, headers=hdrs or None, timeout=timeout, auth=auth)
        if resp.status_code != 200:
            return None
        return resp.json()
    except Exception:
        return None


def safe_post_json(
    url: str,
    *,
    session=None,
    timeout: float = 15,
    headers: Optional[dict] = None,
    json: Optional[dict] = None,
    key_name: str = "",
    key_header: str = "",
) -> Optional[object]:
    """POST JSON, 任何异常/非 200 返回 None (不抛)。key_name 存在时经 key_header 头携带。"""
    s = session or get_session()
    hdrs = dict(headers or {})
    if key_name:
        key = get_key(key_name)
        if not key:
            return None
        if key_header:
            hdrs[key_header] = key
    try:
        resp = s.post(url, json=json, headers=hdrs or None, timeout=timeout)
        if resp.status_code != 200:
            return None
        return resp.json()
    except Exception:
        return None


def safe_get_text(
    url: str,
    *,
    session=None,
    timeout: float = 15,
    headers: Optional[dict] = None,
    params: Optional[dict] = None,
) -> Optional[str]:
    """GET 纯文本, 任何异常/非 200 返回 None (不抛)。"""
    s = session or get_session()
    try:
        resp = s.get(url, params=params, headers=headers or None, timeout=timeout)
        if resp.status_code != 200:
            return None
        return resp.text
    except Exception:
        return None


def polite_wait(seconds: float) -> None:
    """源间礼貌延迟。"""
    if seconds and seconds > 0:
        time.sleep(seconds)


__all__ = ["load_dotenv", "get_session", "get_key", "safe_get_json", "safe_post_json", "safe_get_text", "polite_wait"]
