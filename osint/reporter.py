"""reporter.py — 轻量进度 + 统一人类可读输出 (不引入 tqdm, 匹配项目 print 极简风格)。

进度写到 stderr, 保持 stdout 干净 (便于 --json 输出不被污染)。
"""

from __future__ import annotations

import sys

from .artifacts import OsintArtifact


class Progress:
    """单行进度刷新 (回车覆盖), 完成时换行。"""

    def __init__(self, total: int, what: str = "采集", prefix: str = "[osint]"):
        self.total = total
        self.what = what
        self.prefix = prefix
        self._n = 0

    def step(self, detail: str = "") -> None:
        self._n += 1
        line = f"{self.prefix} {self.what} {self._n}/{self.total}"
        if detail:
            line += f" — {detail}"
        print(f"\r{line}", end="", flush=True, file=sys.stderr)

    def done(self) -> None:
        print(flush=True, file=sys.stderr)


def format_artifacts(arts: list[OsintArtifact]) -> list[str]:
    """统一 human-readable 证据行 (收敛散落的 f-string print)。"""
    return [f"[{a.source}] {a.entity_type}: {a.value} ({a.confidence})" for a in arts]


__all__ = ["Progress", "format_artifacts"]
