# -*- coding: utf-8 -*-
"""测试用的临时目录，统一在进程退出时删掉（2026-10-27）。

背景：这些测试会为每个场景建一个临时项目，以前从不删除 ——
一次全量测试就在 %TEMP% 留下 100 多个 vh-* 目录（实测 189 个，
属于"跑一次脏一次"的典型）。用 atexit 兜底：无论测试通过、失败还是抛异常，
进程退出时都会清掉，测试文件自己不用写 teardown。
"""

from __future__ import annotations

import atexit
import shutil
import tempfile
from pathlib import Path

_DIRS: list[Path] = []


def mkdtemp(prefix: str = "vh-") -> Path:
    d = Path(tempfile.mkdtemp(prefix=prefix))
    _DIRS.append(d)
    return d


@atexit.register
def _cleanup() -> None:
    while _DIRS:
        d = _DIRS.pop()
        try:
            shutil.rmtree(d, ignore_errors=True)
        except Exception:
            pass
