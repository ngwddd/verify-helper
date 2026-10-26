# -*- coding: utf-8 -*-
"""v1.10.5：安全层必须区分「真调用」和「当字符串用的模式」。

实测事故：`tests/test_v03_bridge.py` 里有一行

    for bad in ("os.system(", "subprocess.", "eval(", "exec("):

安全层把它当成 3 条高危（eval / exec / os.system），
理由是「引号后面紧贴 token」—— 那是**模式字符串**，不是调用。
这类误报会让"安全层"变成噪声源，人就开始无视它。

同时防过头：真调用必须照报。
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import _tmp  # noqa: F401  （统一回收临时目录）

import lifecycle as LC  # noqa: E402


def _mk(base: Path, files: dict[str, str]) -> None:
    for rel, body in files.items():
        p = base / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")


def _labels(root: Path) -> list[str]:
    sec = LC.security_layer(root, {"checks": []})
    return [f["message"] for f in sec["findings"]]


class TestQuotedPatterns(unittest.TestCase):
    def test_pattern_strings_not_flagged(self) -> None:
        root = Path(_tmp.mkdtemp(prefix="vh-q1-"))
        _mk(root, {"t.py": 'BAD = ("os.system(", "eval(", "exec(")\n'})
        labels = _labels(root)
        self.assertFalse([x for x in labels if "系统" in x or "eval" in x or "exec" in x],
                         f"字符串里的模式不该被报：{labels}")

    def test_real_calls_still_flagged(self) -> None:
        root = Path(_tmp.mkdtemp(prefix="vh-q2-"))
        _mk(root, {"t.py": "import os\nos.system('ls')\nprint(eval('1+1'))\n"})
        labels = _labels(root)
        self.assertTrue(any("os.system" in x for x in labels), labels)
        self.assertTrue(any("eval" in x for x in labels), labels)

    def test_single_quote_and_backtick_too(self) -> None:
        root = Path(_tmp.mkdtemp(prefix="vh-q3-"))
        _mk(root, {"t.mjs": "const pats = ['eval(', `exec(`];\n"})
        labels = _labels(root)
        self.assertFalse([x for x in labels if "eval" in x or "exec" in x], labels)


if __name__ == "__main__":
    unittest.main()
