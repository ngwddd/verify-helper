# -*- coding: utf-8 -*-
"""tests 检查的判定边界（v1.9.1 回归测试）。

守三条真实踩过的坑：
  1. 测试在 `root/tests/` 时，命令必须带 `-s tests`。
     否则 discover 用默认 start dir（=root）→ 收集 0 个 → 退出码 5 → **假 FAIL**。
     （实测现场：工作区根目录 62 个 .py、0 个 test_*.py，却被判"测试失败"）
  2. 收集到 0 个用例（退出码 5 / "NO TESTS RAN"）是「测不了」，必须记 UNKNOWN，
     不能记 FAIL —— FAIL 意味着"用例跑了但没过"。
  3. 真有用例失败时，仍然是 FAIL，并带出失败用例名。
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import verify_core as V  # noqa: E402


def _mk(root: Path, files: dict[str, str]) -> None:
    for rel, body in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")


def _tests_check(root: Path):
    rep = V.verify(str(root), checks=["tests"], use_cache=False)
    return next(c for c in rep["checks"] if c["id"] == "tests")


PASSING = """
import unittest
class T(unittest.TestCase):
    def test_ok(self):
        self.assertTrue(True)
"""

FAILING = """
import unittest
class T(unittest.TestCase):
    def test_bad(self):
        self.assertEqual(1, 2)
"""

EMPTY = """
# 有文件，但没有用例
X = 1
"""


SCRIPT_NO_CASES = """
import sys
print("hi")   # 探针脚本，名字像测试但没有用例
"""

REAL_STAR_TEST = """
import unittest
class T(unittest.TestCase):
    def test_ok(self):
        self.assertTrue(True)
"""


def _detect(root):
    return V._detect_test_command(root)


class TestDetection(unittest.TestCase):
    def test_subdir_tests_dir_is_used_as_start_dir(self) -> None:
        """tests/ 下有 test_*.py 时，应当 PASS（而不是在 root 收集 0 个）。"""
        root = Path(tempfile.mkdtemp(prefix="vh-td-"))
        _mk(root, {"tests/test_a.py": PASSING})
        c = _tests_check(root)
        self.assertEqual(c["state"], "PASS", f"应该是 PASS，实际 {c['state']}：{c.get('detail')}")
        self.assertIn("tests", c.get("command") or "", "命令里必须带 -s tests")

    def test_no_tests_ran_is_unknown_not_fail(self) -> None:
        """有 test_*.py 但 0 个用例 → UNKNOWN（不能谎报失败）。"""
        root = Path(tempfile.mkdtemp(prefix="vh-td-"))
        _mk(root, {"test_empty.py": EMPTY})
        c = _tests_check(root)
        self.assertEqual(c["state"], "UNKNOWN", f"实际 {c['state']}：{c.get('detail')}")
        # v1.10.3 起：没有用例的文件在**探测阶段**就被排除，detail 会说「没有用例」；
        # 更早的版本靠跑出来「收集到 0 个用例」。两种都必须判 UNKNOWN。
        self.assertIn("用例", c.get("detail") or "")

    def test_real_failure_stays_fail(self) -> None:
        """真有用例失败时仍然是 FAIL（别把这条修正用过头）。"""
        root = Path(tempfile.mkdtemp(prefix="vh-td-"))
        _mk(root, {"tests/test_a.py": FAILING})
        c = _tests_check(root)
        self.assertEqual(c["state"], "FAIL")
        self.assertEqual(c.get("exit_code"), 1)

    def test_script_named_test_is_not_entry(self) -> None:
        """`_foo_test.py` 这类探针脚本不该被当成测试入口（实测踩过）。"""
        root = Path(tempfile.mkdtemp(prefix="vh-td-"))
        _mk(root, {"_desktop_mcp_test.py": SCRIPT_NO_CASES})
        cmd, why, _ = _detect(root)
        self.assertIsNone(cmd, f"不该识别出入口，why={why}")
        self.assertIn("没有用例", why)

    def test_star_test_pattern_is_used(self) -> None:
        """命中 `*_test.py` 时，命令里的 -p 必须是 `*_test.py`（否则等于没跑）。"""
        root = Path(tempfile.mkdtemp(prefix="vh-td-"))
        _mk(root, {"helpers_test.py": REAL_STAR_TEST})
        cmd, why, _ = _detect(root)
        self.assertIsNotNone(cmd, f"应识别出入口，why={why}")
        self.assertIn("*_test.py", cmd, f"命令应为 {cmd}")
        c = _tests_check(root)
        self.assertEqual(c["state"], "PASS", f"实际 {c['state']}：{c.get('detail')}")

    def test_no_entry_is_unknown_not_applicable(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="vh-td-"))
        _mk(root, {"app.py": "print(1)\n"})
        c = _tests_check(root)
        self.assertEqual(c["state"], "UNKNOWN")
        self.assertFalse(c.get("applicable", True))


if __name__ == "__main__":
    unittest.main()
