# -*- coding: utf-8 -*-
"""v1.10.6 的三条新行为（都是这轮验证时踩出来的真实问题）。

1. 「全部用例被跳过」不能算 PASS —— 以前它会给出假绿。
2. 跑测试要优先用**项目自己的 venv**（ABI 可能和系统 Python 不同）。
3. `# noqa` 的行不参与「未使用的 import」判定。
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import verify_core as V


class TestAllSkippedIsUnknown(unittest.TestCase):
    def _check_with(self, out: str, code: int = 0):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "tests").mkdir()
            (root / "tests" / "test_x.py").write_text("import unittest\n", encoding="utf-8")
            orig = V._run
            V._run = lambda *a, **k: (code, out)          # 不真的跑
            try:
                return V.check_tests(root, list(root.rglob("*.py")), V.Ctx(V.Cache()))
            finally:
                V._run = orig

    def test_all_skipped_is_unknown(self) -> None:
        c = self._check_with("Ran 10 tests in 0.000s\n\nOK (skipped=10)\n")
        self.assertEqual(c.state, "UNKNOWN", c.detail)
        self.assertIn("跳过", c.detail)

    def test_partial_skip_still_pass(self) -> None:
        c = self._check_with("Ran 20 tests in 1.2s\n\nOK (skipped=3)\n")
        self.assertEqual(c.state, "PASS", c.detail)

    def test_real_failure_still_fail(self) -> None:
        c = self._check_with("Ran 5 tests in 0.1s\n\nFAILED (failures=1)\n", code=1)
        self.assertEqual(c.state, "FAIL")


class TestPythonForTests(unittest.TestCase):
    def test_env_var_wins(self) -> None:
        import os
        with tempfile.TemporaryDirectory() as d:
            fake = Path(d) / "py.exe"
            fake.write_text("", encoding="utf-8")
            old = os.environ.get("DSH_TEST_PYTHON")
            os.environ["DSH_TEST_PYTHON"] = str(fake)
            try:
                self.assertEqual(V._py_for(Path(d)), str(fake))
            finally:
                if old is None:
                    os.environ.pop("DSH_TEST_PYTHON", None)
                else:
                    os.environ["DSH_TEST_PYTHON"] = old

    def test_verify_python_file(self) -> None:
        import os
        with tempfile.TemporaryDirectory() as d:
            fake = Path(d) / "py.exe"
            fake.write_text("", encoding="utf-8")
            (Path(d) / ".verify-python").write_text(str(fake) + "\n", encoding="utf-8")
            old = os.environ.pop("DSH_TEST_PYTHON", None)
            try:
                self.assertEqual(V._py_for(Path(d)), str(fake))
            finally:
                if old is not None:
                    os.environ["DSH_TEST_PYTHON"] = old

    def test_fallback_is_current_python(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(V._py_for(Path(d)), sys.executable)


class TestNoqaHonoured(unittest.TestCase):
    def test_noqa_import_not_reported(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "a.py").write_text(
                "import _bootstrap  # noqa: F401\n\nprint('hi')\n", encoding="utf-8")
            c = V.check_imports(root, [root / "a.py"], V.Ctx(V.Cache()))
            self.assertEqual(c.findings, [], c.findings)

    def test_plain_unused_import_still_reported(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "b.py").write_text("import json\n\nprint('x')\n", encoding="utf-8")
            c = V.check_imports(root, [root / "b.py"], V.Ctx(V.Cache()))
            self.assertEqual(len(c.findings), 1, c.findings)


if __name__ == "__main__":
    unittest.main()
