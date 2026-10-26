# -*- coding: utf-8 -*-
"""v1.3 新增能力的测试：基线差分与变异门。"""
from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import _tmp  # noqa: F401  （统一回收临时目录）

import verify_core as V          # noqa: E402
from tests import fixture        # noqa: E402


def by_id(rep: dict) -> dict:
    return {c["id"]: c for c in rep["checks"]}


class TestBaseline(unittest.TestCase):
    def test_roundtrip_no_change(self):
        p = fixture.make_clean()
        try:
            rep = V.verify(str(p), use_cache=False)
            snap = V.baseline_snapshot(rep)
            diff = V.baseline_compare(rep, snap)
            self.assertEqual(diff["new"], [])
            self.assertEqual(diff["regressed"], [])
        finally:
            fixture.cleanup(p)

    def test_detects_new_problem(self):
        p = fixture.make_clean()
        try:
            rep = V.verify(str(p), use_cache=False)
            snap = V.baseline_snapshot(rep)
            (p / "broken.py").write_text("def f(:\n", encoding="utf-8")
            rep2 = V.verify(str(p), use_cache=False)
            diff = V.baseline_compare(rep2, snap)
            self.assertEqual(len(diff["new"]), 1)
            self.assertEqual(diff["new"][0]["check"], "syntax")
            self.assertIn("syntax", diff["regressed"])
        finally:
            fixture.cleanup(p)

    def test_detects_fixed_problem(self):
        p = fixture.make_broken()
        try:
            rep = V.verify(str(p), checks=["syntax"], use_cache=False)
            snap = V.baseline_snapshot(rep)
            (p / "bad.py").unlink()
            (p / "bad.mjs").unlink()
            (p / "config.json").unlink()
            rep2 = V.verify(str(p), checks=["syntax"], use_cache=False)
            diff = V.baseline_compare(rep2, snap)
            self.assertTrue(diff["fixed"])
            self.assertIn("syntax", diff["improved"])
        finally:
            fixture.cleanup(p)

    def test_fingerprint_ignores_line_moves(self):
        a = {"file": "x.py", "line": 3, "message": "boom"}
        b = {"file": "x.py", "line": 99, "message": "boom"}
        self.assertEqual(V._fingerprint(a), V._fingerprint(b))


class TestMutation(unittest.TestCase):
    def _weak_project(self) -> Path:
        d = Path(_tmp.mkdtemp(prefix="vh-mut-"))
        (d / "tests").mkdir()
        (d / "calc.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
        (d / "tests" / "test_calc.py").write_text(
            "import unittest\nfrom calc import add\n\n\n"
            "class T(unittest.TestCase):\n"
            "    def test_add(self):\n"
            "        add(1, 2)\n",          # 没有断言
            encoding="utf-8")
        return d

    def test_survived_mutant_is_reported(self):
        d = self._weak_project()
        try:
            rep = V.verify(str(d), checks=["mutation"], use_cache=False)
            c = by_id(rep)["mutation"]
            self.assertEqual(c["state"], "FAIL", c["detail"])
            self.assertTrue(any("没有有效断言" in f["message"] for f in c["findings"]))
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_source_is_restored(self):
        d = self._weak_project()
        try:
            V.verify(str(d), checks=["mutation"], use_cache=False)
            self.assertEqual((d / "calc.py").read_text(encoding="utf-8"),
                             "def add(a, b):\n    return a + b\n")
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_not_applicable_without_tests(self):
        p = fixture.make_clean()
        try:
            c = by_id(V.verify(str(p), checks=["mutation"], use_cache=False))["mutation"]
            self.assertEqual(c["state"], "UNKNOWN")
            self.assertFalse(c["applicable"])
        finally:
            fixture.cleanup(p)

    def test_not_in_default_run(self):
        p = fixture.make_clean()
        try:
            rep = V.verify(str(p), use_cache=False)
            self.assertNotIn("mutation", by_id(rep))
        finally:
            fixture.cleanup(p)


if __name__ == "__main__":
    unittest.main()
