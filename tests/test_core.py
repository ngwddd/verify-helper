# -*- coding: utf-8 -*-
"""核心判定逻辑的测试：三态、风险分级、证据、ignore、自定义规则。"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import check_specs as S          # noqa: E402
import verify_core as V          # noqa: E402
from tests import fixture        # noqa: E402


def by_id(rep: dict) -> dict:
    return {c["id"]: c for c in rep["checks"]}


class TestRegistry(unittest.TestCase):
    def test_every_spec_has_a_runner(self):
        for spec in S.SPECS:
            self.assertIn(spec.id, V.CHECKS, f"{spec.id} 没有实现")

    def test_risk_words_are_valid(self):
        for spec in S.SPECS:
            self.assertIn(spec.risk, S.RISK_ORDER)

    def test_blocking_derives_from_risk(self):
        for spec in S.SPECS:
            self.assertEqual(spec.blocking, spec.risk in S.BLOCKING_RISKS)

    def test_markdown_table_covers_all(self):
        table = S.markdown_table()
        for spec in S.SPECS:
            self.assertIn(f"`{spec.id}`", table)


class TestVerdicts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.broken = fixture.make_broken()
        cls.clean = fixture.make_clean()
        cls.rep_broken = V.verify(str(cls.broken), use_cache=False)
        cls.rep_clean = V.verify(str(cls.clean), use_cache=False)

    @classmethod
    def tearDownClass(cls):
        fixture.cleanup(cls.broken, cls.clean)

    def test_clean_project_passes(self):
        self.assertEqual(self.rep_clean["verdict"], "PASS", V.render(self.rep_clean))

    def test_broken_project_fails(self):
        self.assertEqual(self.rep_broken["verdict"], "FAIL")

    def test_each_planted_bug_is_caught(self):
        b = by_id(self.rep_broken)
        self.assertEqual(b["syntax"]["state"], "FAIL")
        self.assertEqual(b["links"]["state"], "FAIL")
        self.assertEqual(b["html"]["state"], "FAIL")
        self.assertEqual(b["secrets"]["state"], "FAIL")
        self.assertEqual(b["encoding"]["state"], "FAIL")
        self.assertEqual(b["tests"]["state"], "FAIL")

    def test_findings_have_file_and_message(self):
        for c in self.rep_broken["checks"]:
            for f in c["findings"]:
                self.assertIn("file", f)
                self.assertIn("message", f)
                self.assertTrue(f["file"])

    def test_non_blocking_failure_does_not_fail_verdict(self):
        """a11y / bom 这类低风险项即使不通过，也不能把总判定拉成 FAIL。"""
        b = by_id(self.rep_clean)
        for cid in ("a11y", "bom", "paths", "todos"):
            if b[cid]["state"] == "FAIL":
                self.assertFalse(b[cid]["blocking"], cid)

    def test_unknown_is_not_pass(self):
        import tempfile
        empty = Path(tempfile.mkdtemp(prefix="vh-empty-"))
        try:
            rep = V.verify(str(empty), use_cache=False)
            self.assertEqual(rep["verdict"], "UNKNOWN")
            self.assertIn("UNKNOWN", rep["notes"][0] if rep["notes"] else "UNKNOWN")
        finally:
            fixture.cleanup(empty)

    def test_failing_check_carries_remediation(self):
        b = by_id(self.rep_broken)
        self.assertTrue(b["syntax"]["remediation"])
        self.assertIn("怎么改", V.render(self.rep_broken))

    def test_risk_is_exposed(self):
        b = by_id(self.rep_broken)
        self.assertEqual(b["secrets"]["risk"], "critical")
        self.assertEqual(b["a11y"]["risk"], "low")


class TestIgnoreAndRules(unittest.TestCase):
    def test_verifyignore_excludes_template(self):
        p = fixture.make_with_ignore()
        try:
            rep = V.verify(str(p), use_cache=False)
            self.assertEqual(by_id(rep)["links"]["state"], "PASS", V.render(rep))
        finally:
            fixture.cleanup(p)

    def test_custom_rules_fire_and_raise_risk(self):
        p = fixture.make_with_rules()
        try:
            rep = V.verify(str(p), use_cache=False)
            c = by_id(rep)["custom"]
            self.assertEqual(c["state"], "FAIL")
            self.assertTrue(any("no-console-log" in f["message"] for f in c["findings"]))
            # 规则声明 risk=high → 该检查变成阻断项
            self.assertTrue(c["blocking"])
            self.assertEqual(rep["verdict"], "FAIL")
        finally:
            fixture.cleanup(p)

    def test_no_toml_means_not_applicable(self):
        p = fixture.make_clean()
        try:
            c = by_id(V.verify(str(p), use_cache=False))["custom"]
            self.assertEqual(c["state"], "UNKNOWN")
            self.assertFalse(c["applicable"])
        finally:
            fixture.cleanup(p)


class TestCli(unittest.TestCase):
    def test_list_checks_exit_zero(self):
        self.assertEqual(V.main_cli(["--list-checks"]), 0)

    def test_fail_exit_code(self):
        p = fixture.make_broken()
        try:
            self.assertEqual(V.main_cli([str(p), "--checks", "syntax"]), 1)
        finally:
            fixture.cleanup(p)

    def test_pass_exit_code(self):
        p = fixture.make_clean()
        try:
            self.assertEqual(V.main_cli([str(p)]), 0)
        finally:
            fixture.cleanup(p)


if __name__ == "__main__":
    unittest.main()
