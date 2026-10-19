# -*- coding: utf-8 -*-
"""SARIF 2.1.0 输出的结构测试。

SARIF 一旦结构错了，GitHub Code Scanning 会整份拒收，而且报错很难懂，
所以这里把关键字段逐条钉住。
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import check_specs as S          # noqa: E402
import sarif                     # noqa: E402
import verify_core as V          # noqa: E402
from tests import fixture        # noqa: E402


class TestSarif(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.broken = fixture.make_broken()
        cls.rep = V.verify(str(cls.broken), use_cache=False)
        cls.doc = sarif.to_sarif(cls.rep, V.VERSION)

    @classmethod
    def tearDownClass(cls):
        fixture.cleanup(cls.broken)

    def test_top_level(self):
        self.assertEqual(self.doc["version"], "2.1.0")
        self.assertIn("sarif-2.1.0", self.doc["$schema"])
        self.assertIsInstance(self.doc["runs"], list)
        self.assertEqual(len(self.doc["runs"]), 1)

    def test_driver(self):
        d = self.doc["runs"][0]["tool"]["driver"]
        self.assertEqual(d["name"], "verify-helper")
        self.assertTrue(d["version"])
        self.assertTrue(d["informationUri"].startswith("http"))
        # 规则表 = 报告里出现过的检查项（默认不跑 git，所以不一定是 SPECS 全量）
        reported = {c["id"] for c in self.rep["checks"]}
        self.assertEqual({r["id"] for r in d["rules"]}, reported)
        for r in d["rules"]:
            self.assertIn(r["id"], S.BY_ID)

    def test_every_rule_has_remediation(self):
        for rule in self.doc["runs"][0]["tool"]["driver"]["rules"]:
            self.assertIn("remediation", rule["properties"])
            self.assertTrue(rule["properties"]["remediation"])

    def test_results_point_at_real_files(self):
        results = self.doc["runs"][0]["results"]
        self.assertTrue(results, "假项目应该产生至少一条 result")
        for r in results:
            self.assertIn(r["level"], ("error", "warning", "note"))
            self.assertTrue(r["message"]["text"])
            loc = r["locations"][0]["physicalLocation"]
            self.assertTrue(loc["artifactLocation"]["uri"])
            self.assertLess(r["ruleIndex"], len(self.doc["runs"][0]["tool"]["driver"]["rules"]))

    def test_severity_maps_to_level(self):
        levels = {r["ruleId"]: r["level"] for r in self.doc["runs"][0]["results"]}
        self.assertEqual(levels.get("secrets"), "error")     # critical
        self.assertEqual(levels.get("syntax"), "error")      # high

    def test_json_serialisable(self):
        text = sarif.dumps(self.rep, V.VERSION)
        again = json.loads(text)
        self.assertEqual(again["version"], "2.1.0")

    def test_passing_project_has_no_results(self):
        clean = fixture.make_clean()
        try:
            rep = V.verify(str(clean), use_cache=False)
            doc = sarif.to_sarif(rep, V.VERSION)
            self.assertEqual(doc["runs"][0]["results"], [])
            self.assertTrue(doc["runs"][0]["invocations"][0]["executionSuccessful"])
        finally:
            fixture.cleanup(clean)


if __name__ == "__main__":
    unittest.main()
