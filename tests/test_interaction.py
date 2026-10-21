# -*- coding: utf-8 -*-
"""交互测试：流程解析的校验 + 无配置/无浏览器时的降级。

真正跑浏览器的那部分需要 playwright，在 CI 里不存在，
所以这里只覆盖「不依赖浏览器」的那些路径；端到端在本地用 my-site 手工验证。
"""
from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import verify_core as V          # noqa: E402


def proj(toml_text: str | None) -> Path:
    d = Path(tempfile.mkdtemp(prefix="vh-flow-"))
    (d / "index.html").write_text(
        '<html lang="zh"><head><title>t</title></head><body><h1>x</h1></body></html>',
        encoding="utf-8")
    if toml_text is not None:
        (d / "verify.toml").write_text(toml_text, encoding="utf-8")
    return d


GOOD = """
[[flows]]
name = "能点"
steps = [
  { goto = "index.html" },
  { expect = { selector = "h1", text_contains = "x" } },
]
"""


class TestFlowParsing(unittest.TestCase):
    def tearDown(self):
        for d in getattr(self, "_dirs", []):
            shutil.rmtree(d, ignore_errors=True)

    def _load(self, toml_text):
        d = proj(toml_text)
        self._dirs = getattr(self, "_dirs", []) + [d]
        return V._load_flows(d)

    def test_no_toml(self):
        flows, why = self._load(None)
        self.assertEqual(flows, [])
        self.assertIn("没有 verify.toml", why)

    def test_no_flows_section(self):
        flows, why = self._load('[[rules]]\nid="x"\npattern="y"\n')
        self.assertEqual(flows, [])
        self.assertIn("没有 [[flows]]", why)

    def test_flow_without_steps(self):
        flows, why = self._load('[[flows]]\nname = "空的"\n')
        self.assertEqual(flows, [])
        self.assertIn("没有 steps", why)

    def test_step_without_action(self):
        flows, why = self._load('[[flows]]\nname="x"\nsteps=[{ value = 1 }]\n')
        self.assertEqual(flows, [])
        self.assertIn("没有可识别的动作", why)

    def test_step_with_two_actions(self):
        flows, why = self._load('[[flows]]\nname="x"\nsteps=[{ click="a", fill="b" }]\n')
        self.assertEqual(flows, [])
        self.assertIn("多个动作", why)

    def test_unknown_expect_key(self):
        _, why = self._load('[[flows]]\nname="x"\nsteps=[{ expect={ selector="a", colour="red" } }]\n')
        self.assertIn("不认识的键", why)

    def test_expect_without_target(self):
        _, why = self._load('[[flows]]\nname="x"\nsteps=[{ expect={ visible=true } }]\n')
        self.assertIn("缺少", why)

    def test_good_flow(self):
        flows, why = self._load(GOOD)
        self.assertEqual(why, "")
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0]["name"], "能点")
        self.assertEqual(len(flows[0]["steps"]), 2)


class TestCheckFallback(unittest.TestCase):
    def test_not_applicable_without_flows(self):
        d = proj(None)
        try:
            rep = V.verify(str(d), checks=["interaction"], use_cache=False)
            c = {x["id"]: x for x in rep["checks"]}["interaction"]
            self.assertEqual(c["state"], "UNKNOWN")
            self.assertFalse(c["applicable"])
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_unknown_when_playwright_missing(self):
        d = proj(GOOD)
        try:
            if V._find_playwright(d) is not None:
                self.skipTest("这台机器上有 playwright，跳过降级用例")
            rep = V.verify(str(d), checks=["interaction"], use_cache=False)
            c = {x["id"]: x for x in rep["checks"]}["interaction"]
            self.assertEqual(c["state"], "UNKNOWN")
            self.assertIn("playwright", c["detail"])
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_fast_mode_skips(self):
        d = proj(GOOD)
        try:
            rep = V.verify(str(d), checks=["interaction"], fast=True, use_cache=False)
            c = {x["id"]: x for x in rep["checks"]}["interaction"]
            self.assertEqual(c["state"], "UNKNOWN")
            self.assertIn("fast", c["detail"])
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
