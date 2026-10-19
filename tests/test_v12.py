# -*- coding: utf-8 -*-
"""v1.2 新增能力的测试：浏览器层降级、退出码阈值、部署前缀。"""
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


class TestBrowserLayer(unittest.TestCase):
    def test_registered_and_blocking(self):
        spec = S.get("browser")
        self.assertEqual(spec.risk, "high")
        self.assertTrue(spec.blocking)

    def test_not_applicable_without_html(self):
        p = fixture.make_clean()
        try:
            rep = V.verify(str(p), checks=["browser"], use_cache=False)
            c = by_id(rep)["browser"]
            # 干净项目有 index.html，但没装 playwright → 至少不能谎报 PASS
            self.assertIn(c["state"], ("UNKNOWN", "PASS", "FAIL"))
            if c["state"] == "PASS":
                self.assertIn("真跑", c["detail"])
        finally:
            fixture.cleanup(p)

    def test_fast_no_longer_skips_browser(self):
        """v1.4 起 fast 只跳测试/变异 —— 浏览器层是抓真问题的主力，不能被 fast 吞掉。"""
        p = fixture.make_clean()
        try:
            rep = V.verify(str(p), checks=["browser"], fast=True, use_cache=False)
            c = by_id(rep)["browser"]
            self.assertNotIn("fast", c["detail"])
        finally:
            fixture.cleanup(p)


class TestFailOn(unittest.TestCase):
    def test_worst_risk_picks_most_severe(self):
        p = fixture.make_broken()
        try:
            rep = V.verify(str(p), use_cache=False)
            self.assertEqual(V.worst_risk(rep), "critical")   # 假密钥是 critical
        finally:
            fixture.cleanup(p)

    def test_worst_risk_none_when_clean(self):
        p = fixture.make_clean()
        try:
            rep = V.verify(str(p), use_cache=False)
            self.assertIn(V.worst_risk(rep), (None, "low"))
        finally:
            fixture.cleanup(p)


class TestDeployBase(unittest.TestCase):
    def test_detect_base_from_absolute_links(self):
        import tempfile
        d = Path(tempfile.mkdtemp(prefix="vh-base-"))
        try:
            (d / "index.html").write_text(
                '<html lang="zh"><head><title>t</title></head><body>'
                '<link href="/mysite/a.css"><a href="/mysite/x.html">x</a>'
                '<a href="/mysite/y.html">y</a><img src="/mysite/z.png" alt=""></body></html>',
                encoding="utf-8")
            htmls = [d / "index.html"]
            self.assertEqual(V._detect_base(htmls), "/mysite")
        finally:
            fixture.cleanup(d)

    def test_no_base_when_relative(self):
        import tempfile
        d = Path(tempfile.mkdtemp(prefix="vh-nobase-"))
        try:
            (d / "index.html").write_text(
                '<html lang="zh"><body><a href="a.html">a</a></body></html>', encoding="utf-8")
            self.assertEqual(V._detect_base([d / "index.html"]), "")
        finally:
            fixture.cleanup(d)


if __name__ == "__main__":
    unittest.main()
