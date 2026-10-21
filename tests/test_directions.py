# -*- coding: utf-8 -*-
"""方向卡（v6）：填卡、四道闸、渲染、JSON。"""
from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import directions as DIR      # noqa: E402
import verify_core as V       # noqa: E402


class TestCardShape(unittest.TestCase):
    CASES = [
        ("links", {"file": "a.html", "line": 5, "message": "死链：x.html"}),
        ("syntax", {"file": "a.py", "line": 3, "message": "invalid syntax"}),
        ("html", {"file": "a.html", "line": 9, "message": "未闭合 <div>"}),
        ("secrets", {"file": "a.py", "line": 2, "message": "疑似 AWS key"}),
        ("encoding", {"file": "a.txt", "line": 0, "message": "GBK 字节"}),
        ("bom", {"file": "a.css", "line": 0, "message": "开头有 BOM"}),
        ("paths", {"file": "a.py", "line": 4, "message": "C:\\Users\\x\\y"}),
        ("imports", {"file": "a.py", "line": 7, "message": "未使用：json"}),
        ("a11y", {"file": "a.html", "line": 6, "message": "<img> 缺 alt"}),
        ("a11y", {"file": "a.html", "line": 3, "message": "一个页面有 2 个 h1"}),
        ("tests", {"file": "tests/test_a.py", "line": 0, "message": "1 failed"}),
        ("runtime-web", {"file": "a.html", "line": 0, "message": "HTTP 404"}),
        ("browser", {"file": "a.html", "line": 0, "message": "console error"}),
        ("custom", {"file": "a.py", "line": 11, "message": "命中规则 no-print"}),
        ("mutation", {"file": "a.py", "line": 20, "message": "第 20 行改坏仍通过"}),
    ]

    def test_every_check_has_a_card(self):
        for cid, f in self.CASES:
            with self.subTest(check=cid, finding=f["message"]):
                card = DIR.build(cid, f)
                self.assertIsNotNone(card, f"{cid} 应该能生成方向卡")
                self.assertIn(card["class"], ("A", "B", "C"))
                self.assertIn(card["scale"], ("low", "medium", "high"))
                self.assertTrue(card["root_cause"])
                self.assertTrue(card["action"])
                self.assertTrue(card["must_not_touch"])
                # 验证方式必须同时给 MCP 调用与命令行两种
                self.assertIn("verify_start(", card["verify"])
                self.assertIn(f'checks=["{cid}"]', card["verify"])
                self.assertIn(f"--checks {cid}", card["verify"])

    def test_cards_cite_the_location(self):
        """除了 interaction（file 是流程名），每张卡都要写出 文件:行。"""
        for cid, f in self.CASES:
            if cid == "interaction":
                continue
            card = DIR.build(cid, f)
            if card is None:
                continue
            if f.get("line"):
                with self.subTest(check=cid):
                    self.assertIn(f"{f['file']}:{f['line']}", card["root_cause"])

    def test_interaction_uses_step_number(self):
        card = DIR.build("interaction", {"file": "流程A", "line": 3, "message": "Timeout"})
        self.assertIsNotNone(card)
        self.assertIn("第 3 步", card["root_cause"])


class TestGate(unittest.TestCase):
    def test_no_file_no_card(self):
        self.assertIsNone(DIR.build("links", {"file": "", "line": 5, "message": "死链：x"}))

    def test_statistical_checks_have_no_direction(self):
        self.assertIsNone(DIR.build("todos", {"file": "a.py", "line": 1, "message": "x"}))
        self.assertIsNone(DIR.build("git", {"file": "a.py", "line": 1, "message": "x"}))

    def test_unknown_check(self):
        self.assertIsNone(DIR.build("no-such-check", {"file": "a.py"}))

    def test_empty_finding_does_not_crash(self):
        for cid in DIR._BUILDERS:
            with self.subTest(check=cid):
                self.assertIsNone(DIR.build(cid, {}))

    def test_forbidden_action_is_rejected(self):
        bad = DIR._card(
            {"file": "a.html", "line": 5}, "A",
            "某种原因导致这里不对", "重写整个文件比较快",
            ["不要动别处"], "links")
        self.assertFalse(DIR._gate(bad, {"file": "a.html", "line": 5}))

    def test_missing_boundary_is_rejected(self):
        bad = DIR._card(
            {"file": "a.html", "line": 5}, "A",
            "某种原因导致这里不对", "改这一行的引用",
            [], "links")
        self.assertFalse(DIR._gate(bad, {"file": "a.html", "line": 5}))

    def test_bad_verify_command_is_rejected(self):
        bad = DIR._card(
            {"file": "a.html", "line": 5}, "A",
            "某种原因导致这里不对", "改这一行的引用", ["x"], "links")
        bad["verify"] = "随便看看"
        self.assertFalse(DIR._gate(bad, {"file": "a.html", "line": 5}))


class TestIntegration(unittest.TestCase):
    def _fixture(self):
        d = Path(tempfile.mkdtemp(prefix="vh-dir-"))
        (d / "index.html").write_text(
            '<!doctype html>\n<html lang="zh"><head><title>t</title></head>\n'
            '<body><h1>标题</h1><a href="nope.html">死链</a></body></html>\n',
            encoding="utf-8")
        return d

    def test_findings_get_direction_in_json(self):
        d = self._fixture()
        try:
            rep = V.verify(str(d), checks=["links"], use_cache=False)
            c = {x["id"]: x for x in rep["checks"]}["links"]
            self.assertEqual(c["state"], "FAIL")
            self.assertTrue(c["findings"])
            f = c["findings"][0]
            self.assertIn("direction", f)
            self.assertIn("nope.html", f["direction"]["root_cause"])
            self.assertIn("direction_seconds", rep["cache"])
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_render_shows_card_and_hides_generic_advice(self):
        d = self._fixture()
        try:
            text = V.render(V.verify(str(d), checks=["links"], use_cache=False))
            self.assertIn("方向：", text)
            self.assertIn("别动：", text)
            self.assertIn('验证：verify_start(checks=["links"]) 应 PASS', text)
            # 有方向卡时，通用的那句「怎么改」不该再出现
            self.assertNotIn("→ 怎么改：改链接指向真实文件", text)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_pass_has_no_extra_field(self):
        d = Path(tempfile.mkdtemp(prefix="vh-dir-ok-"))
        try:
            (d / "a.py").write_text("x = 1\n", encoding="utf-8")
            rep = V.verify(str(d), checks=["syntax"], use_cache=False)
            c = {x["id"]: x for x in rep["checks"]}["syntax"]
            self.assertEqual(c["state"], "PASS")
            self.assertFalse(c["findings"])
            self.assertEqual(rep["cache"]["directed"], 0)
        finally:
            shutil.rmtree(d, ignore_errors=True)


class TestWrap(unittest.TestCase):
    def test_does_not_split_ascii_words(self):
        lines = V._wrap("前缀文字" * 8 + " html 补 lang", 20)
        joined = "\n".join(lines)
        self.assertNotIn("h\ntml", joined)

    def test_short_text_single_line(self):
        self.assertEqual(V._wrap("短"), ["短"])

    def test_empty(self):
        self.assertEqual(V._wrap(""), [""])


if __name__ == "__main__":
    unittest.main()
