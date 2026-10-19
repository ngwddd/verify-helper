# -*- coding: utf-8 -*-
"""回归集：用真实世界的「形状」锁住行为。

每个用例都对应一次真实踩坑：
  ① 工作区（草稿 + 备份 + 别人的资料）—— 别再假装它是一个项目
  ② 部署在子路径下的站点 —— 别再误报 /repo/x.css 404
  ③ 子项目自己的 .verifyignore —— 从父目录扫时也必须生效
  ④ 散落的 *.test.js —— 别再报「没有测试入口」
  ⑤ 别人的绝对路径 —— 别再算成你的泄漏
  ⑥ 幂等 —— 跑两次结果必须一样

改任何检查后先跑这个文件；它红就说明你改坏了既有行为。
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


def by_id(rep: dict) -> dict:
    return {c["id"]: c for c in rep["checks"]}


def mkproj(files: dict[str, str], prefix: str = "vh-reg-") -> Path:
    d = Path(tempfile.mkdtemp(prefix=prefix))
    for rel, content in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            p.write_bytes(content)
        else:
            p.write_text(content, encoding="utf-8")
    return d


class TestWorkspaceShape(unittest.TestCase):
    """① 工作区：三个子项目 + 一个草稿目录。"""

    @classmethod
    def setUpClass(cls):
        cls.root = mkproj({
            "proj-a/package.json": '{"name":"a"}',
            "proj-a/index.html": '<html lang="zh"><head><title>a</title></head><body><h1>a</h1></body></html>',
            "proj-b/pyproject.toml": '[project]\nname="b"\n',
            "proj-c/setup.py": "from setuptools import setup\nsetup()\n",
            "_sp/draft.py": "def broken(:\n    pass\n",          # 草稿里的语法错
        })
        cls.rep = V.verify(str(cls.root), use_cache=False)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root, ignore_errors=True)

    def test_workspace_is_flagged(self):
        self.assertTrue(any("工作区" in n for n in self.rep["notes"]), self.rep["notes"])

    def test_draft_syntax_error_is_reported(self):
        c = by_id(self.rep)["syntax"]
        self.assertEqual(c["state"], "FAIL")
        self.assertTrue(any("draft.py" in f["file"] for f in c["findings"]))


class TestSiteWithPrefix(unittest.TestCase):
    """② 站点部署在 /repo/ 下，页面里写根绝对路径。"""

    @classmethod
    def setUpClass(cls):
        cls.root = mkproj({
            "index.html": (
                '<!doctype html><html lang="zh"><head><title>t</title>'
                '<link href="/mysite/a.css"></head><body><h1>hi</h1>'
                '<a href="/mysite/x.html">x</a><a href="/mysite/y.html">y</a>'
                '<img src="/mysite/z.png" alt=""></body></html>'),
            "404.html": (
                '<html lang="zh"><head><title>404</title></head><body><h1>找不到</h1>'
                '<a href="/mysite/index.html">回首页</a></body></html>'),
        })
        cls.rep = V.verify(str(cls.root), checks=["links", "runtime-web"], use_cache=False)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root, ignore_errors=True)

    def test_links_pass_with_empty_findings(self):
        c = by_id(self.rep)["links"]
        self.assertEqual(c["state"], "PASS", c["detail"])
        self.assertEqual(c["findings"], [], "PASS 的检查不该带 findings")

    def test_absolute_paths_go_to_hints(self):
        self.assertTrue(by_id(self.rep)["links"]["hints"])

    def test_runtime_serves_under_prefix(self):
        c = by_id(self.rep)["runtime-web"]
        self.assertEqual(c["state"], "PASS", c["detail"])
        self.assertIn("/mysite", c["detail"])


class TestSubprojectIgnore(unittest.TestCase):
    """③ 子项目自己的 .verifyignore，从父目录扫时也要生效。"""

    @classmethod
    def setUpClass(cls):
        cls.root = mkproj({
            "site/index.html": '<html lang="zh"><head><title>s</title></head><body><h1>s</h1></body></html>',
            "site/tpl/snippet.html": '<a href="not-here.html">模板链接</a>',
            "site/.verifyignore": "tpl/*.html\n",
        })
        cls.rep = V.verify(str(cls.root), checks=["links"], use_cache=False)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root, ignore_errors=True)

    def test_ignored_template_does_not_fail(self):
        c = by_id(self.rep)["links"]
        self.assertEqual(c["state"], "PASS", f"{c['detail']} {c['findings']}")
        self.assertTrue(any("verifyignore" in n for n in self.rep["notes"]), self.rep["notes"])


class TestDirectoryIgnore(unittest.TestCase):
    """③b 目录级 ignore：`_sp/` 要整棵子树都不扫。

    这条曾经挂过：之前的实现只过滤文件、不过滤目录，
    于是根目录写 `_sp/` 完全没用，草稿里的语法错照样让整个工作区 FAIL。
    """

    def test_directory_pattern_prunes_subtree(self):
        d = mkproj({
            "good.py": "x = 1\n",
            "_sp/broken.py": "def f(:\n",
            ".verifyignore": "_sp/\n",
        })
        try:
            rep = V.verify(str(d), checks=["syntax"], use_cache=False)
            c = by_id(rep)["syntax"]
            self.assertEqual(c["state"], "PASS", f"{c['detail']} {c['findings']}")
            self.assertEqual(rep["verdict"], "PASS")
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_trailing_slash_equivalent(self):
        for pat in ("_sp", "_sp/"):
            d = mkproj({"ok.py": "x = 1\n",
                        "_sp/broken.py": "def f(:\n",
                        ".verifyignore": pat + "\n"})
            try:
                c = by_id(V.verify(str(d), checks=["syntax"], use_cache=False))["syntax"]
                self.assertEqual(c["state"], "PASS", f"pattern={pat!r} {c['detail']}")
                self.assertEqual(c["findings"], [])
            finally:
                shutil.rmtree(d, ignore_errors=True)


class TestScatteredTests(unittest.TestCase):
    """④ 没有 scripts.test，但有 *.test.js —— 要能认出来。"""

    def test_detects_node_test_files(self):
        d = mkproj({
            "package.json": '{"name":"x"}',
            "a.test.js": "const test = require('node:test');\ntest('x', () => {});\n",
        })
        try:
            cmd, why, _ = V._detect_test_command(d)
            self.assertIsNotNone(cmd, why)
            self.assertIn("node", cmd[0] or "")
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_workspace_does_not_invent_entry(self):
        d = mkproj({"p1/a.test.js": "", "p2/b.test.js": ""})
        try:
            cmd, _, _ = V._detect_test_command(d)
            self.assertIsNone(cmd, "工作区根上不该凭空认出测试入口")
        finally:
            shutil.rmtree(d, ignore_errors=True)


class TestOwnVsOtherPaths(unittest.TestCase):
    """⑤ 别人的家目录不算你的泄漏；自己的必须算。"""

    def test_other_user_path_becomes_hint(self):
        d = mkproj({
            "note.md": "原作者路径 C:\\Users\\someoneelse\\course\\a.txt\n",
            "ok.js": "const a = 1;\n",
        })
        try:
            rep = V.verify(str(d), checks=["paths"], use_cache=False)
            c = by_id(rep)["paths"]
            self.assertEqual(c["findings"], [], "别人的路径不该进 findings")
            self.assertTrue(c["hints"], "应该进 hints")
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_own_home_path_still_reported(self):
        """自己的用户目录必须进 findings —— 这条曾经挂过：
        账号名和用户目录名不一致时，把自己的路径误判成了别人的。"""
        me = Path.home().name
        d = mkproj({"build.py": f'ROOT = r"C:\\Users\\{me}\\proj"\n'})
        try:
            rep = V.verify(str(d), checks=["paths"], use_cache=False)
            c = by_id(rep)["paths"]
            self.assertEqual(c["state"], "FAIL", c["detail"])
            self.assertTrue(any(me in f["message"] for f in c["findings"]))
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_doc_placeholders_are_ignored(self):
        """`C:\\Users\\<you>` 这种文档占位符，既不是泄漏也不是别人的路径。"""
        d = mkproj({"README.md": "示例：C:\\Users\\<you>\\proj 与 /Users/<you>/proj\n"})
        try:
            rep = V.verify(str(d), checks=["paths"], use_cache=False)
            c = by_id(rep)["paths"]
            self.assertEqual(c["findings"], [])
            self.assertEqual(c["hints"], [], "占位符连提示都不该有")
        finally:
            shutil.rmtree(d, ignore_errors=True)


class TestIdempotent(unittest.TestCase):
    """⑥ 同一目录跑两次，结论与各项状态必须一致。"""

    def test_same_signature(self):
        d = mkproj({
            "a.py": "def f(:\n",
            "page.html": '<html lang="zh"><head><title>t</title></head><body><h1>x</h1>'
                         '<a href="missing.html">d</a></body></html>',
        })
        try:
            r1 = V.verify(str(d), checks=["syntax", "links", "html"], use_cache=False)
            r2 = V.verify(str(d), checks=["syntax", "links", "html"], use_cache=False)
            sig = lambda r: (r["verdict"],
                             tuple(sorted((c["id"], c["state"], len(c["findings"]))
                                          for c in r["checks"])))
            self.assertEqual(sig(r1), sig(r2))
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
