# -*- coding: utf-8 -*-
"""测试用的假项目：每个文件埋一个已知缺陷，且互相独立。

原则：**测试不依赖本机任何真实项目**。所有 fixture 都在临时目录里现造，
跑完即删 —— 别人 clone 下来就能 `python -m unittest discover -s tests`。
"""
from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

# 假密钥拆开拼接：否则工具自己的源码会被自己的 secrets 检查命中
FAKE_KEY = "sk-" + "abcdefghijklmnopqrstuvwxyz123456"


def make_broken(root: Path | None = None) -> Path:
    """8 个已知缺陷：3 语法、2 链接、1 结构、1 密钥、1 编码、1 失败测试。"""
    root = Path(root or tempfile.mkdtemp(prefix="vh-broken-"))
    if root.exists():
        shutil.rmtree(root)
    (root / "tests").mkdir(parents=True)

    (root / "bad.py").write_text("def broken(:\n    return 42\n", encoding="utf-8")
    (root / "bad.mjs").write_text("const x = {;\nexport default x;\n", encoding="utf-8")
    (root / "config.json").write_text('{\n  "a": 1,\n}\n', encoding="utf-8")

    (root / "page.html").write_text(
        '<!doctype html>\n<html lang="zh-CN"><head><title>fixture</title></head>\n<body>\n'
        '<h1 id="top">标题</h1>\n<p id="top">重复 id</p>\n'
        '<a href="missing.html">死链</a>\n<a href="#nowhere">坏锚点</a>\n'
        '<a href="other.html#nope">跨页坏锚点</a>\n</body></html>\n', encoding="utf-8")
    (root / "other.html").write_text(
        '<!doctype html><html lang="zh-CN"><body><p id="here">ok</p></body></html>\n',
        encoding="utf-8")

    (root / "leak.py").write_text(
        f'API_KEY = "{FAKE_KEY}"\nDATA = r"C:\\Users\\someone\\secret"\n', encoding="utf-8")

    (root / "tests" / "test_math.py").write_text(
        "import unittest\n\n\nclass T(unittest.TestCase):\n"
        "    def test_one(self):\n        self.assertEqual(1 + 1, 3)\n", encoding="utf-8")

    (root / "gbk_note.txt").write_bytes("这一段是 GBK 编码".encode("gbk"))
    return root


def make_clean(root: Path | None = None) -> Path:
    """一个干净的小项目：应当 PASS。"""
    root = Path(root or tempfile.mkdtemp(prefix="vh-clean-"))
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True, exist_ok=True)
    (root / "ok.py").write_text(
        "def add(a, b):\n    return a + b\n", encoding="utf-8")
    (root / "data.json").write_text('{"a": 1}\n', encoding="utf-8")
    (root / "index.html").write_text(
        '<!doctype html>\n<html lang="zh-CN"><head><title>ok</title></head>\n'
        '<body><h1>hi</h1><p><a href="ok.py">源码</a></p></body></html>\n', encoding="utf-8")
    return root


def make_with_ignore(root: Path | None = None) -> Path:
    """带 .verifyignore：把有死链的模板排除掉后应当 PASS。"""
    root = make_clean(root)
    (root / "tpl").mkdir(exist_ok=True)
    (root / "tpl" / "snippet.html").write_text(
        '<a href="not-here.html">模板里的相对链接</a>\n', encoding="utf-8")
    (root / ".verifyignore").write_text("tpl/*.html\n", encoding="utf-8")
    return root


def make_with_rules(root: Path | None = None) -> Path:
    """带 verify.toml 自定义规则。"""
    root = make_clean(root)
    (root / "app.js").write_text("console.log('debug');\n", encoding="utf-8")
    (root / "verify.toml").write_text(
        '[[rules]]\n'
        'id = "no-console-log"\n'
        "pattern = 'console\\.log\\('\n"
        'paths = ["**/*.js"]\n'
        'message = "生产代码里不要留 console.log"\n'
        'risk = "high"\n', encoding="utf-8")
    return root


def cleanup(*paths: Path) -> None:
    for p in paths:
        shutil.rmtree(p, ignore_errors=True)
