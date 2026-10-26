# -*- coding: utf-8 -*-
"""v1.10.1 的四个修复，各自一条测试。

① 子项目口径统一：正文的「识别到 N 个」与画像列出的数量必须一致
   （实测 bug：正文说 10 个，画像列 15 个）
② 文档里的 http 链接不算安全问题（实测：28 条噪声里混着文档参考链接）
③ `--accept-file` 真正生效（实测：参数存在但从没被读取，静默失效）
④ 备份目录被跳过时，notes 里要说明（否则"文件少了"无从解释）
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import lifecycle as LC  # noqa: E402
import verify_core as V  # noqa: E402


def _mk(base: Path, files: dict[str, str]) -> None:
    for rel, body in files.items():
        p = base / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")


class TestConsistentSubprojectCount(unittest.TestCase):
    def test_note_matches_profile(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="vh-cnt-"))
        _mk(root, {
            "a/x.py": "print(1)\n",
            "b/y.py": "print(2)\n",
            "c/z.py": "print(3)\n",
        })
        rep = V.verify(str(root), checks=["todos"], use_cache=False)
        profile = rep.get("workspace") or []
        self.assertEqual(len(profile), 3)
        joined = " ".join(rep.get("notes") or [])
        self.assertIn("3 个", joined, f"正文数字应与画像一致（3），notes={joined[:200]}")


class TestDocHttpNotFlagged(unittest.TestCase):
    def test_doc_link_ignored_but_code_flagged(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="vh-http-"))
        _mk(root, {
            "README.md": "参考 https://example.com 与 http://example.com/doc\n",
            "fetch.py": 'URL = "http://example.com/api"\n',
        })
        sec = LC.security_layer(root, {"checks": []})
        files = [f.get("file") for f in sec["findings"]]
        self.assertIn("fetch.py", files, "代码里的明文 http 必须报")
        self.assertNotIn("README.md", files, "文档里的 http 链接不该报")


class TestAcceptFile(unittest.TestCase):
    def test_cli_accept_file_is_read(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="vh-af-"))
        _mk(root, {"a.py": "import os\n"})          # imports 会给出低风险提示
        first = V.verify(str(root), checks=["imports"], use_cache=False, artifacts=False)
        un = ((first.get("lifecycle") or {}).get("accept") or {}).get("unresolved") or []
        self.assertTrue(un, "应当有一条未回应")
        fid = un[0]["id"]

        af = Path(tempfile.mkdtemp(prefix="vh-afj-")) / "accept.json"
        af.write_text(json.dumps({"accepted": [{"id": fid, "reason": "临时脚本，已知"}]},
                                 ensure_ascii=False), encoding="utf-8")

        rc = V.main_cli([str(root), "--checks", "imports", "--accept-file", str(af),
                         "--no-artifacts", "--stage", "pr"])
        self.assertIn(rc, (0, 1))
        # 落盘文件里应当有这条接受
        saved = json.loads((root / ".verify-accept.json").read_text(encoding="utf-8"))
        self.assertTrue(any(e.get("id") == fid for e in saved.get("accepted") or []),
                        "accept-file 里的条目应当被合并进 .verify-accept.json")


class TestBackupNote(unittest.TestCase):
    def test_note_when_backup_skipped(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="vh-note-"))
        _mk(root, {
            "app.py": "print(1)\n",
            "old.backup-20260101/app.py": "print(2)\n",
        })
        rep = V.verify(str(root), checks=["todos"], use_cache=False)
        joined = " ".join(rep.get("notes") or [])
        self.assertIn("备份目录", joined, f"应说明跳过了备份目录，notes={joined[:200]}")


if __name__ == "__main__":
    unittest.main()
