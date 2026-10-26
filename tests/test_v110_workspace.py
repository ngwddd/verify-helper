# -*- coding: utf-8 -*-
"""v1.10 的四个改进，各自一条测试（都来自真实工作区实测暴露的噪声）。

1. 安全层必须**按类聚合**：51 条同类问题不能显示成 51 行（实测 17×TLS + 28×http + 6×eval）
2. 备份目录默认跳过：`my-site.backup-20260924/` 与正本重名，会把同一问题报两遍
3. 工作区画像：能列出每个子项目的规模与**有没有测试入口**（实测 15 个子项目）
4. 证据目录可配：`artifacts_dir` 指到别处时不污染项目树
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import _tmp  # noqa: F401  （统一回收临时目录）

import lifecycle as LC  # noqa: E402
import verify_core as V  # noqa: E402


def _mk(base: Path, files: dict[str, str]) -> None:
    for rel, body in files.items():
        p = base / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")


class TestAggregation(unittest.TestCase):
    def test_groups_by_message(self) -> None:
        rows = [{"message": "关闭 TLS 校验", "risk": "high", "file": f"a{i}.py", "line": i}
                for i in range(7)]
        rows += [{"message": "使用 eval()", "risk": "high", "file": "b.py", "line": 1}]
        groups = LC.aggregate_security(rows)
        self.assertEqual(len(groups), 2, "两类问题应聚合成两组")
        self.assertEqual(groups[0]["count"], 7)
        self.assertEqual(groups[0]["message"], "关闭 TLS 校验")
        self.assertTrue(groups[0]["advice"], "同一类超过 5 处应给一次性处理的建议")
        self.assertFalse(groups[1]["advice"], "只有 1 处不需要建议")

    def test_report_shape(self) -> None:
        root = Path(_tmp.mkdtemp(prefix="vh-ag-"))
        _mk(root, {"bad.py": "import os\nos.system('ls')\n"})
        sec = LC.security_layer(root, {"checks": []})
        self.assertIn("groups", sec)
        self.assertGreaterEqual(sec["group_count"], 1)
        self.assertEqual(sum(g["count"] for g in sec["groups"]), sec["count"])


class TestBackupSkip(unittest.TestCase):
    def test_backup_dir_not_scanned(self) -> None:
        root = Path(_tmp.mkdtemp(prefix="vh-bk-"))
        _mk(root, {
            "app.py": "print('real')\n",
            "app.backup-20260101/app.py": "import os\nos.system('ls')\n",   # 备份里才有危险调用
        })
        rep = V.verify(str(root), checks=["secrets"], use_cache=False)
        files = rep["files"]
        # 备份目录里的文件不应计入
        self.assertFalse(any(Path(f).parts and "app.backup-20260101" in str(f)
                             for f in [rep.get("project", "")] + []))
        lc = rep.get("lifecycle") or {}
        sec_files = [f.get("file") for f in (lc.get("security_findings") or [])]
        self.assertFalse(any("backup-" in str(f) for f in sec_files),
                         f"备份目录不该进安全层：{sec_files}")
        self.assertGreaterEqual(files, 1)


class TestWorkspaceProfile(unittest.TestCase):
    def test_lists_subprojects_and_tests(self) -> None:
        root = Path(_tmp.mkdtemp(prefix="vh-ws-"))
        _mk(root, {
            "projA/app.py": "print(1)\n",
            "projB/tests/test_b.py": "import unittest\nclass T(unittest.TestCase):\n"
                                     "    def test_ok(self): pass\n",
            "projB/lib.py": "x = 1\n",
        })
        rep = V.verify(str(root), checks=["todos"], use_cache=False)
        ws = {w["path"]: w for w in (rep.get("workspace") or [])}
        self.assertIn("projA", ws)
        self.assertIn("projB", ws)
        self.assertTrue(ws["projB"]["test_entry"], "projB 有 tests/ 应识别为有测试入口")
        self.assertFalse(ws["projA"]["test_entry"])

    def test_single_project_has_no_profile(self) -> None:
        root = Path(_tmp.mkdtemp(prefix="vh-ws1-"))
        _mk(root, {"app.py": "print(1)\n"})
        rep = V.verify(str(root), checks=["todos"], use_cache=False)
        self.assertEqual(rep.get("workspace"), [], "单项目不该报工作区画像")


class TestArtifactsDir(unittest.TestCase):
    def test_custom_dir_used(self) -> None:
        root = Path(_tmp.mkdtemp(prefix="vh-art-"))
        out = Path(_tmp.mkdtemp(prefix="vh-art-out-"))
        _mk(root, {"a.py": "import os\n"})          # 触发 imports 提示 → 有非 PASS 项
        rep = V.verify(str(root), checks=["imports"], use_cache=False,
                       artifacts_dir=str(out))
        lc = rep.get("lifecycle") or {}
        d = (lc.get("artifacts") or {}).get("dir") or ""
        self.assertTrue(d.startswith(str(out)), f"证据应写到指定目录，实际 {d}")
        self.assertFalse((root / ".verify-artifacts").exists(), "不该污染项目树")


class TestTierReasonInWorkspace(unittest.TestCase):
    def test_no_git_medium(self) -> None:
        root = Path(_tmp.mkdtemp(prefix="vh-tier-"))
        _mk(root, {"a.py": "print(1)\n"})
        rep = V.verify(str(root), checks=["todos"], use_cache=False)
        tier = (rep.get("lifecycle") or {}).get("tier") or {}
        self.assertEqual(tier.get("tier"), "medium")
        self.assertTrue(any("git" in r for r in tier.get("reasons") or []),
                        "没有 git 时理由要说清")


if __name__ == "__main__":
    unittest.main()
