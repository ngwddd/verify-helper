# -*- coding: utf-8 -*-
"""证据归档 + 临时目录清扫（2026-10-27）。

真实问题：browser 检查报「截图 12 张」，但 artifacts 里 0 张 ——
`finally: rmtree(tmp)` 把它们删了，而且 PASS 的检查根本不写证据。
结果是「0 处 JS 报错」只有一句结论，没有可视证据可复核。
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import lifecycle


def _mk_evidence(tmp: Path, n: int = 2) -> Path:
    d = tmp / "vh-evidence-test" / "browser"
    d.mkdir(parents=True)
    for i in range(n):
        (d / f"shot-{i}.png").write_bytes(b"\x89PNG\r\n\x1a\n" + bytes([i]))
    return d


class TestEvidenceArchived(unittest.TestCase):
    def test_pass_with_evidence_is_written(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            ev = _mk_evidence(t)
            report = {"project": "x", "verdict": "PASS", "checks": [
                {"id": "browser", "state": "PASS", "risk": "high",
                 "detail": "真跑 3 页，问题 0 处，截图 2 张",
                 "evidence": {"dir": str(ev)}}]}
            out = t / "artifacts"
            res = lifecycle.write_artifacts(report, t, out_dir=str(out))
            self.assertTrue(res.get("written"), res)
            runs = sorted(d for d in out.iterdir() if d.is_dir())
            self.assertEqual(len(runs), 1)
            shots = list(runs[0].glob("browser-evidence/*.png"))
            self.assertEqual(len(shots), 2, shots)
            # 总结文件也在，且提到证据
            body = (runs[0] / "browser.txt").read_text(encoding="utf-8")
            self.assertIn("## evidence", body)

    def test_plain_pass_still_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            report = {"project": "x", "verdict": "PASS", "checks": [
                {"id": "syntax", "state": "PASS", "risk": "high"}]}
            res = lifecycle.write_artifacts(report, t, out_dir=str(t / "a"))
            self.assertEqual(res.get("written"), [])

    def test_cleanup_removes_temp_dir(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            ev = _mk_evidence(t)
            report = {"checks": [{"id": "browser", "state": "PASS",
                                  "evidence": {"dir": str(ev)}}]}
            lifecycle.cleanup_evidence(report)
            self.assertFalse(ev.is_dir(), "证据临时目录该被删掉")
            self.assertFalse(ev.parent.is_dir(), "外层 vh-evidence-* 也该删掉")


class TestTempSweep(unittest.TestCase):
    def test_stale_own_prefix_removed(self) -> None:
        base = Path(tempfile.gettempdir())
        stale = base / f"vh-browser-test-{os.getpid()}"
        stale.mkdir(exist_ok=True)
        (stale / "x.png").write_bytes(b"1")
        old = time.time() - 12 * 3600
        os.utime(stale, (old, old))
        try:
            res = lifecycle.sweep_temp_dirs(max_age_hours=6)
            self.assertIn(stale.name, res["removed"])
            self.assertFalse(stale.exists())
        finally:
            if stale.exists():
                import shutil as _sh
                _sh.rmtree(stale, ignore_errors=True)

    def test_fresh_dir_kept(self) -> None:
        base = Path(tempfile.gettempdir())
        fresh = base / f"vh-browser-fresh-{os.getpid()}"
        fresh.mkdir(exist_ok=True)
        try:
            res = lifecycle.sweep_temp_dirs(max_age_hours=6)
            self.assertNotIn(fresh.name, res["removed"])
            self.assertTrue(fresh.exists())
        finally:
            import shutil as _sh
            _sh.rmtree(fresh, ignore_errors=True)

    def test_other_programs_untouched(self) -> None:
        base = Path(tempfile.gettempdir())
        other = base / f"not-ours-{os.getpid()}"
        other.mkdir(exist_ok=True)
        old = time.time() - 12 * 3600
        os.utime(other, (old, old))
        try:
            lifecycle.sweep_temp_dirs(max_age_hours=6)
            self.assertTrue(other.exists(), "别人的目录不许删")
        finally:
            import shutil as _sh
            _sh.rmtree(other, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
