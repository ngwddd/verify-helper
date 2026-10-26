# -*- coding: utf-8 -*-
"""v1.9 lifecycle 的单测：守十个能力，不碰网络、不跑浏览器。

每条测试都对应一个具体承诺，而不是"跑一下不炸"：
  · 分层：stage 归一化与每层检查集
  · tier：由**变更**决定；敏感路径直接 high；没有 git 时保守 medium
  · 接受：必须写理由；凭据类不接受
  · 噪声/收敛：fixed/new/repeat 与"三轮不变就收敛"
  · 回归集：regression.toml 能解析，缺检查会报
  · 安全层：只有 critical 阻塞；自己的正则文件不被自己扫
  · 证据：失败项落盘
  · 闸门：安全层 > 失败 > 未回应 > 未知
  · REVIEW.md：skip / no-style / require-evidence / max-nits
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import lifecycle as LC  # noqa: E402


def _proj() -> Path:
    d = Path(tempfile.mkdtemp())
    (d / "src").mkdir()
    (d / "src" / "app.py").write_text("print('hi')\n", encoding="utf-8")
    return d


def _report(checks: list[dict] | None = None) -> dict:
    return {"project": "x", "verdict": "PASS", "checks": checks or [],
            "notes": [], "files": 1, "by_ext": {}, "git": {}, "cache": {}}


class TestStages(unittest.TestCase):
    def test_normalize(self) -> None:
        self.assertEqual(LC.normalize_stage(None), "pr")
        self.assertEqual(LC.normalize_stage("pre-commit"), "precommit")
        self.assertEqual(LC.normalize_stage("post"), "postdeploy")
        self.assertEqual(LC.normalize_stage("乱写"), "pr")

    def test_each_stage_has_checks(self) -> None:
        self.assertIn("secrets", LC.stage_checks("precommit"))
        self.assertIsNone(LC.stage_checks("pr"))          # None = 默认全部
        self.assertIn("browser", LC.stage_checks("postdeploy"))


class TestTier(unittest.TestCase):
    def test_sensitive_path_forces_high(self) -> None:
        facts = {"no_git": False, "files": 1, "added": 1, "removed": 0,
                 "paths": ["auth/login.py"], "sensitive": ["auth/login.py"]}
        t = LC.tier_of(facts)
        self.assertEqual(t["tier"], "high")
        self.assertEqual(t["human_approvals"], 2)

    def test_small_change_is_low(self) -> None:
        facts = {"no_git": False, "files": 1, "added": 3, "removed": 1,
                 "paths": ["src/app.py"], "sensitive": []}
        t = LC.tier_of(facts)
        self.assertEqual(t["tier"], "low")
        self.assertEqual(t["human_approvals"], 0)

    def test_no_git_is_medium(self) -> None:
        t = LC.tier_of({"no_git": True})
        self.assertEqual(t["tier"], "medium")
        self.assertEqual(t["human_approvals"], 1)

    def test_forced(self) -> None:
        self.assertEqual(LC.tier_of({"no_git": True}, "low")["tier"], "low")


class TestFindingId(unittest.TestCase):
    def test_stable(self) -> None:
        f = {"file": "a.py", "line": 12, "message": "boom"}
        self.assertEqual(LC.finding_id("syntax", f), LC.finding_id("syntax", dict(f)))

    def test_differs_by_file(self) -> None:
        a = LC.finding_id("syntax", {"file": "a.py", "line": 1, "message": "x"})
        b = LC.finding_id("syntax", {"file": "b.py", "line": 1, "message": "x"})
        self.assertNotEqual(a, b)


class TestAccepts(unittest.TestCase):
    def test_requires_reason(self) -> None:
        rep = _report([{"id": "todos", "state": "FAIL", "risk": "low", "applicable": True,
                        "findings": [{"file": "a.py", "line": 1, "message": "TODO"}]}])
        out = LC.apply_accepts(rep, {"accepted": [{"id": "todos:a.py:1:xx", "reason": ""}]})
        # 没有理由 → 不算接受
        self.assertEqual(out["accepted"], 0)
        self.assertEqual(out["unresolved_count"], 1)

    def test_accept_marks_finding(self) -> None:
        rep = _report([{"id": "todos", "state": "FAIL", "risk": "low", "applicable": True,
                        "findings": [{"file": "a.py", "line": 1, "message": "TODO"}]}])
        fid = LC.finding_id("todos", rep["checks"][0]["findings"][0])
        out = LC.apply_accepts(rep, {"accepted": [{"id": fid, "reason": "排期到下周"}]})
        self.assertEqual(out["accepted"], 1)
        self.assertEqual(rep["checks"][0]["findings"][0]["accepted"]["reason"], "排期到下周")

    def test_critical_not_acceptable(self) -> None:
        rep = _report([{"id": "secrets", "state": "FAIL", "risk": "critical", "applicable": True,
                        "findings": [{"file": "a.py", "line": 2, "message": "key"}]}])
        fid = LC.finding_id("secrets", rep["checks"][0]["findings"][0])
        out = LC.apply_accepts(rep, {"accepted": [{"id": fid, "reason": "测试用"}]})
        self.assertEqual(out["accepted"], 0, "凭据类不能接受")

    def test_unknown_is_not_unresolved(self) -> None:
        """UNKNOWN 是「缺 oracle」，不是「人没回应」—— 单独计数，不进 unresolved。"""
        rep = _report([{"id": "tests", "state": "UNKNOWN", "risk": "high",
                        "applicable": True, "detail": "没有测试入口", "findings": []}])
        out = LC.apply_accepts(rep, {"accepted": []})
        self.assertEqual(out["unresolved_count"], 0)
        self.assertEqual(out["unknown_checks"], ["tests"])


class TestNoiseConvergence(unittest.TestCase):
    def test_noise_rounds(self) -> None:
        root = _proj()
        rep = _report([{"id": "todos", "state": "FAIL", "risk": "low", "applicable": True,
                        "findings": [{"file": "a.py", "line": 1, "message": "TODO"}]}])
        n1 = LC.noise_track(root, rep)
        self.assertEqual(n1["total"], 1)
        n2 = LC.noise_track(root, rep)
        self.assertEqual(n2["repeat"], 1)
        self.assertEqual(n2["new"], 0)

    def test_convergence_after_three_equal_rounds(self) -> None:
        root = _proj()
        rep = _report([{"id": "todos", "state": "FAIL", "risk": "low", "applicable": True,
                        "findings": [{"file": "a.py", "line": 1, "message": "TODO"}]}])
        for _ in range(3):
            LC.noise_track(root, rep)
        c = LC.convergence(root, rep)
        self.assertTrue(c["converged"])
        self.assertIn("收敛", c["advice"])


class TestRegression(unittest.TestCase):
    def test_parse_and_missing_check(self) -> None:
        root = _proj()
        (root / "regression.toml").write_text(
            '# 事故回归集\n[[case]]\npath = "src/app.py"\ncheck = "syntax"\n'
            'why = "曾经少个括号，整站白屏"\n\n[[case]]\npath = "x.py"\ncheck = "不存在"\n',
            encoding="utf-8")
        rules = LC.regression_rules(root)
        self.assertEqual(len(rules["cases"]), 2)
        rep = _report([{"id": "syntax", "state": "PASS", "risk": "high", "applicable": True,
                        "findings": []}])
        out = LC.apply_regression(rep, rules, root)
        self.assertEqual(out["cases"], 2)
        self.assertEqual(len(out["missing"]), 1, "声明了不存在的检查应报 missing")


class TestSecurity(unittest.TestCase):
    def test_skips_self_and_blocks_only_critical(self) -> None:
        root = _proj()
        (root / "bad.py").write_text("import os\nos.system('ls')\n", encoding="utf-8")
        (root / "lifecycle.py").write_text("eval('x')\n", encoding="utf-8")   # 自身应被跳过
        rep = _report([])
        sec = LC.security_layer(root, rep)
        files = {f["file"] for f in sec["findings"]}
        self.assertIn("bad.py", files)
        self.assertNotIn("lifecycle.py", files, "定义正则的文件不该被自己扫")
        self.assertFalse(sec["blocked"], "没有凭据就不该阻塞（high 只需回应）")

    def test_secret_failure_blocks(self) -> None:
        root = _proj()
        rep = _report([{"id": "secrets", "state": "FAIL", "risk": "critical", "applicable": True,
                        "findings": [{"file": "a.py", "line": 3, "message": "key"}]}])
        sec = LC.security_layer(root, rep)
        self.assertTrue(sec["blocked"])


class TestArtifacts(unittest.TestCase):
    def test_writes_failed_checks(self) -> None:
        root = _proj()
        rep = _report([{"id": "tests", "state": "FAIL", "risk": "high", "applicable": True,
                        "command": "pytest", "exit_code": 1, "output": "1 failed",
                        "findings": [{"file": "a.py", "line": 1, "message": "x"}]}])
        out = LC.write_artifacts(rep, root)
        self.assertTrue(out["written"], "失败项应落盘")
        self.assertTrue(Path(out["written"][0]).is_file())

    def test_pass_only_writes_nothing(self) -> None:
        root = _proj()
        out = LC.write_artifacts(_report([{"id": "syntax", "state": "PASS"}]), root)
        self.assertEqual(out["written"], [])


class TestGate(unittest.TestCase):
    def test_security_blocks_first(self) -> None:
        rep = _report([{"id": "syntax", "state": "PASS", "risk": "high", "applicable": True}])
        g = LC.gate(rep, "pr", {"tier": "low"}, [], {"blocked": True, "count": 1},
                    {"converged": False}, False)
        self.assertEqual(g["verdict"], "FAIL")
        self.assertIn("安全层", g["blocked_by"][0]["reason"])

    def test_blocking_fail(self) -> None:
        rep = _report([{"id": "syntax", "state": "FAIL", "risk": "high", "applicable": True}])
        g = LC.gate(rep, "pr", {"tier": "low"}, [], {"blocked": False},
                    {"converged": False}, False)
        self.assertEqual(g["verdict"], "FAIL")

    def test_unresolved_blocks(self) -> None:
        rep = _report([{"id": "syntax", "state": "PASS", "risk": "high", "applicable": True}])
        g = LC.gate(rep, "pr", {"tier": "low"}, [{"id": "x", "risk": "high"}],
                    {"blocked": False}, {"converged": False}, False)
        self.assertEqual(g["verdict"], "FAIL")

    def test_low_risk_unresolved_does_not_block(self) -> None:
        """低风险提示不该卡住 PR —— 否则低噪声变成高噪声，人就无视它了。"""
        rep = _report([{"id": "syntax", "state": "PASS", "risk": "high", "applicable": True}])
        g = LC.gate(rep, "pr", {"tier": "low"}, [{"id": "x", "risk": "low"}],
                    {"blocked": False}, {"converged": False}, False)
        self.assertEqual(g["verdict"], "PASS")
        self.assertEqual(g["unresolved_low"], 1)

    def test_precommit_allows_unresolved(self) -> None:
        rep = _report([{"id": "syntax", "state": "PASS", "risk": "high", "applicable": True}])
        g = LC.gate(rep, "precommit", {"tier": "low"}, [{"id": "x"}], {"blocked": False},
                    {"converged": False}, True)
        self.assertEqual(g["verdict"], "PASS", "提交前不该因为未回应而卡住")

    def test_all_unknown_stays_unknown(self) -> None:
        rep = _report([{"id": "tests", "state": "UNKNOWN", "risk": "high", "applicable": True}])
        g = LC.gate(rep, "pr", {"tier": "low"}, [], {"blocked": False},
                    {"converged": False}, False)
        self.assertEqual(g["verdict"], "UNKNOWN", "没有可判定项时必须是 UNKNOWN，不能谎报 PASS")

    def test_unknown_only_is_unknown(self) -> None:
        """缺 oracle → UNKNOWN（挡住合并，但不说成"已知的坏"）。"""
        rep = _report([{"id": "tests", "state": "UNKNOWN", "risk": "high", "applicable": True}])
        g = LC.gate(rep, "pr", {"tier": "low"}, [], {"blocked": False},
                    {"converged": False}, False)
        self.assertEqual(g["verdict"], "UNKNOWN")
        self.assertIn("缺 oracle", g["blocked_by"][0]["reason"])


class TestReviewMd(unittest.TestCase):
    def test_parse_and_filter(self) -> None:
        root = _proj()
        (root / "REVIEW.md").write_text(
            "skip: drafts/**, legacy/**\nno-style: true\nrequire-evidence: true\n"
            "max-nits: 2\nfail-means: 文档说谎\n", encoding="utf-8")
        rv = LC.load_review_md(root)
        self.assertTrue(rv["found"])
        self.assertIn("drafts/**", rv["rules"]["skip"])
        self.assertTrue(rv["rules"]["no_style"])
        self.assertEqual(rv["rules"]["max_nits"], 2)
        self.assertIn("文档说谎", rv["rules"]["fail_means"])

        # skip 路径 + 缺证据：用 custom（medium，不受 no-style 影响）
        rep = _report([{"id": "custom", "state": "FAIL", "risk": "medium", "applicable": True,
                        "findings": [
                            {"file": "drafts/a.md", "line": 1, "message": "x"},
                            {"file": "src/b.py", "line": 2, "message": "y"},
                            {"file": "src/c.py", "message": "没有行号"},
                        ]}])
        out = LC.apply_review(rep, rv)
        self.assertEqual(out["dropped"], 1, "skip 路径应被丢掉")
        self.assertEqual(out["no_evidence"], 1, "没有 file+line 的应被丢掉")

        # no-style：只关风格类检查（a11y），不影响 todos 这类诊断
        rep2 = _report([
            {"id": "a11y", "state": "FAIL", "risk": "low", "applicable": True,
             "findings": [{"file": "src/i.html", "line": 3, "message": "img 缺 alt"}]},
            {"id": "todos", "state": "FAIL", "risk": "low", "applicable": True,
             "findings": [{"file": "src/j.py", "line": 4, "message": "TODO"}]},
        ])
        out2 = LC.apply_review(rep2, rv)
        self.assertEqual(out2["dropped"], 1, "只应丢掉 a11y 那条")
        self.assertEqual(len(rep2["checks"][1]["findings"]), 1, "todos 不该被 no-style 干掉")

    def test_absent(self) -> None:
        self.assertFalse(LC.load_review_md(_proj())["found"])


class TestMergeProbe(unittest.TestCase):
    def test_non_git_is_rejected(self) -> None:
        out = LC.merge_probe(_proj(), "main")
        self.assertFalse(out["ok"])
        self.assertIn("不是 git 仓库", out["note"])


if __name__ == "__main__":
    unittest.main()
