"""Acceptance evidence for full verification and cross-project fixture classes."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from full_verify import decide, full_verify


PASSING_TEST = """import unittest
from app import value

class ContractTests(unittest.TestCase):
    def test_value(self):
        self.assertEqual(value(), 42)
"""


class FullVerification(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def file(self, relative, content):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def run_full(self, **options):
        report = full_verify(self.root, trusted=True, **options)
        rows = {row["id"]: row for row in report["checks"]}
        return report, rows

    def test_unit_test_evidence_and_copy_isolation(self):
        source = self.file("app.py", "def value(): return 42\n")
        self.file("tests/test_app.py", PASSING_TEST + """
    def test_writes_stay_in_snapshot(self):
        from pathlib import Path
        Path("app.py").write_text("changed")
        Path("generated.txt").write_text("created")
""")
        report, rows = self.run_full()
        self.assertEqual(report["verdict"], "PASS", report["blockers"])
        self.assertEqual(rows["tests"]["coverage"]["observed"], 2)
        self.assertEqual(source.read_text(), "def value(): return 42\n")
        self.assertFalse((self.root / "generated.txt").exists())
        evidence = Path(report["evidence_dir"]) / rows["tests"]["evidence_ref"]
        self.assertEqual(hashlib.sha256(evidence.read_bytes()).hexdigest(), rows["tests"]["evidence_sha256"])
        saved = json.loads((Path(report["evidence_dir"]) / "report.json").read_text(encoding="utf-8"))
        self.assertEqual(saved["snapshot_sha256"], report["snapshot_sha256"])

    def test_source_pass_cannot_replace_missing_runtime(self):
        self.file("app.py", "def value(): return 42\n")
        report, rows = self.run_full()
        self.assertEqual(rows["syntax"]["state"], "PASS")
        self.assertEqual(rows["tests"]["state"], "UNKNOWN")
        self.assertEqual(report["verdict"], "UNKNOWN")

    def test_partial_and_all_skipped_never_certify_complete_coverage(self):
        self.file("app.py", "def value(): return 42\n")
        tests = self.file("tests/test_app.py", PASSING_TEST)
        for skip_all in (False, True):
            fixture = PASSING_TEST
            if skip_all:
                fixture = fixture.replace("    def test_value", '    @unittest.skip("missing runtime")\n    def test_value')
            else:
                fixture += '\n    @unittest.skip("missing runtime")\n    def test_other(self): pass\n'
            tests.write_text(fixture, encoding="utf-8")
            with self.subTest(skip_all=skip_all):
                report, rows = self.run_full()
                self.assertEqual(report["verdict"], "UNKNOWN")
                self.assertEqual(rows["tests"]["coverage"]["skipped"], 1)

    @unittest.skipUnless(shutil.which("node") and shutil.which("npm"), "Requires Node and npm")
    def test_zero_exit_without_tests_from_dsh_balance_class(self):
        self.file("package.json", '{"scripts":{"test":"node live.mjs"}}')
        self.file("live.mjs", "console.log('SKIP live runtime unavailable');\n")
        report, rows = self.run_full()
        self.assertEqual(rows["tests"]["exit_code"], 0)
        self.assertEqual(rows["tests"]["state"], "UNKNOWN")
        self.assertEqual(report["verdict"], "UNKNOWN")

    @unittest.skipUnless(shutil.which("node") and shutil.which("npm"), "Requires Node and npm")
    def test_mixed_languages_cannot_share_one_suite_result(self):
        self.file("app.py", "def value(): return 42\n")
        self.file("tests/test_app.py", PASSING_TEST)
        self.file("package.json", '{"scripts":{"test":"node --test"}}')
        self.file("project.test.mjs", "import { test } from 'node:test'; test('native test runner', () => {});\n")
        report, rows = self.run_full()
        self.assertEqual(rows["tests-python"]["state"], "PASS")
        self.assertEqual(rows["tests-javascript"]["state"], "PASS", rows["tests-javascript"])
        self.assertEqual(report["verdict"], "PASS")

    def test_evidence_failure_cannot_yield_pass(self):
        self.file("README.md", "Documentation.")
        invalid = self.file("unavailable", "This target is a file.")
        report, _ = self.run_full(evidence_dir=invalid)
        self.assertEqual(report["verdict"], "UNKNOWN")
        self.assertTrue(report["blockers"])

    def test_missing_evidence_is_an_independent_veto(self):
        row = {"id": "tests", "state": "PASS", "applicable": True}
        report = {"checks": [row], "plan": {"tests": "Required"}}
        self.assertEqual(decide(report), "UNKNOWN")
        row["evidence_ref"] = "tests.json"
        row["coverage"] = {"planned": 4, "observed": 3}
        self.assertEqual(decide(report), "UNKNOWN")

    def test_secret_does_not_appear_in_report_or_artifacts(self):
        sentinel = "sk-" + "X" * 28
        self.file(".env", f"SERVICE_KEY={sentinel}\n")
        report, rows = self.run_full()
        self.assertEqual(report["verdict"], "FAIL")
        self.assertEqual(rows["secrets"]["state"], "FAIL")
        self.assertNotIn(sentinel, json.dumps(report))
        for artifact in Path(report["evidence_dir"]).glob("*"):
            self.assertNotIn(sentinel.encode(), artifact.read_bytes())

    def test_project_contract_detects_bad_business_state(self):
        self.file("tool.mjs", "console.log('save migration v2');\n")
        self.file("package.json", '{"scripts":{"test":"node --test"}}')
        self.file("save.test.mjs", "import { test } from 'node:test'; test('save', () => {});\n")
        self.file("verify.toml", '''[[verification.contracts]]
argv = ["node", "tool.mjs"]
expect_output = "save migration v3"
''')
        if not shutil.which("node"):
            self.skipTest("Requires Node")
        report, rows = self.run_full()
        self.assertEqual(rows["contract-1"]["state"], "FAIL")
        self.assertEqual(report["verdict"], "FAIL")

    def test_release_contract_checks_digest_and_members(self):
        self.file("README.md", "Delivery.")
        (self.root / "dist").mkdir()
        path = self.root / "dist/bundle.zip"
        with zipfile.ZipFile(path, "w") as package:
            package.writestr("README.md", "Delivery guide.")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        config = self.file("verify.toml", f'''[[verification.delivery]]
path = "dist/bundle.zip"
sha256 = "{digest}"
members = ["README.md"]
''')
        report, rows = self.run_full()
        self.assertEqual(rows["delivery-1"]["state"], "PASS")
        self.assertEqual(report["verdict"], "PASS")
        config.write_text(config.read_text().replace('["README.md"]', '["LICENSE"]'), encoding="utf-8")
        report, rows = self.run_full()
        self.assertEqual(rows["delivery-1"]["state"], "FAIL")
        self.assertEqual(report["verdict"], "FAIL")

    @unittest.skipUnless(shutil.which("git"), "Requires Git")
    def test_unresolved_merge_never_falls_back_to_head(self):
        self.file("README.md", "Valid.")
        for args in (["init", "-q"], ["add", "README.md"],
                     ["-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                      "commit", "-qm", "base"]):
            subprocess.run(["git", *args], cwd=self.root, check=True)
        report, _ = self.run_full(against="nonexistent")
        self.assertEqual(report["verdict"], "UNKNOWN")
        self.assertTrue(report["blockers"])
        report, _ = self.run_full(against="HEAD")
        self.assertEqual(report["verdict"], "PASS")
        self.assertIn("tree", report["merge"])

    @unittest.skipUnless(os.environ.get("VERIFY_PLAYWRIGHT_ROOT") and shutil.which("node"),
                         "Requires a configured Chromium installation")
    def test_real_browser_and_click_flow(self):
        self.file("index.html", """<!doctype html>
<html lang="en"><head><title>Fixture</title></head><body>
<h1>Start</h1><button onclick="this.textContent='Save restored'">Restore</button>
</body></html>""")
        self.file("verify.toml", '''[[flows]]
name = "Restore saved session"
steps = [{goto="index.html"}, {click="button"}, {expect={selector="button", text_contains="Save restored"}}]
''')
        report, rows = self.run_full()
        self.assertEqual(rows["browser"]["state"], "PASS", rows["browser"])
        self.assertEqual(rows["interaction"]["state"], "PASS", rows["interaction"])
        self.assertEqual(report["verdict"], "PASS")
        self.assertTrue(rows["browser"]["media"])

    @unittest.skipUnless(os.environ.get("VERIFY_TSC") and shutil.which("node"),
                         "Requires a configured TypeScript compiler")
    def test_typescript_typecheck(self):
        self.file("tsconfig.json", '{"compilerOptions":{"strict":true},"files":["sample.ts"]}')
        self.file("sample.ts", 'const state: number = "wrong type";\n')
        report, rows = self.run_full()
        self.assertEqual(rows["typescript"]["state"], "FAIL", rows["typescript"])
        self.assertEqual(report["verdict"], "FAIL")

    @unittest.skipUnless(shutil.which("cmake") and shutil.which("ctest")
                         and os.environ.get("VERIFY_NATIVE_FIXTURE"), "Requires native toolchain")
    def test_cmake_build_and_ctest_execute_real_binary(self):
        self.file("CMakeLists.txt", """cmake_minimum_required(VERSION 3.16)
project(verification_fixture C)
enable_testing()
add_executable(state main.c)
add_test(NAME state_machine COMMAND state)
""")
        self.file("main.c", "int main(void) { return 0; }\n")
        report, rows = self.run_full()
        self.assertEqual(rows["build-native"]["state"], "PASS", rows["build-native"])
        self.assertEqual(rows["tests-native"]["state"], "PASS", rows["tests-native"])
        self.assertEqual(report["verdict"], "PASS")
        self.assertNotIn("browser", report["plan"])
