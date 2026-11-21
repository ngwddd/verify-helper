"""Acceptance evidence for full verification and cross-project fixture classes."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import threading
import unittest
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from jsonschema import Draft202012Validator

from full_verify import decide, full_verify
import full_verify as engine
import lifecycle
import verify_core as core
from process_boundary import contain_worker


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
        options.setdefault("evidence_dir", self.root / ".verify-artifacts")
        report = full_verify(self.root, unsafe_local=True, **options)
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
        self.file("verify.toml", "[verification]\nnpm_test = true\n")
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

    @unittest.skipUnless(shutil.which("node"), "Requires Node")
    def test_runs_four_node_suites_and_declared_data_contract(self):
        for number in range(4):
            self.file(f"suite{number}.spec.mjs",
                      "import { test } from 'node:test'; test('fixture', () => {});\n")
        self.file("package.json", '{"scripts":{"test":"node unsupported-script.js"}}')
        self.file("tools/validate-data.js", "console.log('dataset validated');\n")
        self.file("verify.toml", '[[verification.contracts]]\nargv=["node","tools/validate-data.js"]\n'
                                 'expect_output="dataset validated"\n')
        report, rows = self.run_full()
        self.assertEqual(rows["tests"]["coverage"]["observed"], 4)
        self.assertEqual(rows["contract-1"]["state"], "PASS")
        self.assertEqual(report["verdict"], "PASS")

    def test_evidence_failure_cannot_yield_pass(self):
        self.file("README.md", "Documentation.")
        invalid = self.file("unavailable", "This target is a file.")
        report, _ = self.run_full(evidence_dir=invalid)
        self.assertEqual(report["verdict"], "UNKNOWN")
        self.assertTrue(report["blockers"])

    def test_v2_evidence_retrieval_rejects_changed_receipt(self):
        self.file("README.md", "Documentation.")
        report, rows = self.run_full()
        directory = Path(report["evidence_dir"])
        self.assertEqual(engine.read_evidence(directory)["verdict"], "PASS")
        (directory / rows["encoding"]["evidence_ref"]).write_text("changed", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "digest"):
            engine.read_evidence(directory)

    def test_v2_full_report_has_explicit_releasability_and_ledger(self):
        self.file("app.py", "def value(): return 42\n")
        report, _ = self.run_full()
        schema_path = Path(__file__).resolve().parents[1] / "docs/v2/SCHEMA-v2.json"
        Draft202012Validator(json.loads(schema_path.read_bytes())).validate(report)
        self.assertEqual(report["scope"], "FULL")
        self.assertFalse(report["releasable"])
        tests = next(row for row in report["ledger"] if row["check_id"] == "tests")
        self.assertEqual(tests["applicability"], "APPLICABLE")
        self.assertEqual(tests["eligible"], tests["executed"] + tests["skipped"] + tests["not_run"])
        self.assertGreater(tests["not_run"], 0)

    def test_v2_policy_records_unavailable_explicit_check(self):
        self.file("README.md", "Documentation.")
        policy = self.file("policy.json", '{"required_checks":["physical-oracle"]}')
        report, _ = self.run_full(policy_path=policy)
        row = next(item for item in report["ledger"] if item["check_id"] == "physical-oracle")
        self.assertTrue(row["required"])
        self.assertEqual(row["not_run"], 1)
        self.assertEqual(report["verdict"], "UNKNOWN")

    def test_rc2_invalid_yaml_is_a_required_syntax_failure(self):
        self.file("workflow.yaml", "jobs: [\n")
        report, rows = self.run_full()
        self.assertEqual(report["verdict"], "FAIL")
        self.assertEqual(rows["syntax"]["findings"][0]["file"], "workflow.yaml")

    def test_rc2_missing_node_is_applicable_and_preserves_other_failures(self):
        js = self.file("sample.mjs", "const state = 1;")
        py = self.file("broken.py", "def broken(:\n")
        with patch.object(core, "_run", return_value=(127, "")):
            ctx = core.Ctx(core.Cache(False))
            unavailable = core.check_syntax(self.root, [js], ctx)
            known_failure = core.check_syntax(self.root, [js, py], ctx)
        self.assertTrue(unavailable.applicable)
        self.assertEqual(unavailable.state, "UNKNOWN")
        self.assertEqual(unavailable.coverage, {"planned": 1, "observed": 0})
        self.assertEqual(known_failure.state, "FAIL")

    def test_rc2_project_cannot_be_its_own_scratch_directory(self):
        self.file("README.md", "Documentation.")
        with patch.dict(os.environ, {"VERIFY_SCRATCH_DIRECTORY": str(self.root)}):
            report, _ = self.run_full()
        self.assertEqual(report["verdict"], "UNKNOWN")
        self.assertEqual([item.name for item in self.root.iterdir()], ["README.md"])

    def test_rc2_manifest_binds_the_frozen_check_plan(self):
        self.file("README.md", "Documentation.")
        report, _ = self.run_full()
        manifest = json.loads((Path(report["evidence_dir"]) / "manifest.json").read_bytes())
        self.assertEqual(report["plan_digest"], manifest["plan_digest"])
        self.assertEqual(set(report["plan"]), {row["check_id"] for row in report["ledger"] if row["required"]})

    def test_rc2_worker_process_boundary_is_applied(self):
        if os.name != "nt":
            self.file("README.md", "Documentation.")
            report, _ = self.run_full()
            self.assertEqual(report["process_boundary"], "process")
            return
        import win32api
        import win32con
        import win32event

        go, receipt = self.root / "go", self.root / "pid"
        worker_code = (
            "from pathlib import Path\nimport sys,time,subprocess\n"
            f"while not Path({str(go)!r}).exists(): time.sleep(.02)\n"
            "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(90)'],"
            "creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP)\n"
            f"Path({str(receipt)!r}).write_text(str(p.pid))\n"
        )
        with subprocess.Popen([core.sys.executable, "-c", worker_code]) as worker:
            with contain_worker(worker) as boundary:
                self.assertEqual(boundary, "windows-job")
                go.touch()
                worker.wait(timeout=15)
                child = win32api.OpenProcess(win32con.SYNCHRONIZE, False, int(receipt.read_text()))
            try:
                self.assertEqual(win32event.WaitForSingleObject(child, 5000), win32event.WAIT_OBJECT_0)
            finally:
                child.Close()

    def test_rc2_mutation_budget_preserves_missing_coverage(self):
        source = self.file("calc.py", "".join(f"def value_{n}():\n    return {n} + 1\n"
                                             for n in range(6)))
        tests = self.file("tests/test_calc.py", "import unittest, calc\nclass Check(unittest.TestCase):\n" +
                          "".join(f"    def test_value_{n}(self): self.assertEqual(calc.value_{n}(), {n+1})\n"
                                  for n in range(6)))
        original = source.read_bytes()
        ctx = core.Ctx(core.Cache(False), mutation_max=2)
        result = core.check_mutation(self.root, [source, tests], ctx)
        self.assertEqual(result.state, "UNKNOWN", result.detail)
        self.assertEqual(result.coverage, {"planned": 6, "observed": 2})
        self.assertEqual(source.read_bytes(), original)

    def test_v2_p0_02_finds_js_syntax_error_past_previous_cap(self):
        if not shutil.which("node"):
            self.skipTest("Requires Node")
        for index in range(121):
            self.file(f"module-{index:03}.mjs", "const = ;\n" if index == 120 else "const x = 1;\n")
        report, rows = self.run_full()
        self.assertEqual(report["verdict"], "FAIL")
        self.assertEqual(rows["syntax"]["findings"][-1]["file"], "module-120.mjs")

    def test_v2_cancels_an_already_started_command(self):
        ready = self.root / "started"
        stop = self.root / "cancel"
        source = self.file("fixture.py", f"from pathlib import Path\nimport time\n"
                           f"Path({str(ready)!r}).touch()\ntime.sleep(90)\n")
        answers = []
        with patch.dict(os.environ, {"VERIFY_HELPER_CANCEL_FILE": str(stop)}):
            worker = threading.Thread(target=lambda: answers.append(
                core._run([core.sys.executable, str(source)], self.root, 15)))
            worker.start()
            try:
                for _ in range(100):
                    if ready.exists():
                        break
                    threading.Event().wait(0.05)
                self.assertTrue(ready.exists())
            finally:
                stop.touch()
                worker.join(12)
        self.assertFalse(worker.is_alive())
        self.assertEqual(answers[0][0], 125)

    def test_v2_p0_06_browser_absence_remains_required(self):
        self.file("index.html", "<!doctype html><html><body><p>Fixture</p></body></html>")
        with patch.object(core, "_find_playwright", return_value=None):
            report = engine._run_plan(self.root, trusted=True)
        engine._finalize(report, None)
        browser = next(row for row in report["ledger"] if row["check_id"] == "browser")
        self.assertTrue(browser["required"])
        self.assertEqual(browser["applicability"], "APPLICABLE")
        self.assertEqual(browser["reason_code"], "MISSING_BROWSER_DEPENDENCY")
        self.assertEqual(report["verdict"], "UNKNOWN")

    def test_cleanup_failure_changes_the_archived_and_returned_verdict(self):
        self.file("README.md", "Documentation.")

        class CleanupFailure(tempfile.TemporaryDirectory):
            def __exit__(self, *error):
                super().__exit__(*error)
                raise PermissionError("Simulated locked Windows file")

        with patch("full_verify.tempfile.TemporaryDirectory", CleanupFailure):
            report, _ = self.run_full()
        archived = Path(report["evidence_dir"]) / "report.json"
        saved = json.loads(archived.read_text(encoding="utf-8"))
        self.assertEqual(report["verdict"], "UNKNOWN")
        self.assertEqual(saved["verdict"], report["verdict"])
        self.assertEqual(saved["blockers"], report["blockers"])

    def test_missing_evidence_is_an_independent_veto(self):
        row = {"id": "tests", "state": "PASS", "applicable": True}
        report = {"checks": [row], "plan": {"tests": "Required"}}
        self.assertEqual(decide(report), "UNKNOWN")
        row["evidence_ref"] = "tests.json"
        row["coverage"] = {"planned": 4, "observed": 3}
        self.assertEqual(decide(report), "UNKNOWN")

    def test_v2_p0_05_lifecycle_failure_blocks_full_pass(self):
        self.file("README.md", "Documentation.")
        with patch.object(lifecycle, "apply", side_effect=RuntimeError("worker failure")):
            report = engine._run_plan(self.root, trusted=False)
        for row in report["checks"]:
            row["evidence_ref"] = row["id"] + ".json"
        self.assertEqual(decide(report), "UNKNOWN")

    def test_v2_p1_03_same_metadata_changed_bytes_miss_syntax_cache(self):
        source = self.file("module.js", "let x = 1;\n")
        before = source.stat()
        cache = core.Cache()
        cache.put(source, True)
        source.write_text("let = x 1;\n", encoding="utf-8")
        os.utime(source, ns=(before.st_atime_ns, before.st_mtime_ns))
        self.assertEqual(source.stat().st_size, before.st_size)
        self.assertIsNone(cache.get(source))

    def test_secret_does_not_appear_in_report_or_artifacts(self):
        sentinel = "sk-" + "X" * 28
        self.file("config.py", f'SERVICE_KEY = "{sentinel}"\n')
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
        self.assertEqual(rows["delivery-1"]["state"], "PASS", rows["delivery-1"])
        self.assertEqual(report["verdict"], "PASS")
        config.write_text(config.read_text().replace('["README.md"]', '["LICENSE"]'), encoding="utf-8")
        report, rows = self.run_full()
        self.assertEqual(rows["delivery-1"]["state"], "FAIL")
        self.assertEqual(report["verdict"], "FAIL")

    def test_rc2_package_name_and_version_must_match_metadata(self):
        self.file("README.md", "Delivery.")
        (self.root / "dist").mkdir()
        path = self.root / "dist/fixture-2.0-py3-none-any.whl"
        folder = "fixture-2.0.dist-info"
        members = {f"{folder}/METADATA": b"Name: fixture\nVersion: 1.0\n",
                   f"{folder}/WHEEL": b"Wheel-Version: 1.0\n"}
        with zipfile.ZipFile(path, "w") as archive:
            record = []
            for name, data in members.items():
                archive.writestr(name, data)
                value = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip("=")
                record.append(f"{name},sha256={value},{len(data)}")
            entry = f"{folder}/RECORD"
            archive.writestr(entry, "\n".join([*record, f"{entry},,"]) + "\n")
        report, rows = self.run_full()
        self.assertEqual(report["verdict"], "FAIL")
        self.assertIn("version differs", rows["delivery-1"]["detail"])

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

    @unittest.skipUnless(shutil.which("git"), "Requires Git")
    def test_v2_p0_04_known_merge_conflict_is_fail(self):
        self.file("README.md", "Original\n")

        def git(*args):
            subprocess.run(["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                            *args], cwd=self.root, check=True, capture_output=True)

        git("init", "-qb", "main")
        git("add", "README.md")
        git("commit", "-qm", "base")
        git("switch", "-qc", "other")
        file = self.file("README.md", "Other\n")
        git("commit", "-qam", "other")
        git("switch", "-q", "main")
        self.file("README.md", "Main\n")
        git("commit", "-qam", "main")
        report, _ = self.run_full(against="other")
        self.assertEqual(report["verdict"], "FAIL")
        self.assertEqual(file.read_text(), "Main\n")

    @unittest.skipUnless(os.environ.get("VERIFY_PLAYWRIGHT_ROOT") and shutil.which("node"),
                         "Requires a configured Chromium installation")
    def test_real_browser_and_click_flow(self):
        self.file("index.html", """<!doctype html>
<html lang="en"><head><title>Fixture</title></head><body>
<h1>Start</h1><button onclick="this.textContent='Save restored'">Restore</button>
<a href="/docs/en/404.html">English</a>
<script src="/docs/app.mjs" type="module"></script>
<link rel="stylesheet" href="/docs/site.css">
</body></html>""")
        self.file("en/404.html", """<!doctype html>
<html lang="en"><head><title>Not found</title></head><body><h1>Not found</h1></body></html>""")
        self.file("site.css", "body { color: black; }\n")
        self.file("app.mjs", "document.body.dataset.ready = innerWidth === 390 ? 'mobile' : 'yes';\n")
        self.file("verify.toml", '''[[flows]]
name = "Restore saved session"
viewport = {width=390, height=844}
steps = [{goto="index.html"}, {expect={selector="body[data-ready='mobile']", visible=true}}, {click="button"}, {expect={selector="button", text_contains="Save restored"}}]
''')
        report, rows = self.run_full()
        self.assertEqual(rows["browser"]["state"], "PASS", rows["browser"])
        self.assertEqual(rows["interaction"]["state"], "PASS", rows["interaction"])
        self.assertEqual(report["verdict"], "PASS")
        self.assertTrue(rows["browser"]["media"])
        self.assertEqual(rows["browser"]["coverage"]["observed"], 2)

    @unittest.skipUnless(os.environ.get("VERIFY_PLAYWRIGHT_ROOT") and shutil.which("node"),
                         "Requires a configured Chromium installation")
    def test_v2_p1_02_combined_browser_conditions_are_all_required(self):
        self.file("index.html", '<!doctype html><html><head><title>Fixture</title></head>'
                  '<body><p id="state">Actual</p></body></html>')
        self.file("verify.toml", """[[flows]]
name = "Combined assertions"
steps = [{goto="index.html"}, {expect={no_console_error=true, url_contains="index.html", selector="#state", text_contains="Expected", timeout=250}}]
""")
        report, rows = self.run_full()
        self.assertEqual(rows["interaction"]["state"], "FAIL", rows["interaction"])
        self.assertEqual(report["verdict"], "FAIL")

    @unittest.skipUnless(os.environ.get("VERIFY_PLAYWRIGHT_ROOT") and shutil.which("node"),
                         "Requires a configured Chromium installation")
    def test_v2_p0_02_browser_reaches_page_beyond_previous_cap(self):
        for index in range(31):
            script = "<script>throw new Error('last page')</script>" if index == 30 else ""
            name = "index.html" if index == 0 else f"page-{index:03}.html"
            self.file(name, "<!doctype html><html><head><title>Fixture</title></head>"
                      f"<body><p>Fixture</p>{script}</body></html>")
        report, rows = self.run_full()
        self.assertEqual(rows["browser"]["coverage"]["observed"], 31)
        self.assertEqual(report["verdict"], "FAIL")
        self.assertTrue(any(item["file"] == "page-030.html" for item in rows["browser"]["findings"]))

    @unittest.skipUnless(os.environ.get("VERIFY_PLAYWRIGHT_ROOT") and shutil.which("node"),
                         "Requires a configured Chromium installation")
    def test_rc2_browser_refuses_cross_origin_network(self):
        received = []

        class Witness(BaseHTTPRequestHandler):
            def do_GET(self):
                received.append(self.path)
                self.send_response(204)
                self.end_headers()

        with ThreadingHTTPServer(("127.0.0.1", 0), Witness) as server:
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            try:
                port = server.server_address[1]
                self.file("index.html", "<!doctype html><html><head><title>Fixture</title>"
                          f'<script src="http://127.0.0.1:{port}/external.js"></script>'
                          "</head><body><p>Fixture</p></body></html>")
                report, rows = self.run_full()
                self.assertEqual(received, [])
                self.assertEqual(rows["browser"]["state"], "UNKNOWN", rows["browser"])
                self.assertEqual(rows["browser"]["reason_code"], "PREVIEW_EXTERNAL_NETWORK_BLOCKED")
                self.assertFalse(report["releasable"])
            finally:
                server.shutdown()
                thread.join()

    @unittest.skipUnless(os.environ.get("VERIFY_TSC") and shutil.which("node"),
                         "Requires a configured TypeScript compiler")
    def test_typescript_typecheck(self):
        self.file("tsconfig.json", '{"compilerOptions":{"strict":true},"files":["sample.ts"]}')
        self.file("sample.ts", 'const state: number = "wrong type";\n')
        report, rows = self.run_full()
        self.assertEqual(rows["typescript"]["state"], "FAIL", rows["typescript"])
        self.assertEqual(report["verdict"], "FAIL")
        self.file("sample.ts", "const state: number = 42;\n")
        self.file("excluded.ts", "const uncompiled: number = 42;\n")
        report, rows = self.run_full()
        self.assertEqual(rows["typescript"]["state"], "UNKNOWN", rows["typescript"])
        self.assertEqual(rows["typescript"]["coverage"], {"planned": 2, "observed": 1})
        self.assertEqual(report["verdict"], "UNKNOWN")

    @unittest.skipUnless(shutil.which("cmake") and shutil.which("ctest")
                         and os.environ.get("VERIFY_NATIVE_FIXTURE"), "Requires native toolchain")
    def test_cmake_build_and_ctest_execute_real_binaries(self):
        self.file("CMakeLists.txt", """cmake_minimum_required(VERSION 3.16)
project(verification_fixture C CXX)
enable_testing()
add_executable(state main.c)
add_executable(compatibility compatibility.cpp)
add_test(NAME state_machine COMMAND state)
add_test(NAME compatibility COMMAND compatibility)
""")
        self.file("main.c", "int main(void) { return 0; }\n")
        self.file("compatibility.cpp", "int main() { const bool compatible = true; return !compatible; }\n")
        report, rows = self.run_full()
        self.assertEqual(rows["build-native"]["state"], "PASS", rows["build-native"])
        self.assertEqual(rows["tests-native"]["state"], "PASS", rows["tests-native"])
        self.assertEqual(rows["tests-native"]["coverage"], {"planned": 2, "observed": 2})
        self.assertEqual(report["verdict"], "PASS")
        self.assertNotIn("browser", report["plan"])
