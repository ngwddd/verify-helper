"""Cross-platform checks for the protected entry point and sealed report."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from full_verify import full_verify
from private_storage import require_private
from report_export import mcp_report
from run_evidence import digest, json_bytes, read_evidence, resolve_local_finding


class TestProtectedVerification(unittest.TestCase):
    def setUp(self):
        work = tempfile.TemporaryDirectory()
        self.addCleanup(work.cleanup)
        self.base = Path(work.name)
        self.source = self.base / "project"
        self.source.mkdir()
        self.output = self.base / "receipts"

    def run_protected(self, **kwargs):
        return full_verify(self.source, evidence_dir=self.output, run_id="vh_rc3_fixture", **kwargs)

    def test_excluded_private_inputs_block_project_execution(self):
        witness = self.base / "host-witness"
        (self.source / "test_app.py").write_text(
            "import unittest\nfrom pathlib import Path\n"
            "class Fixture(unittest.TestCase):\n"
            f"    def test_run(self): Path({str(witness)!r}).touch()\n", encoding="utf-8")
        (self.source / ".env.fixture").write_text("synthetic private input", encoding="utf-8")
        report = self.run_protected()
        self.assertFalse(witness.exists())
        self.assertEqual(report["verdict"], "UNKNOWN")
        self.assertFalse(report["releasable"])
        self.assertEqual(report["security_assurance"], "NOT_PROVIDED")
        self.assertNotIn(str(self.source), json.dumps(report))
        self.assertNotIn(".env.fixture", json.dumps(report))
        self.assertEqual(report, read_evidence(self.output / report["run_id"]))

    def test_mcp_sealed_archive_excludes_project_metadata_and_raw_diagnostics(self):
        marker = "R1JQR2t3RFZzWmNDWTVQTGhlVHJSc0t1"
        project_file = self.source / f"{marker}.py"
        project_file.write_text("bad syntax @\n", encoding="utf-8")
        (self.source / "verify.toml").write_text("[configuration\n" + marker, encoding="utf-8")
        policy = self.base / "policy.json"
        policy.write_text(json.dumps({"required_checks": [marker]}), encoding="utf-8")
        report = self.run_protected(sealed=True, policy_path=policy)
        self.assertEqual(report["verdict"], "FAIL")
        self.assertIn("syntax", report["plan"])
        for artifact in (self.output / report["run_id"]).iterdir():
            self.assertIn(artifact.suffix, {".json", ".sarif"})
            self.assertNotIn(marker.encode(), artifact.read_bytes())

    def test_older_mcp_report_is_rebuilt_from_a_fixed_schema(self):
        marker = "opaque-synthetic-restricted-value"
        report = {"project": marker, "status": "COMPLETED", "verdict": "FAIL",
                  "plan": {marker: marker}, "checks": [
                      {"id": marker, "title": marker, "state": "FAIL", "applicable": True,
                       "reason_code": marker, "command": marker, "detail": marker,
                       "evidence_ref": marker, "media": [{"path": marker}],
                       "findings": [{"message": marker, "file": marker}]}],
                  "sarif": {"message": marker}, "blockers": [marker]}
        public = mcp_report(report, "vh_rc3_fixture", "test-version")
        self.assertEqual(public["verdict"], "FAIL")
        self.assertNotIn(marker, json.dumps(public))

    def test_snapshot_omits_hardlink_to_host_file(self):
        witness = self.base / "host-witness"
        witness.write_text("synthetic private hardlink target", encoding="utf-8")
        os.link(witness, self.source / "alias.txt")
        (self.source / "app.py").write_text("value = 1\n", encoding="utf-8")
        report = self.run_protected()
        self.assertEqual(report["verdict"], "UNKNOWN")
        self.assertIn("Source snapshot contains omitted or changed entries", report["blockers"])
        self.assertNotIn("alias.txt", json.dumps(report))

    def test_snapshot_omits_linked_host_directory(self):
        witness = self.base / "host-directory"
        witness.mkdir()
        (witness / "outside.py").write_text("invalid Python @\n", encoding="utf-8")
        alias = self.source / "private-alias"
        if os.name == "nt":
            subprocess.run(["cmd.exe", "/d", "/c", "mklink", "/J", str(alias), str(witness)],
                           check=True, capture_output=True)
            self.addCleanup(alias.rmdir)
        else:
            alias.symlink_to(witness, target_is_directory=True)
        (self.source / "app.py").write_text("value = 1\n", encoding="utf-8")
        report = self.run_protected()
        self.assertEqual(report["verdict"], "UNKNOWN")
        self.assertIn("Source snapshot contains omitted or changed entries", report["blockers"])
        self.assertNotIn("private-alias", json.dumps(report))

    def test_rehashing_changed_evidence_does_not_reauthenticate_it(self):
        (self.source / "app.py").write_text("value = 1\n", encoding="utf-8")
        key = bytes(range(32))
        report = self.run_protected(evidence_key=key)
        archive = self.output / report["run_id"]
        self.assertEqual(read_evidence(archive, key=key), report)
        with self.assertRaisesRegex(ValueError, "key is required"):
            read_evidence(archive)
        manifest_path = archive / "manifest.json"
        report_path = archive / "report.json"
        manifest = json.loads(manifest_path.read_bytes())
        report.update(verdict="PASS", releasable=True, security_status="ENFORCED")
        body = json_bytes(report)
        report_path.write_bytes(body)
        manifest["files"]["report.json"] = digest(body)
        manifest_path.write_bytes(json_bytes(manifest))
        with self.assertRaisesRegex(ValueError, "authentication failed"):
            read_evidence(archive, key=key)

    def test_project_config_cannot_disable_isolation(self):
        (self.source / "verify.toml").write_text(
            '[verification]\nnetwork = "unrestricted"\nsandbox = "off"\n', encoding="utf-8")
        (self.source / "test_app.py").write_text("import unittest\n", encoding="utf-8")
        report = self.run_protected()
        rows = {row["id"]: row for row in report["checks"]}
        self.assertEqual(rows["configuration"]["state"], "FAIL")
        self.assertEqual(rows["tests"]["state"], "UNKNOWN")
        self.assertFalse(report["releasable"])

    def test_project_ignore_cannot_hide_bad_source_or_test(self):
        (self.source / ".verifyignore").write_text("hidden.py\ntest_hidden.py\n", encoding="utf-8")
        (self.source / "hidden.py").write_text("value = @\n", encoding="utf-8")
        (self.source / "test_hidden.py").write_text("import unittest\n", encoding="utf-8")
        report = self.run_protected()
        self.assertEqual(report["verdict"], "FAIL")
        rows = {row["id"]: row for row in report["checks"]}
        self.assertIn("tests", report["plan"])
        self.assertEqual(rows["syntax"]["findings"][0]["line"], 1)
        self.assertNotIn("hidden.py", json.dumps(report))

    def test_evidence_permissions_under_open_umask(self):
        (self.source / "app.py").write_text("answer = 42\n", encoding="utf-8")
        mask = os.umask(0)
        try:
            report = self.run_protected()
        finally:
            os.umask(mask)
        run = self.output / report["run_id"]
        require_private(run, directory=True)
        for entry in run.iterdir():
            require_private(entry)
            if os.name != "nt":
                self.assertEqual(entry.stat().st_mode & 0o777, 0o600)

    def test_legacy_cli_switch_is_rejected_and_full_mode_runs_locally(self):
        witness = self.base / "host-witness"
        (self.source / "test_app.py").write_text(
            f"from pathlib import Path\nPath({str(witness)!r}).touch()\n", encoding="utf-8")
        cli = [sys.executable, str(Path(__file__).resolve().parents[1] / "full_verify.py")]
        rejected = subprocess.run([*cli, "run", str(self.source), "--trust-project-code"],
                                  capture_output=True, text=True, timeout=10)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("unrecognized arguments", rejected.stderr)
        self.assertFalse(witness.exists())
        report = self.run_protected()
        self.assertTrue(witness.exists())
        self.assertEqual(report["verdict"], "UNKNOWN")
        self.assertFalse(report["releasable"])

    def test_unsafe_success_is_not_releasable(self):
        (self.source / "README.md").write_text("Developer fixture.\n", encoding="utf-8")
        report = self.run_protected(unsafe_local=True)
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["execution_mode"], "local-host")
        self.assertFalse(report["releasable"])

    def test_single_source_file_has_a_separate_static_scope(self):
        (self.source / "other.py").write_text("invalid = @\n", encoding="utf-8")
        selected = self.source / "entry.py"
        selected.write_text("value = 1\n", encoding="utf-8")
        report = full_verify(selected, evidence_dir=self.output)
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["target_kind"], "file")
        self.assertEqual(report["security_status"], "NOT_REQUIRED")
        self.assertNotIn("tests", report["plan"])
        self.assertFalse(report["releasable"])
        self.assertEqual(self.run_protected()["verdict"], "FAIL")

    def test_custom_rule_limits_are_reported_as_missing_coverage(self):
        (self.source / "verify.toml").write_text(
            '[[rules]]\npattern = "literal"\npaths = ["content.txt"]\n', encoding="utf-8")
        (self.source / "content.txt").write_text("x" * 33_000, encoding="utf-8")
        report = self.run_protected()
        custom = next(row for row in report["checks"] if row["id"] == "custom")
        self.assertEqual(custom["state"], "UNKNOWN")
        self.assertEqual(custom["reason_code"], "CUSTOM_RULE_BUDGET_EXCEEDED")

    def test_confirmed_custom_failure_survives_incomplete_coverage(self):
        (self.source / "verify.toml").write_text(
            '[[rules]]\npattern = "fixture-forbidden"\npaths = ["content.txt"]\nrisk = "high"\n',
            encoding="utf-8")
        (self.source / "content.txt").write_text("fixture-forbidden\n" + "x" * 33_000, encoding="utf-8")
        report = self.run_protected()
        custom = next(row for row in report["checks"] if row["id"] == "custom")
        self.assertEqual(report["verdict"], "FAIL")
        self.assertEqual(custom["state"], "FAIL")
        self.assertEqual(custom["reason_code"], "CUSTOM_RULE_BUDGET_EXCEEDED")
        self.assertEqual(custom["coverage"], {"planned": 1, "observed": 0, "skipped": 0})

    def test_local_finding_alias_requires_an_intact_opt_in_index(self):
        file_name = "synthetic-private-filename.py"
        (self.source / file_name).write_text("bad syntax @\n", encoding="utf-8")
        report = self.run_protected(local_locations=True)
        archive = self.output / report["run_id"]
        locations = archive / "locations.json"
        require_private(locations)
        self.assertNotIn(file_name, json.dumps(report))
        self.assertEqual(file_name, resolve_local_finding(archive, "source-001"))
        locations.write_text('{"source-001":"replacement.py"}', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            resolve_local_finding(archive, "source-001")
