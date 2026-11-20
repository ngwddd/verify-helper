"""Cross-platform checks for the protected entry point and sealed report."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from full_verify import full_verify
from isolated_runtime import IMAGE_VARIABLE, BoundaryUnavailable, run_isolated
from report_export import mcp_report
from run_evidence import read_evidence


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

    def test_private_inputs_and_invalid_image_do_not_fall_back_to_host(self):
        witness = self.base / "host-witness"
        (self.source / "test_app.py").write_text(
            "import unittest\nfrom pathlib import Path\n"
            "class Fixture(unittest.TestCase):\n"
            f"    def test_run(self): Path({str(witness)!r}).touch()\n", encoding="utf-8")
        (self.source / ".env.fixture").write_text("synthetic private input", encoding="utf-8")
        with patch.dict(os.environ, {IMAGE_VARIABLE: "invalid-image"}):
            report = self.run_protected(trusted=True)
        self.assertFalse(witness.exists())
        self.assertEqual(report["verdict"], "UNKNOWN")
        self.assertFalse(report["releasable"])
        self.assertIn("ISOLATION_UNAVAILABLE", {row.get("reason_code") for row in report["checks"]})
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

    def test_no_project_runtime_in_mcp_without_isolation(self):
        witness = self.base / "host-witness"
        (self.source / "test_app.py").write_text(
            f"from pathlib import Path\nPath({str(witness)!r}).touch()\n", encoding="utf-8")
        with patch.dict(os.environ):
            os.environ.pop(IMAGE_VARIABLE, None)
            report = self.run_protected(trusted=True, sealed=True)
        self.assertFalse(witness.exists())
        self.assertEqual(report["verdict"], "UNKNOWN")

    def test_invalid_image_is_refused_before_launch(self):
        with patch("isolated_runtime.subprocess.Popen") as launch:
            with self.assertRaises(BoundaryUnavailable):
                run_isolated(self.source, Path("."), ["/usr/local/bin/python"], "python:latest", lambda: False)
            launch.assert_not_called()

    def test_snapshot_omits_hardlink_to_host_file(self):
        witness = self.base / "host-witness"
        witness.write_text("synthetic private hardlink target", encoding="utf-8")
        os.link(witness, self.source / "alias.txt")
        (self.source / "app.py").write_text("value = 1\n", encoding="utf-8")
        report = self.run_protected()
        self.assertEqual(report["verdict"], "UNKNOWN")
        self.assertIn("Source snapshot contains omitted or changed entries", report["blockers"])
        self.assertNotIn("alias.txt", json.dumps(report))
