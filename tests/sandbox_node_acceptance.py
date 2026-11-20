"""Real offline JavaScript smoke cases using the pinned Node image."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from full_verify import _snapshot, full_verify
from private_storage import private_write
from protected_oracle import POLICY_VARIABLE


class TestNodeGuest(unittest.TestCase):
    def test_javascript_syntax_and_operator_behavior(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            source = base / "project"
            source.mkdir()
            entry = source / "entry.mjs"
            entry.write_text("console.log(Number(process.argv[2]) * 2);\n", encoding="utf-8")
            fingerprint, omitted = _snapshot(source, base / "snapshot", protected=True)
            self.assertFalse(omitted)
            policy = base / "operator.json"
            private_write(policy, json.dumps({
                "project": str(source),
                "snapshot_sha256": fingerprint,
                "entry": "entry.mjs",
                "cases": [
                    {"argv": ["2"], "stdout": "4\n", "exit_code": 0},
                    {"argv": ["6"], "stdout": "12\n", "exit_code": 0},
                ],
            }).encode())
            with patch.dict(os.environ, {POLICY_VARIABLE: str(policy)}):
                report = full_verify(source, evidence_dir=base / "evidence")
            rows = {row["id"]: row for row in report["checks"]}
            self.assertEqual(rows["syntax"]["state"], "PASS", rows["syntax"])
            self.assertEqual(rows["behavior-contract"]["state"], "PASS", rows["behavior-contract"])
            self.assertEqual(rows["behavior-contract"]["coverage"]["observed"], 2)
            self.assertFalse(report["releasable"])
            entry.write_text("const invalid = ;\n", encoding="utf-8")
            broken = full_verify(source, evidence_dir=base / "evidence")
            syntax = next(row for row in broken["checks"] if row["id"] == "syntax")
            self.assertEqual(syntax["state"], "FAIL")
            self.assertEqual(broken["verdict"], "FAIL")
