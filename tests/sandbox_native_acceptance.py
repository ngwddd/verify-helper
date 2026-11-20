"""Execute C and C++ source fixtures in the pinned offline GCC guest."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from full_verify import _snapshot, full_verify
from private_storage import private_write
from protected_oracle import POLICY_VARIABLE


class TestNativeGuest(unittest.TestCase):
    def test_native_single_source_matches_only_the_reviewed_behavior(self):
        examples = {
            "entry.c": '#include <stdio.h>\nint main(int n, char **a) { puts(n > 1 ? a[1] : "empty"); }\n',
            "entry.cpp": '#include <iostream>\nint main(int n, char **a) { std::cout << a[1] << "\\n"; }\n',
        }
        for name, program in examples.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary).resolve()
                source = base / "source"
                source.mkdir()
                (source / name).write_text(program, encoding="utf-8")
                snapshot, omitted = _snapshot(source, base / "snapshot", protected=True)
                self.assertFalse(omitted)
                policy = base / "oracle.json"
                cases = [{"argv": [value], "stdout": value + "\n", "exit_code": 0}
                         for value in ("first", "second")]
                data = {"project": str(source), "snapshot_sha256": snapshot, "entry": name, "cases": cases}
                private_write(policy, json.dumps(data).encode())
                with patch.dict(os.environ, {POLICY_VARIABLE: str(policy)}):
                    report = full_verify(source, evidence_dir=base / "evidence")
                    result = next(row for row in report["checks"] if row["id"] == "behavior-contract")
                    self.assertEqual(result["state"], "PASS", result)
                    self.assertEqual(result["coverage"]["observed"], 2)
                    self.assertFalse(report["releasable"])
                    cases[1]["stdout"] = "expected mismatch\n"
                    private_write(policy, json.dumps(data).encode())
                    report = full_verify(source, evidence_dir=base / "evidence")
                    result = next(row for row in report["checks"] if row["id"] == "behavior-contract")
                    self.assertEqual(result["state"], "FAIL", result)
                    self.assertEqual(report["verdict"], "FAIL")
