"""Protected object-store verification against clean, dirty and merged trees."""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from full_verify import full_verify
from run_evidence import read_evidence


@unittest.skipUnless(shutil.which("git"), "A Git toolchain is required")
class TestProtectedGit(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name)
        self.repo = self.base / "source"
        self.repo.mkdir()
        self.run_git("init", "-qb", "main")
        self.run_git("config", "core.autocrlf", "false")
        self.write("entry.py", "value = 1\n")
        self.commit("initial")

    def run_git(self, *args):
        return subprocess.check_output(
            ["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", *args],
            cwd=self.repo, stderr=subprocess.DEVNULL, timeout=20,
        ).decode().strip()

    def write(self, name, value):
        (self.repo / name).write_bytes(value.encode())

    def commit(self, message):
        self.run_git("add", ".")
        self.run_git("commit", "-qm", message)
        return self.run_git("rev-parse", "HEAD")

    def verify(self, **options):
        return full_verify(self.repo, evidence_dir=self.base / "receipts", **options)

    def test_exact_revision_uses_packed_objects_and_requires_clean_input(self):
        head = self.run_git("rev-parse", "HEAD")
        self.run_git("gc", "--quiet")
        self.run_git("pack-refs", "--all")
        report = self.verify(revision=head)
        self.assertEqual(report["git"]["head"], head)
        self.assertFalse(report["git"]["dirty"])
        self.assertFalse(report["releasable"])
        self.write("entry.py", "value = 2\n")
        dirty = self.verify(revision=head)
        self.assertEqual(dirty["verdict"], "UNKNOWN")
        self.assertEqual(dirty["reason_code"], "GIT_SNAPSHOT_UNAVAILABLE")
        self.assertNotIn("snapshot_sha256", dirty)

    def test_merge_checks_target_tree_and_never_checks_out_the_base(self):
        self.run_git("switch", "-qc", "other")
        self.write("merge-only.py", "def broken(:\n")
        base = self.commit("add invalid source")
        self.run_git("switch", "-q", "main")
        self.write("README.md", "Head fixture\n")
        head = self.commit("add head documentation")
        report = self.verify(revision=head, against="other")
        self.assertEqual(report["verdict"], "FAIL")
        self.assertEqual(report["merge"]["base_commit"], base)
        self.assertNotEqual(report["merge"]["tree"], report["git"]["tree"])
        self.assertFalse((self.repo / "merge-only.py").exists())
        self.assertEqual(self.run_git("rev-parse", "HEAD"), head)

    def test_merge_conflict_and_missing_revision_do_not_fall_back(self):
        self.run_git("switch", "-qc", "other")
        self.write("entry.py", "value = 2\n")
        self.commit("other edit")
        self.run_git("switch", "-q", "main")
        self.write("entry.py", "value = 3\n")
        self.commit("main edit")
        conflict = self.verify(against="other")
        self.assertEqual(conflict["verdict"], "FAIL")
        self.assertTrue(conflict["merge_conflict"])
        archive = self.base / "receipts" / conflict["run_id"]
        self.assertEqual(read_evidence(archive)["checks"][0]["reason_code"], "GIT_MERGE_CONFLICT")
        missing = self.verify(revision="f" * 40)
        self.assertEqual(missing["reason_code"], "GIT_SNAPSHOT_UNAVAILABLE")
        self.assertEqual(missing["verdict"], "UNKNOWN")
