"""Verify the release gate with ephemeral test-only signatures."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from release_approval import ASSETS, CHECKS, MATRICES, REPORTS, verify
from run_evidence import plan_digest


class TestReleaseGate(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.commit = "a" * 40
        self.key = Ed25519PrivateKey.generate()
        self.public = self.root / "reviewer.pem"
        self.public.write_bytes(self.key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
        self.payload = self.root / "approval.json"
        self.signature = self.root / "approval.sig"
        self.assets = self.root / "assets"
        self.assets.mkdir()
        for name in ASSETS - {"SHA256SUMS", "provenance.json", "sbom.cdx.json"}:
            (self.assets / name).write_bytes(b"synthetic test-only distribution")
        self.write(self.assets / "sbom.cdx.json", {"bomFormat": "CycloneDX", "components": [{"name": "fixture"}]})
        self.write(self.assets / "provenance.json", {
            "version": "2.0.0", "commit": self.commit, "workflow_run": "123",
            "sbom_sha256": self.sha(self.assets / "sbom.cdx.json"),
        })
        hashes = [f"{self.sha(self.assets / name)} *{name}" for name in ASSETS - {"SHA256SUMS", "provenance.json"}]
        (self.assets / "SHA256SUMS").write_text("\n".join(hashes), encoding="ascii")
        self.approval = {
            "schema_version": 1, "repository": "ngwddd/verify-helper", "version": "2.0.0",
            "commit": self.commit, "verdict": "GO", "open_blockers": [], "workflow_run": "123",
            "security_tests": dict.fromkeys(CHECKS, "PASS"), "matrices": dict.fromkeys(MATRICES, "PASS"),
            "assets": {name: self.sha(self.assets / name) for name in ASSETS}, "reports": {},
        }
        for platform, filename in REPORTS.items():
            plan = {"tests": "Required"}
            path = self.root / filename
            self.write(path, {
                "platform": platform, "version": "2.0.0", "status": "COMPLETED", "scope": "FULL",
                "mode": "full", "verdict": "PASS", "security_status": "ENFORCED", "releasable": True,
                "git": {"head": self.commit, "dirty": False}, "snapshot_sha256": "b" * 64, "plan": plan,
                "plan_digest": plan_digest(plan), "evidence_manifest": "manifest.json",
                "ledger": [{"check_id": "tests", "required": True, "verdict": "PASS", "execution": "EXECUTED",
                            "eligible": 1, "executed": 1, "skipped": 0, "not_run": 0, "evidence_refs": ["test.json"]}],
            })
            self.approval["reports"][platform] = self.sha(path)

    @staticmethod
    def write(path, obj):
        path.write_text(json.dumps(obj), encoding="utf-8")

    @staticmethod
    def sha(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def sign(self):
        self.write(self.payload, self.approval)
        self.signature.write_bytes(self.key.sign(self.payload.read_bytes()))

    def check(self):
        verify(self.commit, self.assets, self.root, self.payload, self.signature, self.public)

    def test_exact_approval_then_changed_asset(self):
        self.sign()
        self.check()
        (self.assets / "sbom.cdx.json").write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "assets differ"):
            self.check()

    def test_modified_approval_invalidates_signature(self):
        self.sign()
        self.payload.write_bytes(self.payload.read_bytes() + b" ")
        with self.assertRaises(InvalidSignature):
            self.check()

    def test_signed_skip_never_satisfies_release_requirements(self):
        self.approval["security_tests"]["L18"] = "SKIPPED"
        self.sign()
        with self.assertRaisesRegex(ValueError, "acceptance is incomplete"):
            self.check()
        self.approval["security_tests"]["L18"] = "PASS"
        path = self.root / "windows.json"
        report = json.loads(path.read_bytes())
        report["security_status"] = "UNAVAILABLE"
        self.write(path, report)
        self.approval["reports"]["Windows"] = self.sha(path)
        self.sign()
        with self.assertRaisesRegex(ValueError, "lacks an eligible protected full report"):
            self.check()
