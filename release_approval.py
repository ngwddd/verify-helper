"""Verify a detached independent release approval before creating the stable tag."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from run_evidence import plan_digest


VERSION = "2.0.0"
REPOSITORY = "ngwddd/verify-helper"
ASSETS = {"verify_helper-2.0.0-py3-none-any.whl", "verify_helper-2.0.0.tar.gz",
          "sbom.cdx.json", "SHA256SUMS", "provenance.json"}
CHECKS = {f"L{number:02}" for number in range(1, 19)}
REPORTS = {"Linux": "linux.json", "Windows": "windows.json"}
MATRICES = {"language_adapters", "git_and_real_projects", "desktop_agents", "independent_evidence"}


def _hash(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        raise ValueError("Expected a regular release file")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _review(approval: Path, signature: Path, public_key: Path) -> dict:
    if public_key.resolve(strict=True).is_relative_to(Path(__file__).resolve().parent):
        raise ValueError("Reviewer key must come from trusted storage outside the checkout")
    key = load_pem_public_key(public_key.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Independent reviewer key must use Ed25519")
    payload = approval.read_bytes()
    if len(payload) > 64 * 1024:
        raise ValueError("Approval is too large")
    key.verify(signature.read_bytes(), payload)
    return json.loads(payload)


def _verify_report(path: Path, operating_system: str, commit: str, expected_digest: str) -> None:
    if _hash(path) != expected_digest:
        raise ValueError("Full verification report does not match independent approval")
    report = json.loads(path.read_bytes())
    plan = report.get("plan", {})
    git = report.get("git", {})
    if (report.get("platform") != operating_system or report.get("version") != VERSION
            or report.get("status") != "COMPLETED" or report.get("scope") != "FULL"
            or report.get("mode") != "full" or report.get("verdict") != "PASS"
            or report.get("security_status") != "ENFORCED" or report.get("releasable") is not True
            or git.get("head") != commit or git.get("dirty") is not False
            or not re.fullmatch(r"[a-f0-9]{64}", report.get("snapshot_sha256") or "")
            or not plan or report.get("plan_digest") != plan_digest(plan)
            or report.get("blockers") or report.get("evidence_manifest") != "manifest.json"):
        raise ValueError(f"{operating_system} lacks an eligible protected full report")
    rows = [row for row in report["ledger"] if row["required"]]
    if (len(rows) != len(plan) or {row["check_id"] for row in rows} != plan.keys()
            or any(row["verdict"] != "PASS" or row["execution"] != "EXECUTED"
                   or not row["eligible"] or row["executed"] != row["eligible"]
                   or row["skipped"] or row["not_run"] or not row["evidence_refs"] for row in rows)):
        raise ValueError(f"{operating_system} has incomplete required coverage")


def verify(commit: str, assets: Path, evidence: Path, approval: Path, signature: Path, public_key: Path) -> None:
    if not re.fullmatch(r"[a-f0-9]{40}", commit):
        raise ValueError("Candidate must be an exact Git commit")
    signed = _review(approval, signature, public_key)
    if (signed.get("schema_version") != 1 or signed.get("repository") != REPOSITORY
            or signed.get("version") != VERSION or signed.get("commit") != commit
            or signed.get("verdict") != "GO" or signed.get("open_blockers") != []):
        raise ValueError("Independent review has not approved this release")
    for name, required in (("security_tests", CHECKS), ("matrices", MATRICES)):
        results = signed[name]
        if set(results) != required or set(results.values()) != {"PASS"}:
            raise ValueError("Independent acceptance is incomplete")
    approved_assets = signed["assets"]
    if set(approved_assets) != ASSETS or any(_hash(assets / name) != approved_assets[name] for name in ASSETS):
        raise ValueError("Release assets differ from the reviewed build")
    manifest = (assets / "SHA256SUMS").read_text(encoding="ascii").splitlines()
    expected_hashes = {f"{approved_assets[name]} *{name}" for name in ASSETS - {"SHA256SUMS", "provenance.json"}}
    if len(manifest) != len(expected_hashes) or set(manifest) != expected_hashes:
        raise ValueError("Checksum list does not cover the reviewed distributions and SBOM")
    sbom = json.loads((assets / "sbom.cdx.json").read_bytes())
    if sbom.get("bomFormat") != "CycloneDX" or not sbom.get("components"):
        raise ValueError("Reviewed build is missing its dependency SBOM")
    provenance = json.loads((assets / "provenance.json").read_bytes())
    if (provenance.get("commit") != commit or provenance.get("version") != VERSION
            or str(provenance.get("workflow_run")) != str(signed["workflow_run"])
            or not re.fullmatch(r"[1-9][0-9]*", str(signed["workflow_run"]))
            or provenance.get("sbom_sha256") != approved_assets["sbom.cdx.json"]):
        raise ValueError("Build provenance differs from the reviewed release")
    reports = signed["reports"]
    if set(reports) != REPORTS.keys():
        raise ValueError("Independent review must cover both platforms")
    for platform, filename in REPORTS.items():
        _verify_report(evidence / filename, platform, commit, reports[platform])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("commit")
    for argument in ("assets", "evidence", "approval", "signature", "public_key"):
        parser.add_argument(argument, type=Path)
    options = parser.parse_args()
    try:
        verify(**vars(options))
    except (OSError, ValueError, KeyError, TypeError, AttributeError, InvalidSignature) as error:
        parser.exit(2, f"Release gate denied approval ({type(error).__name__}).\n")
    print(f"Independent release approval verified for {options.commit}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
