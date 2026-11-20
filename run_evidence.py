"""Build and recheck the evidence graph for a full verification run."""
from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_bytes(value: dict) -> bytes:
    return json.dumps(value, ensure_ascii=False, indent=2).encode("utf-8")


def plan_digest(plan: dict) -> str:
    return "sha256:" + digest(json.dumps(plan, sort_keys=True, ensure_ascii=True).encode("ascii"))


def set_gate_fields(report: dict) -> None:
    verdict = report["verdict"]
    report["scope"] = "FULL"
    report.setdefault("status", "COMPLETED")
    ledger = []
    counts = {"required": len(report["plan"]), "passed": 0, "failed": 0, "unknown": 0}
    outcomes = {"PASS": "passed", "FAIL": "failed", "UNKNOWN": "unknown"}
    for row in report["checks"]:
        identifier = row["id"]
        required = identifier in report["plan"]
        applicable = row.get("applicable", False)
        outcome = row["state"]
        evidence = [row["evidence_ref"]] if row.get("evidence_sha256") else []
        coverage = row.get("coverage") or {}
        executed = coverage.get("observed", int(applicable and outcome != "UNKNOWN"))
        skipped = coverage.get("skipped", 0)
        eligible = max(coverage.get("planned", 0), executed + skipped, int(applicable))
        missing = eligible - executed - skipped
        if not applicable:
            execution, reason = "NOT_RUN", "NOT_APPLICABLE"
        elif outcome == "UNKNOWN" and not executed:
            execution, reason = "UNAVAILABLE", row.get("reason_code") or "REQUIRED_EVIDENCE_UNAVAILABLE"
        elif missing or skipped:
            execution, reason = "PARTIAL", "COVERAGE_INCOMPLETE"
        else:
            execution, reason = "EXECUTED", "CHECK_" + outcome
        if required:
            gate_state = "UNKNOWN" if outcome == "PASS" and (missing or skipped or not evidence) else outcome
            counts[outcomes[gate_state]] += 1
        ledger.append({"check_id": identifier, "required": required,
                       "applicability": "APPLICABLE" if applicable else "NOT_APPLICABLE",
                       "execution": execution, "verdict": outcome, "reason_code": reason,
                       "oracle": row.get("command") or report["plan"].get(identifier),
                       "eligible": eligible, "executed": executed, "skipped": skipped,
                       "not_run": missing, "evidence_refs": evidence})
    counts["unknown"] += counts["required"] - sum(counts[key] for key in outcomes.values())
    report["ledger"] = ledger
    report["coverage"] = counts
    report["releasable"] = (
        verdict == "PASS" and report["status"] == "COMPLETED"
        and report.get("security_status", "ENFORCED") == "ENFORCED"
    )


def write_manifest(report: dict, output: Path, *, key: bytes | None = None) -> None:
    report["evidence_manifest"] = "manifest.json"
    records = {"results.sarif": digest((output / "results.sarif").read_bytes())}
    for row in report["checks"]:
        if row.get("evidence_sha256"):
            records[row["evidence_ref"]] = row["evidence_sha256"]
        for media in row.get("media", ()):
            records[media["path"]] = media["sha256"]
    body = json_bytes(report)
    records["report.json"] = digest(body)
    manifest = {"run_id": report["run_id"], "snapshot_sha256": report.get("snapshot_sha256"),
                "policy_digest": report["policy_digest"], "plan_digest": report["plan_digest"], "files": records}
    if key is not None:
        manifest["hmac_sha256"] = hmac.digest(key, json_bytes(manifest), "sha256").hex()
    pending = output / "report.json.tmp"
    pending.write_bytes(body)
    (output / "manifest.json").write_bytes(json_bytes(manifest))
    pending.replace(output / "report.json")


def read_evidence(output: Path, *, key: bytes | None = None) -> dict:
    manifest_path = output / "manifest.json"
    if manifest_path.is_symlink():
        raise ValueError("Evidence manifest is not a regular file")
    manifest = json.loads(manifest_path.read_bytes())
    if not isinstance(manifest, dict):
        raise ValueError("Evidence manifest must be an object")
    signature = manifest.pop("hmac_sha256", None)
    if key is not None:
        expected = hmac.digest(key, json_bytes(manifest), "sha256").hex()
        if not isinstance(signature, str) or not hmac.compare_digest(signature.encode("utf-8"), expected.encode("ascii")):
            raise ValueError("Evidence authentication failed")
    elif signature is not None:
        raise ValueError("Evidence authentication key is required")
    records = manifest.get("files")
    if not isinstance(records, dict) or not {"report.json", "results.sarif"} <= records.keys():
        raise ValueError("Evidence manifest is incomplete")
    for name, expected in records.items():
        if not name or name != Path(name).name or "/" in name or "\\" in name or ":" in name:
            raise ValueError("Evidence manifest contains an invalid path")
        path = output / name
        if not path.is_file() or path.is_symlink() or digest(path.read_bytes()) != expected:
            raise ValueError("Evidence digest mismatch or missing receipt")
    body = (output / "report.json").read_bytes()
    if digest(body) != records["report.json"]:
        raise ValueError("Evidence report changed while it was being read")
    report = json.loads(body)
    if (report["run_id"] != manifest["run_id"] or report.get("snapshot_sha256") != manifest["snapshot_sha256"]
            or report["policy_digest"] != manifest["policy_digest"]):
        raise ValueError("Evidence manifest is bound to a different run")
    if "plan_digest" in manifest and (
            report.get("plan_digest") != manifest["plan_digest"]
            or plan_digest(report["plan"]) != manifest["plan_digest"]):
        raise ValueError("Evidence manifest does not match the verification plan")
    for row in report["checks"]:
        name = row.get("evidence_ref")
        if row.get("evidence_sha256") and records.get(name) != row["evidence_sha256"]:
            raise ValueError("Evidence receipt is missing from the manifest")
        for media in row.get("media", ()):
            if records.get(media["path"]) != media["sha256"]:
                raise ValueError("Media receipt is missing from the manifest")
    return report
