"""Project-controlled values cross the report boundary through a fixed schema."""
from __future__ import annotations

import re

import check_specs
import sarif
from run_evidence import plan_digest, set_gate_fields


VERDICTS = {"PASS", "FAIL", "UNKNOWN"}
REASONS = {"JAVASCRIPT_SYNTAX_UNAVAILABLE", "ISOLATION_UNAVAILABLE",
           "ISOLATED_TEST_ORACLE_UNVERIFIED", "ISOLATED_PROCESS_NONZERO",
           "UNSUPPORTED_ISOLATED_ADAPTER", "CUSTOM_RULE_BUDGET_EXCEEDED",
           "BEHAVIOR_CONTRACT_UNAVAILABLE", "BEHAVIOR_CONTRACT_MATCHED", "BEHAVIOR_CONTRACT_MISMATCH",
           "BEHAVIOR_CONTRACT_INCOMPLETE", "GIT_MERGE_CONFLICT", "GIT_SNAPSHOT_UNAVAILABLE"}
PUBLIC_CHECKS = frozenset(check_specs.ordered_ids()) | {
    "execution-isolation", "scan-coverage", "configuration", "behavior-contract", "git-snapshot",
}


def project_receipts(report: dict, *, locations: dict | None = None) -> dict:
    """Build exportable receipts without project filenames, diagnostics, or media."""
    checks = report["checks"]
    plan = report["plan"]
    ids = {}
    for identifier in [*(row["id"] for row in checks), *plan]:
        if identifier not in ids:
            ids[identifier] = identifier if identifier in PUBLIC_CHECKS else f"check-{len(ids) + 1:03}"
    public_plan = {ids[key]: "Required verification check" for key in plan}
    public_checks = []
    aliases = {}
    for row in checks:
        identifier = ids[row["id"]]
        state = row.get("state")
        public = {"id": identifier, "title": check_specs.get(identifier).title,
                  "state": state if state in VERDICTS else "UNKNOWN",
                  "applicable": row.get("applicable") is True,
                  "blocking": row.get("blocking") is True}
        reason = row.get("reason_code")
        if reason in REASONS:
            public["reason_code"] = reason
        if identifier == "syntax" and state == "FAIL":
            findings = []
            for finding in (row.get("findings") or [])[:100]:
                file, line = finding.get("file"), finding.get("line")
                if isinstance(file, str) and type(line) is int and 0 < line <= 1_000_000:
                    alias = aliases.setdefault(file, f"source-{len(aliases) + 1:03}")
                    if locations is not None:
                        locations[alias] = file
                    findings.append({"file": alias, "line": line,
                                     "message": "SOURCE_SYNTAX_INVALID"})
            if findings:
                public["findings"] = findings
                public["remediation"] = "Check the source syntax at the reported line."
        coverage = row.get("coverage")
        if coverage and all(type(coverage.get(key, 0)) is int and 0 <= coverage.get(key, 0) <= 200_000
                            for key in ("planned", "observed", "skipped")):
            public["coverage"] = {key: coverage.get(key, 0) for key in ("planned", "observed", "skipped")}
        isolation = row.get("isolation_receipt")
        if isinstance(isolation, dict):
            version = isolation.get("engine_version")
            image = isolation.get("image_digest")
            time_limit = isolation.get("time_limit_seconds")
            if (isinstance(version, str) and re.fullmatch(r"[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}", version)
                    and isinstance(image, str) and re.fullmatch(r"sha256:[a-f0-9]{64}", image)
                    and type(time_limit) is int and 5 <= time_limit <= 180):
                public["isolation_receipt"] = {
                    "provider": "docker-local-linux", "engine_version": version, "image_digest": image,
                    "uid": 65532, "network": "none", "host_bind_mounts": 0, "time_limit_seconds": time_limit,
                    "root_filesystem_read_only": True, "credential_environment": "minimal",
                    "verified": False,
                }
        public_checks.append(public)
    return {"checks": public_checks, "plan": public_plan, "plan_digest": plan_digest(public_plan),
            "export_policy": "sealed"}


def mcp_report(report: dict, run_id: str, version: str) -> dict:
    """Rebuild the response after archive verification, including for older archives."""
    public = project_receipts(report)
    for row, source in zip(public["checks"], report["checks"], strict=True):
        receipt = source.get("evidence_ref")
        digest = source.get("evidence_sha256")
        if (isinstance(receipt, str) and re.fullmatch(r"check-[0-9]{3,6}\.json", receipt)
                and isinstance(digest, str) and re.fullmatch(r"[a-f0-9]{64}", digest)):
            row.update(evidence_ref=receipt, evidence_sha256=digest)
    status = report.get("status")
    verdict = report.get("verdict")
    security = report.get("security_status")
    public.update(schema_version=2, run_id=run_id, version=version,
                  status=status if status in {"COMPLETED", "CANCELLED", "ERROR"} else "ERROR",
                  verdict=verdict if verdict in VERDICTS else "UNKNOWN")
    public["security_status"] = security if security in {"ENFORCED", "VIOLATED", "NOT_REQUIRED"} else "UNAVAILABLE"
    public["target_kind"] = "file" if report.get("target_kind") == "file" else "project"
    if public["security_status"] == "UNAVAILABLE":
        reason = report.get("reason_code")
        public["reason_code"] = reason if reason == "GIT_SNAPSHOT_UNAVAILABLE" else "ISOLATION_UNAVAILABLE"
    omitted = report.get("protected_input")
    if isinstance(omitted, dict) and type(omitted.get("excluded_count")) is int:
        public["protected_input"] = {"reason_code": "PROTECTED_INPUT_EXCLUDED",
                                     "excluded_count": min(200_000, max(0, omitted["excluded_count"]))}
    if report.get("evidence_manifest") == "manifest.json":
        public["evidence_manifest"] = "manifest.json"
    set_gate_fields(public)
    public["releasable"] = public["releasable"] and report.get("releasable") is True
    public["sarif"] = sarif.to_sarif(public, version)
    return public
