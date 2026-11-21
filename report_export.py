"""Project-controlled values cross the report boundary through a fixed schema."""
from __future__ import annotations

import re

import check_specs
import sarif
from run_evidence import plan_digest, set_gate_fields


VERDICTS = {"PASS", "FAIL", "UNKNOWN"}
REASONS = {"JAVASCRIPT_SYNTAX_UNAVAILABLE", "ISOLATION_UNAVAILABLE",
           "ISOLATED_TEST_ORACLE_UNVERIFIED", "ISOLATED_PROCESS_NONZERO",
           "UNSUPPORTED_ISOLATED_ADAPTER", "CUSTOM_RULE_BUDGET_EXCEEDED", "EXECUTION_NOT_RUN", "NO_TEST_ENTRY",
           "TEST_RUNTIME_UNAVAILABLE", "TEST_TIMEOUT_OR_CANCELLED", "TEST_COVERAGE_MISSING", "TEST_OUTPUT_LIMIT",
           "TESTS_DESELECTED",
           "MISSING_BROWSER_DEPENDENCY",
           "BEHAVIOR_CONTRACT_UNAVAILABLE", "BEHAVIOR_CONTRACT_MATCHED", "BEHAVIOR_CONTRACT_MISMATCH",
           "BEHAVIOR_CONTRACT_INCOMPLETE", "GIT_MERGE_CONFLICT", "GIT_SNAPSHOT_UNAVAILABLE"}
PUBLIC_CHECKS = frozenset(check_specs.ordered_ids()) | {
    "execution-isolation", "scan-coverage", "configuration", "behavior-contract", "git-snapshot",
    "tests-python", "tests-javascript", "typescript", "build-native", "runtime-native", "tests-native",
}
FINDING_KINDS = {"syntax": "SOURCE_SYNTAX_INVALID", "tests": "TEST_FAILURE",
                 "tests-python": "TEST_FAILURE", "tests-javascript": "TEST_FAILURE"}
SOURCE_ALIAS = re.compile(r"source-(?:[0-9]{3,6}|h[0-9a-f]{32})")


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
    sealed = report.get("export_policy") == "sealed"
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
        if state == "FAIL":
            findings = []
            for finding in (row.get("findings") or [])[:100]:
                file, line = finding.get("file"), finding.get("line")
                if not isinstance(file, str) or type(line) is not int or not 0 < line <= 1_000_000:
                    continue
                if sealed:
                    finding_code = finding.get("message")
                    if finding_code not in FINDING_KINDS.values() or not SOURCE_ALIAS.fullmatch(file):
                        continue
                    alias = file
                else:
                    finding_code = FINDING_KINDS.get(row["id"].rsplit(":", 1)[-1])
                    if not finding_code:
                        continue
                    alias = aliases.setdefault(file, f"source-{len(aliases) + 1:03}")
                    if locations is not None:
                        locations[alias] = file
                findings.append({"file": alias, "line": line, "message": finding_code})
            if findings:
                public["findings"] = findings
                public["remediation"] = ("Check the source syntax at the reported line." if identifier == "syntax"
                                         else "Inspect the failing test and assertion at the reported line.")
        coverage = row.get("coverage")
        keys = ("planned", "observed", "skipped", "planned_files", "observed_files", "collected", "deselected")
        if coverage and all(type(coverage.get(key, 0)) is int and 0 <= coverage.get(key, 0) <= 200_000
                            for key in keys):
            public["coverage"] = {key: coverage.get(key, 0) for key in keys
                                  if key in coverage or key in ("planned", "observed", "skipped")}
        if type(row.get("exit_code")) is int and -65536 <= row["exit_code"] <= 65536:
            public["exit_code"] = row["exit_code"]
        version = row.get("runtime_version")
        if isinstance(version, str) and re.fullmatch(r"[0-9]{1,4}(?:\.[0-9]{1,4}){2}", version):
            public["runtime_version"] = version
        if type(row.get("unregistered_candidates")) is int and 0 < row["unregistered_candidates"] <= 200000:
            public["unregistered_candidates"] = row["unregistered_candidates"]
        seconds = row.get("seconds")
        if type(seconds) in (int, float) and 0 <= seconds <= 3600:
            public["duration_ms"] = round(seconds * 1000)
        elif type(row.get("duration_ms")) is int and 0 <= row["duration_ms"] <= 3600000:
            public["duration_ms"] = row["duration_ms"]
        public_checks.append(public)
    return {"checks": public_checks, "plan": public_plan, "plan_digest": plan_digest(public_plan),
            "export_policy": "sealed"}


def mcp_report(report: dict, run_id: str, version: str) -> dict:
    """Rebuild the response after archive verification, including for older archives."""
    public = project_receipts(report)
    for row, source in zip(public["checks"], report["checks"], strict=True):
        if source.get("media"):
            row["media_count"] = len(source["media"])
        receipt = source.get("evidence_ref")
        digest = source.get("evidence_sha256")
        if (isinstance(receipt, str) and re.fullmatch(r"check-[0-9]{3,6}\.json", receipt)
                and isinstance(digest, str) and re.fullmatch(r"[a-f0-9]{64}", digest)):
            row.update(evidence_ref=receipt, evidence_sha256=digest)
    status = report.get("status")
    verdict = report.get("verdict")
    security = report.get("security_status")
    public.update(schema_version=2, run_id=run_id, version=report.get("version", version),
                  status=status if status in {"COMPLETED", "CANCELLED", "ERROR"} else "ERROR",
                  verdict=verdict if verdict in VERDICTS else "UNKNOWN")
    public["security_status"] = security if security in {"ENFORCED", "VIOLATED", "NOT_REQUIRED"} else "UNAVAILABLE"
    public["target_kind"] = "file" if report.get("target_kind") == "file" else "project"
    if report.get("execution_mode") in {"local-host", "static"}:
        public["execution_mode"] = report["execution_mode"]
        public["security_assurance"] = "NOT_PROVIDED"
        public["isolation_enforced"] = False
        if re.fullmatch(r"[0-9.]+", report.get("python", "")):
            public["python_version"] = report["python"]
    if report.get("reason_code") == "GIT_SNAPSHOT_UNAVAILABLE":
        public["reason_code"] = "GIT_SNAPSHOT_UNAVAILABLE"
    if report.get("dependency_assurance") == "HOST_UNPINNED":
        public["dependency_assurance"] = "HOST_UNPINNED"
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
