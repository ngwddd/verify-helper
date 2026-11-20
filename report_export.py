"""Project-controlled values cross the report boundary through a fixed schema."""
from __future__ import annotations

import re

import check_specs
import sarif
from run_evidence import plan_digest, set_gate_fields


VERDICTS = {"PASS", "FAIL", "UNKNOWN"}
REASONS = {"JAVASCRIPT_SYNTAX_UNAVAILABLE", "ISOLATION_UNAVAILABLE",
           "ISOLATED_TEST_ORACLE_UNVERIFIED", "ISOLATED_PROCESS_NONZERO",
           "UNSUPPORTED_ISOLATED_ADAPTER"}
PUBLIC_CHECKS = frozenset(check_specs.ordered_ids()) | {"execution-isolation", "scan-coverage", "configuration"}


def project_receipts(report: dict) -> dict:
    """Build exportable receipts without project filenames, diagnostics, or media."""
    checks = report["checks"]
    plan = report["plan"]
    ids = {}
    for identifier in [*(row["id"] for row in checks), *plan]:
        if identifier not in ids:
            ids[identifier] = identifier if identifier in PUBLIC_CHECKS else f"check-{len(ids) + 1:03}"
    public_plan = {ids[key]: "Required verification check" for key in plan}
    public_checks = []
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
        coverage = row.get("coverage")
        if coverage and all(type(coverage.get(key, 0)) is int and 0 <= coverage.get(key, 0) <= 200_000
                            for key in ("planned", "observed", "skipped")):
            public["coverage"] = {key: coverage.get(key, 0) for key in ("planned", "observed", "skipped")}
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
    public.update(run_id=run_id, status=status if status in {"COMPLETED", "CANCELLED", "ERROR"} else "ERROR",
                  verdict=verdict if verdict in VERDICTS else "UNKNOWN")
    value = report.get("snapshot_sha256")
    if isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value):
        public["snapshot_sha256"] = value
    set_gate_fields(public)
    public["releasable"] = public["releasable"] and report.get("releasable") is True
    public["sarif"] = sarif.to_sarif(public, version)
    return public
