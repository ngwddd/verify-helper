# -*- coding: utf-8 -*-
"""SARIF 2.1.0 输出。

为什么要它：SARIF 是 OASIS 标准，GitHub Code Scanning 直接吃这个格式 ——
上传之后，每条告警会出现在 PR 的 diff 行内，而不是躺在某个日志里没人看。
我们的 JSON 只有自己认，SARIF 是所有代码托管平台都认。

只做映射，不做裁剪：检查判定逻辑一行都不改，只在输出层换一种表示。
"""
from __future__ import annotations

import json
from pathlib import Path

import check_specs as S

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "verify-helper"
TOOL_URI = "https://github.com/ngwddd/verify-helper"


def _rule(spec: S.CheckSpec) -> dict:
    rule = {
        "id": spec.id,
        "name": spec.title,
        "shortDescription": {"text": spec.title},
        "fullDescription": {"text": spec.doc},
        "defaultConfiguration": {"level": S.SARIF_LEVEL[spec.risk]},
        "properties": {
            "risk": spec.risk,
            "blocking": spec.blocking,
            "remediation": spec.remediation,
            "tags": [spec.category],
        },
        "help": {"text": f"{spec.doc}\n\n怎么改：{spec.remediation}",
                 "markdown": f"**{spec.title}**（风险：{S.RISK_LABEL[spec.risk]}）\n\n"
                             f"{spec.doc}\n\n**怎么改**：{spec.remediation}"},
    }
    if spec.refs:
        rule["properties"]["references"] = list(spec.refs)
    return rule


def _level(check: dict, finding: dict) -> str:
    sev = finding.get("severity") or check.get("risk") or "medium"
    return S.SARIF_LEVEL.get(sev, "warning")


def _result(project: Path, check: dict, finding: dict) -> dict:
    spec = S.get(check["id"])
    msg = finding.get("message") or check.get("detail") or spec.title
    res = {
        "ruleId": check["id"],
        "ruleIndex": 0,                      # 后面统一回填
        "level": _level(check, finding),
        "message": {"text": f"{msg}"},
        "properties": {
            "check": check["id"],
            "risk": check.get("risk", spec.risk),
            "state": check.get("state"),
        },
    }
    f = finding.get("file")
    line = finding.get("line") or 0
    if f:
        try:
            uri = (Path(f) if Path(f).is_absolute() else Path(f)).as_posix()
        except Exception:
            uri = str(f)
        loc = {"physicalLocation": {"artifactLocation": {"uri": uri}}}
        if line > 0:
            loc["physicalLocation"]["region"] = {"startLine": int(line)}
        res["locations"] = [loc]
    else:
        # 没有具体文件（例如测试套件整体失败）：把位置指到项目根
        res["locations"] = [{"physicalLocation": {
            "artifactLocation": {"uri": project.name or ".", "uriBaseId": "%SRCROOT%"},
        }}]
    return res


def to_sarif(report: dict, version: str = "1.1.0") -> dict:
    """把 verify_core 的报告转成 SARIF 2.1.0。"""
    project = Path(report.get("project", "."))

    used: list[S.CheckSpec] = []
    for c in report.get("checks", []):
        if c.get("state") == "PASS":
            continue                        # 通过的检查不进 results，但 rule 仍登记
        spec = S.get(c["id"])
        if spec.id not in [s.id for s in used]:
            used.append(spec)
    for c in report.get("checks", []):      # 通过的也登记 rule，方便平台按规则统计
        spec = S.get(c["id"])
        if spec.id not in [s.id for s in used]:
            used.append(spec)

    index = {s.id: i for i, s in enumerate(used)}

    results = []
    for c in report.get("checks", []):
        if c.get("state") == "PASS":
            continue
        if not c.get("applicable", True):
            continue                        # 「项目里没有这类文件」不是问题，不该进 SARIF
        findings = c.get("findings") or []
        if findings:
            for f in findings:
                r = _result(project, c, f)
                r["ruleIndex"] = index.get(c["id"], 0)
                results.append(r)
        else:
            # 检查整体失败但没有逐条位置（例如测试退出码非 0）
            r = _result(project, c, {"message": c.get("detail") or c.get("title", "")})
            r["ruleIndex"] = index.get(c["id"], 0)
            results.append(r)

    run = {
        "tool": {"driver": {
            "name": TOOL_NAME,
            "version": version,
            "informationUri": TOOL_URI,
            "rules": [_rule(s) for s in used],
        }},
        "results": results,
        "invocations": [{
            "executionSuccessful": report.get("verdict") != "FAIL",
            "endTimeUtc": report.get("started", "") + "Z",
        }],
        "properties": {
            "verdict": report.get("verdict"),
            "files": report.get("files"),
            "seconds": report.get("seconds"),
        },
    }
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [run],
    }


def dumps(report: dict, version: str = "1.1.0", indent: int = 2) -> str:
    return json.dumps(to_sarif(report, version), ensure_ascii=False, indent=indent)
