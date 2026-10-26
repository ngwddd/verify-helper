# -*- coding: utf-8 -*-
"""lifecycle.py —— 把「检查器」升级成「分层闸门」（v1.9）

原来 verify-helper 是一次性跑 15~17 项、给一个 PASS/FAIL/UNKNOWN。
这套东西的弱点不是检查项不够，而是**没有生命周期语义**：

  · 不知道这一轮属于哪一层（提交前 / PR / 合并 / 上线后）
  · 不知道这次变更有多危险（改动决定风险，不是项目决定风险）
  · 没有「这条我认了」的机制 —— 于是永远 FAIL，人就开始无视它
  · 不重复抑制、不判收敛 —— 每次都说同样的话，噪声吃掉信任
  · 没有回归集 —— 出过的事故不会变成下一次的自动检查

本模块补齐这十件事，全部是**纯后处理**（只读报告 dict + 读少量本地文件），
不改任何一项检查的实现，所以不会把原来的判定弄坏。

十个能力：
  ① 分层        STAGES / stage_checks() / gate()
  ② 风险 tier   diff_facts() / tier_of()
  ③ 证据留档    write_artifacts()
  ④ 接受机制    load_accepts() / save_accepts() / apply_accepts()
  ⑤ 噪声        noise_track()
  ⑥ 收敛        convergence()
  ⑦ 回归集      regression_rules() / apply_regression()
  ⑧ 合并队列    merge_probe()（由 CLI 传入的 worktree 路径驱动）
  ⑨ 安全层      security_layer()
  ⑩ 度量        metrics()

设计原则（跟文章一致）：
  · 判定只认证据：每条 finding 有稳定 id，接受必须写理由
  · 风险由**变更**决定，不由项目决定；敏感路径永远按最高档
  · 噪声要可测：记「人对它的反应」，而不是只数条数
  · 收敛优先：两轮不再变少就提示「别再刷了」
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import subprocess
import time
from pathlib import Path

VERSION = "1.10.4"

# ───────────────────────────── ① 分层 ─────────────────────────────
# 层不是「跑哪几项」这么简单，每层有它该拦的东西和该放的东西。
STAGES = {
    "precommit": {
        "title": "提交前",
        "purpose": "秒级反馈：语法、编码、密钥、未用 import、本机路径。挂 git hook 用。",
        "checks": ["syntax", "encoding", "bom", "secrets", "imports", "paths", "todos", "custom"],
        "blocking_risks": ["critical", "high"],
        "allow_unknown": True,
    },
    "pr": {
        "title": "PR",
        "purpose": "完整静态 + 运行时；按风险决定要不要人看。",
        "checks": None,                      # None = 默认全部
        "blocking_risks": ["critical", "high"],
        "allow_unknown": False,
    },
    "merge": {
        "title": "合并",
        "purpose": "全量再跑一次，且最好与目标分支组合后跑（--against）。",
        "checks": None,
        "blocking_risks": ["critical", "high"],
        "allow_unknown": False,
    },
    "postdeploy": {
        "title": "上线后",
        "purpose": "只跑运行时：页面 200、浏览器无异常、交互流程。",
        "checks": ["runtime-web", "browser", "interaction", "tests"],
        "blocking_risks": ["critical", "high"],
        "allow_unknown": True,
    },
}

STAGE_ALIASES = {"pre-commit": "precommit", "commit": "precommit", "post": "postdeploy",
                 "deploy": "postdeploy", "after": "postdeploy"}


def normalize_stage(stage: str | None) -> str:
    if not stage:
        return "pr"
    s = stage.strip().lower().replace("_", "-")
    s = STAGE_ALIASES.get(s, s.replace("-", ""))
    return s if s in STAGES else "pr"


def stage_checks(stage: str) -> list[str] | None:
    return STAGES[normalize_stage(stage)]["checks"]


# ─────────────────────── ② 风险 tier（由变更决定）───────────────────────
# 敏感路径：命中即 high，不管改动多小。
SENSITIVE_PATTERNS = [
    "auth/*", "*/auth/*", "login*", "password*", "oauth*", "token*",
    "billing/*", "*/billing/*", "payment*", "checkout*",
    ".github/workflows/*", "*.yml.example", "installer*", "install.*",
    "migrations/*", "*/migrations/*", "schema.sql",
    "release*", "publish*", "deploy*", "Dockerfile*", "docker-compose*",
    "*.pem", "*.key", "*.p12", "*.pfx",
]


def _git(root: Path, args: list[str], timeout: int = 30) -> tuple[int, str]:
    try:
        p = subprocess.run(["git", *args], cwd=str(root), capture_output=True,
                           text=True, encoding="utf-8", errors="replace", timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except Exception as e:
        return 1, f"{type(e).__name__}: {e}"


def diff_facts(root: Path, base: str | None = None) -> dict:
    """这次改了什么：文件、行数、是否命中敏感路径。

    没有 git、或没有任何改动时返回 no_git/no_diff，tier 由调用方决定怎么降级。
    """
    root = Path(root)
    if not (root / ".git").exists() and not (root.parent / ".git").exists():
        return {"no_git": True, "files": 0, "added": 0, "removed": 0,
                "paths": [], "sensitive": [], "base": ""}

    ref = base or "HEAD"
    # 已跟踪文件的改动（含暂存）
    code, out = _git(root, ["diff", "--numstat", ref])
    if code != 0:
        code, out = _git(root, ["diff", "--numstat", "HEAD~1"])
    files = added = removed = 0
    paths: list[str] = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        a, r, path = parts[0], parts[1], parts[2]
        files += 1
        try:
            added += int(a) if a != "-" else 0
            removed += int(r) if r != "-" else 0
        except ValueError:
            pass
        paths.append(path)

    # 未跟踪的新文件也算改动
    code, out2 = _git(root, ["ls-files", "--others", "--exclude-standard"])
    if code == 0:
        for path in [x.strip() for x in out2.splitlines() if x.strip()]:
            files += 1
            paths.append(path)
            try:
                added += len((root / path).read_text(encoding="utf-8", errors="ignore").splitlines())
            except Exception:
                pass

    sensitive = [p for p in paths
                 if any(fnmatch.fnmatch(p, pat) or fnmatch.fnmatch(p, "*" + pat)
                        for pat in SENSITIVE_PATTERNS)]
    return {"no_git": False, "files": files, "added": added, "removed": removed,
            "paths": sorted(set(paths))[:200], "sensitive": sorted(set(sensitive)),
            "base": ref, "no_diff": files == 0}


def tier_of(facts: dict, forced: str | None = None) -> dict:
    """变更 → low / medium / high，以及需要几个人。

    规则（写死，先严格；有证据再放宽 —— 跟文章一致）：
      high   : 命中敏感路径，或改动 ≥ 400 行，或改动文件 ≥ 25 个
      medium : 改动 ≥ 60 行，或文件 ≥ 6 个，或改了测试/配置
      low    : 其它
    没有 git 信息时给 medium：不知道改了什么，就不该自动放行。
    """
    if forced and forced in ("low", "medium", "high"):
        return {"tier": forced, "forced": True, "reasons": ["由调用方指定"],
                "human_approvals": {"low": 0, "medium": 1, "high": 2}[forced]}

    reasons: list[str] = []
    if facts.get("no_git"):
        return {"tier": "medium", "forced": False, "reasons": ["没有 git 信息，无法判断改动范围"],
                "human_approvals": 1}
    if facts.get("sensitive"):
        reasons.append("命中敏感路径：" + "、".join(facts["sensitive"][:5]))
    if facts.get("added", 0) + facts.get("removed", 0) >= 400:
        reasons.append(f"改动 {facts['added'] + facts['removed']} 行（≥400）")
    if facts.get("files", 0) >= 25:
        reasons.append(f"改动 {facts['files']} 个文件（≥25）")

    tier = "low"
    if reasons:
        tier = "high"
    elif facts.get("added", 0) + facts.get("removed", 0) >= 60 or facts.get("files", 0) >= 6:
        tier = "medium"
        reasons.append(f"改动 {facts.get('added', 0) + facts.get('removed', 0)} 行 / "
                       f"{facts.get('files', 0)} 个文件")
    elif facts.get("no_diff"):
        tier = "medium"
        reasons.append("没有检测到改动，保守按 medium")

    return {"tier": tier, "forced": False, "reasons": reasons,
            "human_approvals": {"low": 0, "medium": 1, "high": 2}[tier]}


# ─────────────────── ③ 证据留档（失败项的原始输出）───────────────────
def write_artifacts(report: dict, root: Path, keep: int = 20,
                    out_dir: str | None = None) -> dict:
    """把每条失败/未知检查的命令与输出落盘，报告里给路径。

    为什么要留档：文章里「读证据而不是读代码」。没有原始输出，
    下一个人只能重新跑一遍，或者相信"我看过了"。
    """
    root = Path(root)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    base = (Path(out_dir) if out_dir else root / ".verify-artifacts") / stamp
    written: list[str] = []
    try:
        for c in report.get("checks", []):
            if c.get("state") == "PASS":
                continue
            body = ["# " + c.get("id", "?"), "state: " + str(c.get("state")),
                    "risk: " + str(c.get("risk")), "command: " + str(c.get("command") or "-"),
                    "exit: " + str(c.get("exit_code")), ""]
            if c.get("detail"):
                body += ["## detail", str(c["detail"]), ""]
            if c.get("output"):
                body += ["## output (tail)", str(c["output"])[-4000:], ""]
            for f in (c.get("findings") or [])[:40]:
                body.append("- " + json.dumps(f, ensure_ascii=False)[:800])
            base.mkdir(parents=True, exist_ok=True)
            p = base / f"{c.get('id', 'check')}.txt"
            p.write_text("\n".join(body), encoding="utf-8")
            written.append(str(p))
        if written:
            (base / "index.json").write_text(
                json.dumps({"project": report.get("project"), "verdict": report.get("verdict"),
                            "files": written}, ensure_ascii=False, indent=2), encoding="utf-8")
        # 只保留最近 N 次（只在自管目录里裁剪，别动用户指定的目录）
        parent = Path(out_dir) if out_dir else root / ".verify-artifacts"
        runs = sorted([d for d in parent.iterdir() if d.is_dir()]) if parent.is_dir() else []
        for d in runs[:-keep]:
            for f in d.rglob("*"):
                if f.is_file():
                    f.unlink(missing_ok=True)
            for f in sorted(d.rglob("*"), reverse=True):
                if f.is_dir():
                    f.rmdir()
            d.rmdir()
    except Exception as e:
        return {"dir": str(base), "written": written, "error": f"{type(e).__name__}: {e}"}
    return {"dir": str(base) if written else "", "written": written}


# ───────────────────── ④ 接受机制（必须写理由）─────────────────────
ACCEPT_FILE = ".verify-accept.json"


def finding_id(check_id: str, f: dict) -> str:
    """稳定 id：同一处同一问题，跨运行一致。"""
    loc = f.get("file") or f.get("path") or ""
    line = f.get("line") or f.get("lineno") or 0
    msg = (f.get("message") or f.get("detail") or f.get("text") or "")[:160]
    h = hashlib.sha1(f"{check_id}|{loc}|{line}|{msg}".encode("utf-8")).hexdigest()[:10]
    return f"{check_id}:{loc}:{line}:{h}"


def load_accepts(root: Path) -> dict:
    for d in (Path(root), Path(root).parent):
        p = d / ACCEPT_FILE
        if p.is_file():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                if isinstance(data, dict) and isinstance(data.get("accepted"), list):
                    return {"path": str(p), "accepted": data["accepted"]}
            except Exception:
                pass
    return {"path": "", "accepted": []}


def save_accepts(root: Path, entries: list[dict]) -> str:
    p = Path(root) / ACCEPT_FILE
    p.write_text(json.dumps({"version": 1, "accepted": entries}, ensure_ascii=False, indent=2),
                 encoding="utf-8")
    return str(p)


def apply_accepts(report: dict, accepts: dict, extra: list[dict] | None = None) -> dict:
    """把 accepted 里的 id 标记到对应 finding 上；返回仍未回应的清单。

    规则：接受必须有非空 reason，且不允许接受 critical（密钥类）。
    """
    table: dict[str, dict] = {}
    for e in list(accepts.get("accepted") or []) + list(extra or []):
        if not isinstance(e, dict):
            continue
        fid = e.get("id")
        reason = (e.get("reason") or "").strip()
        if not fid or not reason:
            continue
        # 凭据类永远不接受：fid 形如 "secrets:<file>:<line>:<hash>"
        if str(fid).split(":")[0] in ("secrets", "security-secrets"):
            continue
        if e.get("risk") == "critical":
            continue
        table[fid] = e

    unresolved: list[dict] = []
    accepted_count = 0
    for c in report.get("checks", []):
        if c.get("state") == "PASS":
            continue
        for f in c.get("findings") or []:
            fid = f.get("id") or finding_id(c.get("id", ""), f)
            f["id"] = fid
            e = table.get(fid)
            if e:
                f["accepted"] = {"reason": e.get("reason"), "at": e.get("at", "")}
                accepted_count += 1
            else:
                unresolved.append({"id": fid, "check": c.get("id"), "risk": c.get("risk"),
                                   "file": f.get("file") or f.get("path"),
                                   "line": f.get("line") or f.get("lineno"),
                                   "message": (f.get("message") or "")[:200]})
        # UNKNOWN 不进 unresolved：它是「缺 oracle」，不是「人没回应」。
        # 这类由 gate() 单独处理：判定为 UNKNOWN（≠ PASS），而不是 FAIL。

    unknowns = [c.get("id") for c in report.get("checks", [])
                if c.get("state") == "UNKNOWN" and c.get("applicable", True)]
    return {"accepted": accepted_count, "unresolved": unresolved,
            "unresolved_count": len(unresolved), "unknown_checks": unknowns}


# ────────────────────── ⑤ 噪声 & ⑥ 收敛 ──────────────────────
NOISE_FILE = ".verify-noise.json"


def _load_noise(root: Path) -> dict:
    p = Path(root) / NOISE_FILE
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {"runs": [], "findings": {}}


def _save_noise(root: Path, data: dict) -> None:
    try:
        (Path(root) / NOISE_FILE).write_text(
            json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass


def noise_track(root: Path, report: dict) -> dict:
    """记录每轮 finding 集合，算出 fixed / new / 重复最多的规则。"""
    data = _load_noise(root)
    prev = set((data.get("runs") or [{}])[-1].get("ids") or [])
    cur_ids = []
    for c in report.get("checks", []):
        for f in c.get("findings") or []:
            cur_ids.append(f.get("id") or finding_id(c.get("id", ""), f))
    cur = set(cur_ids)

    fixed = sorted(prev - cur)
    new = sorted(cur - prev)
    repeat = sorted(cur & prev)

    runs = (data.get("runs") or []) + [{
        "at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "ids": sorted(cur),
        "count": len(cur),
        "verdict": report.get("verdict"),
    }]
    runs = runs[-12:]
    by_rule: dict[str, int] = {}
    for i in repeat:
        by_rule[i.split(":")[0]] = by_rule.get(i.split(":")[0], 0) + 1
    data["runs"] = runs
    data["findings"] = data.get("findings") or {}
    for i in cur:
        row = data["findings"].get(i) or {"seen": 0, "first": time.strftime("%Y-%m-%d")}
        row["seen"] = int(row.get("seen", 0)) + 1
        row["last"] = time.strftime("%Y-%m-%d")
        data["findings"][i] = row
    _save_noise(root, data)

    return {"total": len(cur), "fixed": len(fixed), "new": len(new), "repeat": len(repeat),
            "repeat_top": sorted(by_rule.items(), key=lambda kv: -kv[1])[:5],
            "runs": len(runs)}


def convergence(root: Path, report: dict) -> dict:
    """连续两轮 finding 数不减少 → 认为收敛，提示别再刷轮次。"""
    data = _load_noise(root)
    runs = data.get("runs") or []
    counts = [r.get("count", 0) for r in runs[-4:]]
    if len(counts) < 2:
        return {"rounds": len(counts), "converged": False,
                "advice": "第一次运行，还没有可比的历史。"}
    shrinking = counts[-1] < counts[-2]
    stalled = len(counts) >= 3 and len(set(counts[-3:])) == 1
    if stalled:
        return {"rounds": len(counts), "converged": True,
                "advice": "连续三轮条数不变 → 收敛了。剩下的要么接受（写理由），"
                          "要么改代码；不要再刷第 4 轮。"}
    return {"rounds": len(counts), "converged": (not shrinking),
            "advice": ("还在减少，继续修。" if shrinking
                       else "这轮没变少。先看 repeat_top：是不是同一类问题在反复？")}


# ───────────────────────── ⑦ 回归集 ─────────────────────────
REGRESSION_FILE = "regression.toml"


def regression_rules(root: Path) -> dict:
    """读 regression.toml：曾经出过事的路径 → 必跑/必看。

    极简 TOML 解析（只支持 [[case]] + key = "value"），避免为了一点配置引依赖。
    """
    p = Path(root) / REGRESSION_FILE
    if not p.is_file():
        return {"path": "", "cases": []}
    cases: list[dict] = []
    cur: dict = {}
    try:
        for raw in p.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("[[case]]"):
                if cur:
                    cases.append(cur)
                cur = {}
                continue
            m = re.match(r'(\w+)\s*=\s*"([^"]*)"', line)
            if m:
                cur[m.group(1)] = m.group(2)
            m2 = re.match(r"(\w+)\s*=\s*(\d+)", line)
            if m2:
                cur[m2.group(1)] = int(m2.group(2))
        if cur:
            cases.append(cur)
    except Exception:
        return {"path": str(p), "cases": [], "error": True}
    return {"path": str(p), "cases": cases}


def apply_regression(report: dict, rules: dict, root: Path) -> dict:
    """回归集：这些路径必须出现在本轮的覆盖里，且对应检查必须真的跑到。"""
    cases = rules.get("cases") or []
    if not cases:
        return {"cases": 0, "hits": [], "missing": []}
    files: list[str] = []
    for c in report.get("checks", []):
        for f in c.get("findings") or []:
            files.append(str(f.get("file") or ""))
    ran = {c.get("id") for c in report.get("checks", []) if c.get("state") != "UNKNOWN"}
    hits, missing = [], []
    for case in cases:
        path = case.get("path", "")
        check = case.get("check", "")
        if check and check not in ran:
            missing.append({"case": case, "why": f"检查 {check} 本轮没有有效结果"})
            continue
        if path and not any(fnmatch.fnmatch(f, path) for f in files):
            # 没命中不是错 —— 只说明"这次没改到它"
            hits.append({"case": case, "why": "本轮没有涉及该路径"})
        else:
            hits.append({"case": case, "why": "涉及该路径"})
    return {"cases": len(cases), "hits": hits, "missing": missing}


# ─────────────────── ⑨ 安全层（独立、可阻塞、不可接受）───────────────────
# (正则, 说明, 风险, 作用域) —— 作用域 code 表示「只在代码里算」，
# 文档（.md/.txt/.rst）里的 http 链接是**参考资料**，不是请求，报它纯属噪声。
DANGEROUS_PATTERNS = [
    (r"subprocess\.(?:run|Popen|call)\([^)]*shell\s*=\s*True", "subprocess 使用 shell=True", "high", "any"),
    (r"(?<![\w.])eval\s*\(", "使用 eval()", "high", "code"),
    (r"(?<![\w.])exec\s*\(", "使用 exec()", "high", "code"),
    (r"os\.system\s*\(", "使用 os.system()", "high", "code"),
    (r"http://(?!127\.0\.0\.1|localhost)", "明文 http:// 外链（代码里）", "medium", "code"),
    (r"verify\s*=\s*False", "requests 关闭了 TLS 校验", "high", "code"),
    (r"--insecure|ssl\s*=\s*False|CERT_NONE", "关闭 TLS 校验", "high", "any"),
]
DOC_EXT = {".md", ".markdown", ".txt", ".rst", ".adoc"}
STYLE_CHECKS = {"a11y"}          # 只这些算"风格"，受 no-style 影响
SEC_CODE_EXT = {".py", ".js", ".mjs", ".cjs", ".ts", ".sh", ".ps1", ".yml", ".yaml", ".toml"}


SELF_FILES = {"lifecycle.py"}          # 定义这些正则的文件本身不该被它扫
# 备份/草稿目录：与正本重名，扫两遍等于把同一问题报两次
BACKUP_PART_RE = re.compile(r"(\.backup-|\.bak-|\.old$|\.orig$|^backup-|^bak-)", re.I)


def _ignore_patterns(root: Path) -> list[str]:
    p = Path(root) / ".verifyignore"
    try:
        return [x.strip() for x in p.read_text(encoding="utf-8").splitlines()
                if x.strip() and not x.strip().startswith("#")]
    except Exception:
        return []


def security_layer(root: Path, report: dict, max_files: int = 4000,
                   extra_skip: list[str] | None = None) -> dict:
    """在 secrets 之上再加一层「危险调用」扫描。

    只有 **critical**（真实凭据）才阻塞；high 的进 unresolved，必须被回应
    （修掉，或 --accept 写理由）。这样既不放过真问题，也不会因为一条
    eval() 之类把整个流程永远卡死 —— 噪声会让这条通道失去信任。
    """
    root = Path(root)
    findings: list[dict] = []
    scanned = 0
    ignores = _ignore_patterns(root) + list(extra_skip or [])
    for p in root.rglob("*"):
        if len(findings) >= 60 or scanned >= max_files:
            break
        if not p.is_file() or p.suffix.lower() not in SEC_CODE_EXT:
            continue
        if p.name in SELF_FILES:
            continue
        if any(part in {".git", "node_modules", "venv", "__pycache__", ".verify-artifacts"}
               for part in p.parts):
            continue
        rel = p.relative_to(root).as_posix()
        if any(fnmatch.fnmatch(rel, pat) for pat in ignores):
            continue
        if any(BACKUP_PART_RE.search(part) for part in p.parts):
            continue
        try:
            if p.stat().st_size > 1_500_000:
                continue
            text = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        scanned += 1
        is_doc = p.suffix.lower() in DOC_EXT
        for pat, label, risk, scope in DANGEROUS_PATTERNS:
            if scope == "code" and is_doc:
                continue
            for m in re.finditer(pat, text):
                line = text.count("\n", 0, m.start()) + 1
                findings.append({
                    "id": f"security:{p.relative_to(root).as_posix()}:{line}:{label}",
                    "file": p.relative_to(root).as_posix(),
                    "line": line, "message": label, "risk": risk, "accept": False,
                })
                break
    # 密钥类永远算安全层
    for c in report.get("checks", []):
        if c.get("id") == "secrets" and c.get("state") == "FAIL":
            for f in c.get("findings") or []:
                findings.append({"id": finding_id("secrets", f),
                                 "file": f.get("file"), "line": f.get("line"),
                                 "message": "疑似真实凭据", "risk": "critical", "accept": False})
    blocked = any(f.get("risk") == "critical" for f in findings)
    groups = aggregate_security(findings)
    return {"blocked": blocked, "scanned": scanned, "findings": findings[:80],
            "count": len(findings), "groups": groups,
            "group_count": len(groups)}


def aggregate_security(findings: list[dict]) -> list[dict]:
    """把同类发现聚合成一组：17 处 verify=False 不该显示成 17 行。"""
    buckets: dict[tuple, dict] = {}
    for f in findings:
        key = (f.get("message") or "?", f.get("risk") or "?")
        row = buckets.setdefault(key, {"message": key[0], "risk": key[1],
                                       "count": 0, "files": []})
        row["count"] += 1
        row["files"].append(f"{f.get('file')}:{f.get('line')}")
    groups = sorted(buckets.values(), key=lambda r: (-r["count"], r["message"]))
    for g in groups:
        g["files"] = g["files"][:6]
        # 同一类超过 5 处 → 提示「一次性处理」，而不是逐条纠结
        g["advice"] = ("同一类问题反复出现：要么一次性改掉，要么在 REVIEW.md 里 "
                       "`security-skip:` 豁免那批文件（别逐条接受，那是噪声）"
                       if g["count"] > 5 else "")
    return groups


# ───────────────────────── ⑩ 度量 ─────────────────────────
def metrics(report: dict, stage_result: dict, tier: dict, acc: dict,
            noise: dict | None = None, sec: dict | None = None) -> dict:
    checks = report.get("checks", [])
    applied = [c for c in checks if c.get("applicable", True)]
    unknown = [c for c in applied if c.get("state") == "UNKNOWN"]
    fails = [c for c in applied if c.get("state") == "FAIL"]
    slow = sorted(applied, key=lambda c: -(c.get("seconds") or 0))[:3]
    return {
        "checks_total": len(checks),
        "checks_applicable": len(applied),
        "fail": len(fails),
        "unknown": len(unknown),
        "unknown_rate": round(len(unknown) / max(1, len(applied)), 3),
        "unknown_checks": [c.get("id") for c in unknown],
        "accepted": acc.get("accepted", 0),
        "unresolved": acc.get("unresolved_count", 0),
        "needs_human_eyes": acc.get("unresolved_count", 0),   # 人要花的时间的代理指标
        "unresolved_by_check": _count_by(acc.get("unresolved") or [], "check"),
        "unresolved_by_risk": _count_by(acc.get("unresolved") or [], "risk"),
        "tier": tier.get("tier"),
        "human_approvals_required": tier.get("human_approvals"),
        "stage": stage_result.get("stage"),
        "security_findings": (sec or {}).get("count", 0),
        "noise_new": (noise or {}).get("new", 0),
        "noise_repeat": (noise or {}).get("repeat", 0),
        "noise_fixed": (noise or {}).get("fixed", 0),
        "slowest": [{"check": c.get("id"), "seconds": c.get("seconds")} for c in slow],
    }


def _count_by(rows: list[dict], key: str) -> dict:
    out: dict[str, int] = {}
    for r in rows:
        k = str(r.get(key) or "?")
        out[k] = out.get(k, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))


# ───────────────────── 闸门总判定（把上面拼起来）─────────────────────
def gate(report: dict, stage: str, tier: dict, unresolved: list[dict],
         sec: dict, conv: dict, allow_unknown: bool) -> dict:
    """综合判定：安全层 > 阻断级失败 > 未回应项 > 未知项。"""
    st = normalize_stage(stage)
    spec = STAGES[st]
    blocking_fail = [c.get("id") for c in report.get("checks", [])
                     if c.get("state") == "FAIL" and c.get("applicable", True)
                     and c.get("risk") in spec["blocking_risks"]]
    unknown_blocking = [c.get("id") for c in report.get("checks", [])
                        if c.get("state") == "UNKNOWN" and c.get("applicable", True)
                        and c.get("risk") in spec["blocking_risks"]]

    # 未回应里只有 medium 及以上才卡住；low 是提示（跟「低风险 0 人」一致）
    unresolved_blocking = [u for u in unresolved
                           if str(u.get("risk") or "").lower() in ("critical", "high", "medium")]

    hard: list[dict] = []       # 已知的坏 → FAIL
    soft: list[dict] = []       # 无法判定 → UNKNOWN（不谎报 PASS，也不谎报 FAIL）
    if sec.get("blocked"):
        hard.append({"reason": "安全层有高危发现", "count": sec.get("count")})
    if blocking_fail:
        hard.append({"reason": "阻断级检查失败", "checks": blocking_fail})
    if unresolved_blocking and spec is not STAGES["precommit"]:
        hard.append({"reason": "有未回应的 finding（中风险及以上）",
                     "count": len(unresolved_blocking)})
    if unknown_blocking and not allow_unknown:
        soft.append({"reason": "阻断级检查无法判定（缺 oracle）", "checks": unknown_blocking})

    applied = [c for c in report.get("checks", []) if c.get("applicable", True)]
    any_definitive = any(c.get("state") in ("PASS", "FAIL") for c in applied)
    if hard:
        verdict = "FAIL"
    elif soft or not any_definitive:
        verdict = "UNKNOWN"
    else:
        verdict = "PASS"
    return {"stage": st, "title": spec["title"], "purpose": spec["purpose"],
            "verdict": verdict, "blocked_by": hard + soft,
            "unresolved_blocking": len(unresolved_blocking),
            "unresolved_low": len(unresolved) - len(unresolved_blocking),
            "allow_unknown": allow_unknown,
            "converged": conv.get("converged"), "convergence_advice": conv.get("advice")}


# ───────────────────────── 总入口 ─────────────────────────
def apply(report: dict, root: Path, opts: dict | None = None) -> dict:
    """后处理：给 report 加 lifecycle 段，并按闸门结论修正 verdict。

    opts:
      stage, tier(auto/forced), accepts(list), only_new(bool),
      artifacts(bool), review_md(bool), regression(bool)
    """
    opts = opts or {}
    root = Path(root)
    stage = normalize_stage(opts.get("stage"))

    facts = diff_facts(root, opts.get("against"))
    tier = tier_of(facts, opts.get("tier") if opts.get("tier") not in (None, "auto") else None)
    review = load_review_md(root) if opts.get("review_md", True) else {"found": False, "rules": {}}

    acc = apply_accepts(report, load_accepts(root), opts.get("accepts"))
    sec = security_layer(root, report,
                         extra_skip=(review.get("rules") or {}).get("security_skip") or [])
    # 安全层的高危发现也必须有回应（可 --accept 写理由；critical 不接受）
    for f in sec["findings"]:
        if f.get("risk") in ("critical", "high"):
            acc["unresolved"].append({"id": f["id"], "check": "security", "risk": f["risk"],
                                      "file": f.get("file"), "line": f.get("line"),
                                      "message": f.get("message")})
    acc["unresolved_count"] = len(acc["unresolved"])
    noise = noise_track(root, report)
    conv = convergence(root, report)
    reg = apply_regression(report, regression_rules(root), root)
    arts = (write_artifacts(report, root, out_dir=opts.get("artifacts_dir"))
            if opts.get("artifacts", True) else {"written": []})

    # only_new：只留新出现的 finding（基于噪声库里的上一轮）
    dropped = 0
    if opts.get("only_new"):
        keep: list[dict] = []
        for u in acc["unresolved"]:
            row = _load_noise(root).get("findings", {}).get(u["id"]) or {}
            if int(row.get("seen", 1)) <= 1:
                keep.append(u)
        dropped = len(acc["unresolved"]) - len(keep)
        acc["unresolved"] = keep
        acc["unresolved_count"] = len(keep)

    g = gate(report, stage, tier, acc["unresolved"], sec, conv,
             STAGES[stage]["allow_unknown"])
    m = metrics(report, g, tier, acc, noise, sec)

    report["lifecycle"] = {
        "version": VERSION,
        "stage": g,
        "tier": tier,
        "diff": facts,
        "review_md": review,
        "accept": {"accepted": acc["accepted"], "unresolved": acc["unresolved"][:40],
                   "unresolved_count": acc["unresolved_count"], "only_new_dropped": dropped},
        "security": {k: v for k, v in sec.items() if k != "findings"},
        "security_findings": sec["findings"][:20],
        "noise": noise,
        "convergence": conv,
        "regression": reg,
        "artifacts": {"dir": arts.get("dir", ""), "count": len(arts.get("written") or [])},
        "metrics": m,
    }

    # 修正总判定：闸门说 FAIL 就 FAIL；闸门说 PASS 但原判定 FAIL（非阻断项）则降为 PASS
    report["verdict"] = g["verdict"]        # 闸门结论即最终结论（三态严格）
    if g["verdict"] == "PASS" and g.get("unresolved_low"):
        report.setdefault("notes", []).append(
            f"有 {g['unresolved_low']} 条低风险提示未回应 —— 不阻断，但建议接受或修掉。")
    return report


# ─────────────────── ⑧ 合并队列：与目标分支组合后再跑 ───────────────────
def merge_probe(root: Path, base: str = "main", workdir: Path | None = None) -> dict:
    """在临时 worktree 里把当前分支与 base 合并，供调用方对**合并结果**跑检查。

    返回 {ok, path, note}；调用方负责清理（cleanup_worktree）。
    """
    root = Path(root)
    if not (root / ".git").exists():
        return {"ok": False, "path": "", "note": "不是 git 仓库，跳过合并队列"}
    wd = Path(workdir or Path(os.environ.get("TEMP", ".")) / f"vh-merge-{int(time.time())}")
    code, out = _git(root, ["worktree", "add", "--detach", str(wd), "HEAD"])
    if code != 0:
        return {"ok": False, "path": "", "note": f"worktree 创建失败：{out[-300:]}"}
    code, out = _git(wd, ["merge", "--no-edit", base])
    if code != 0:
        _git(root, ["worktree", "remove", "--force", str(wd)])
        return {"ok": False, "path": "",
                "note": f"与 {base} 合并有冲突（这正是合并队列要拦的情况）：{out[-400:]}"}
    return {"ok": True, "path": str(wd), "note": f"已在临时 worktree 中合并 {base}"}


def cleanup_worktree(root: Path, path: str) -> None:
    if path:
        _git(Path(root), ["worktree", "remove", "--force", path])


# ─────────────────── ⑧' REVIEW.md（人写给检查器的规则）───────────────────
def load_review_md(root: Path) -> dict:
    """读 REVIEW.md：这个仓库里「失败」长什么样、别报什么、必须给什么证据。

    支持的写法（中英都认）：
        skip: drafts/**, legacy/**
        max-nits: 5
        require-evidence: true
        fail-means: 文档说谎 / 配置路由错
        no-style: true
    """
    for name in ("REVIEW.md", "review.md", ".review.md"):
        p = Path(root) / name
        if p.is_file():
            break
    else:
        return {"found": False, "path": "", "rules": {}}
    rules: dict = {"skip": [], "security_skip": [], "no_style": False,
                   "require_evidence": False, "max_nits": 10, "fail_means": ""}
    try:
        for raw in p.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw.strip()
            low = line.lower()
            if low.startswith(("skip:", "跳过:", "不检查:")):
                val = line.split(":", 1)[1].strip()
                rules["skip"] += [x.strip() for x in val.split(",") if x.strip()]
            elif low.startswith(("max-nits:", "最多提示:")):
                try:
                    rules["max_nits"] = int(line.split(":", 1)[1].strip())
                except ValueError:
                    pass
            elif low.startswith(("require-evidence:", "必须证据:")):
                rules["require_evidence"] = "true" in low or "是" in line
            elif low.startswith(("security-skip:", "安全豁免:")):
                val = line.split(":", 1)[1].strip()
                rules["security_skip"] += [x.strip() for x in val.split(",") if x.strip()]
            elif low.startswith(("no-style:", "不报风格:")):
                rules["no_style"] = "true" in low or "是" in line
            elif low.startswith(("fail-means:", "失败意味着:")):
                rules["fail_means"] = line.split(":", 1)[1].strip()
    except Exception:
        pass
    return {"found": True, "path": str(p), "rules": rules}


def apply_review(report: dict, review: dict) -> dict:
    """按 REVIEW.md 过滤 finding：skip 路径、no-style、max-nits、证据要求。"""
    rules = review.get("rules") or {}
    if not review.get("found"):
        return {"dropped": 0}
    skipped = 0
    no_evidence = 0
    for c in report.get("checks", []):
        keep = []
        for f in c.get("findings") or []:
            path = str(f.get("file") or f.get("path") or "")
            if any(fnmatch.fnmatch(path, pat) for pat in rules.get("skip") or []):
                skipped += 1
                continue
            # no-style 只关掉真正的风格类检查；todos/bom/paths 是诊断信息，不关
            if rules.get("no_style") and c.get("id") in STYLE_CHECKS:
                skipped += 1
                continue
            if rules.get("require_evidence") and not (f.get("file") and f.get("line")):
                no_evidence += 1
                continue
            keep.append(f)
        c["findings"] = keep[: rules.get("max_nits") or 10] if c.get("risk") == "low" else keep
    return {"dropped": skipped, "no_evidence": no_evidence}
