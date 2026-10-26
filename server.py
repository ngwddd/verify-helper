# -*- coding: utf-8 -*-
"""项目验证 MCP —— stdio JSON-RPC 2.0，零依赖。

为什么手写而不装官方 SDK：这台机器上没有 mcp 包；协议面又只有
initialize / tools/list / tools/call 三个方法，手写比装依赖更容易审。

传输：换行分隔的 JSON（一行一条消息），与主流 MCP 客户端一致。
日志一律走 stderr —— stdout 只能是协议消息，混进去就废了。
"""
from __future__ import annotations

import json
import sys
import time
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import verify_core  # noqa: E402

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

SERVER_NAME = "verify-helper"


def _version() -> str:
    """每次都读当前值。

    之前把它在 import 时存成常量：热加载内核后 serverInfo 还停在启动时的版本号，
    客户端看到的版本和实际跑的代码对不上（实测报 1.3.0 而实际已是 1.4）。
    """
    return verify_core.VERSION


PROTOCOL = "2024-11-05"

LAST: dict[str, dict] = {}      # run_id -> report


def log(*a):
    print(*a, file=sys.stderr, flush=True)


# ──────────────────────────────────────────────────────────────────────
# 工具定义
# ──────────────────────────────────────────────────────────────────────
TOOLS = [
    {
        "name": "verify_start",
        "description": (
            "对一个项目目录跑一遍验证，返回三态结论（PASS / FAIL / UNKNOWN）与每条检查的证据。"
            "15 项检查并行跑，每项带风险等级（严重/高/中/低）与修复建议。"
            "没有 oracle 的检查一律记 UNKNOWN，绝不谎报 PASS。"
            "支持 verify.toml 自定义规则、.verifyignore 排除、SARIF 输出。"
            "v1.9 起支持分层闸门：stage=precommit/pr/merge/postdeploy；"
            "tier 按 git 改动自动判风险档（命中敏感路径/大改动=high）；"
            "每条 finding 必须被回应（修掉，或用 accept 写理由接受）；"
            "带噪声统计与收敛判定、回归集、安全层、证据留档。"
            "browser 检查会用真实浏览器抓 JS 报错（需要本机装有 playwright）。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "项目目录的绝对路径"},
                "checks": {
                    "type": "array",
                    "items": {"type": "string",
                              "enum": ["syntax", "links", "html", "secrets", "encoding",
                                       "tests", "runtime-web", "browser", "a11y", "bom",
                                       "paths", "imports", "todos", "custom", "git"]},
                    "description": "只跑指定的检查；省略表示跑默认全部（不含 git）",
                },
                "include_git": {"type": "boolean",
                                "description": "是否把 git 工作区状态算进总判定，默认 false"},
                "fast": {"type": "boolean",
                         "description": "跳过测试与变异检查，保留运行时和浏览器（仍是秒级）"},
                "no_cache": {"type": "boolean",
                             "description": "忽略语法缓存，全部重新解析"},
                "workers": {"type": "integer",
                            "description": "并行度，默认 8，上限 16"},
                "format": {"type": "string", "enum": ["text", "json", "sarif"],
                           "description": "text=给人看；json=完整报告；sarif=SARIF 2.1.0"},
                "stage": {"type": "string",
                          "enum": ["precommit", "pr", "merge", "postdeploy"],
                          "description": "这一轮属于哪一层，默认 pr"},
                "tier": {"type": "string", "enum": ["auto", "low", "medium", "high"],
                         "description": "风险档；auto = 按 git 改动自动判定"},
                "accept": {"type": "array", "items": {"type": "object"},
                           "description": "[{id, reason}] 接受的 finding（必须写理由）"},
                "only_new": {"type": "boolean",
                             "description": "只报本轮新出现的 finding（基于噪声库）"},
                "against": {"type": "string",
                            "description": "合并队列：与目标分支组合后再判定（如 main）"},
                "artifacts": {"type": "boolean",
                              "description": "是否写 .verify-artifacts 证据，默认 true"},
                "review_md": {"type": "boolean",
                              "description": "是否读 REVIEW.md 的仓库级规则，默认 true"},
            },
            "required": ["path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "verify_report",
        "description": "取回某次验证的完整报告（JSON）。不给 run_id 就返回最近一次。",
        "inputSchema": {
            "type": "object",
            "properties": {"run_id": {"type": "string"}},
            "additionalProperties": False,
        },
    },
    {
        "name": "verify_checks",
        "description": "列出所有可用检查项、各自判定什么、以及是否参与总判定。",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "verify_accept",
        "description": (
            "管理「接受」记录（.verify-accept.json）。一条 finding 要么修掉，要么写理由接受 —— "
            "这是 v1.9 的强制回应机制。action=list 读出全部；action=add 追加一条（必须给 id 与 reason）；"
            "action=clear 清空。critical（凭据类）不接受。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": ["list", "add", "clear"]},
                "path": {"type": "string", "description": "项目目录（写在这里的 .verify-accept.json）"},
                "id": {"type": "string", "description": "finding id（verify_start 报告里的 id 字段）"},
                "reason": {"type": "string", "description": "为什么可以接受（必填，会留档）"},
            },
            "required": ["action", "path"],
            "additionalProperties": False,
        },
    },
]


def tool_verify_start(args: dict) -> tuple[str, bool]:
    path = (args or {}).get("path") or ""
    if not path:
        return json.dumps({"error": "缺少 path 参数"}, ensure_ascii=False), True
    checks = args.get("checks") or None
    include_git = bool(args.get("include_git"))
    fast = bool(args.get("fast"))
    no_cache = bool(args.get("no_cache"))
    workers = int(args.get("workers") or 8)
    fmt = args.get("format") or "text"

    rep = verify_core.verify(
        path, checks=checks, include_git=include_git,
        fast=fast, use_cache=not no_cache, workers=workers,
        stage=args.get("stage") or "pr",
        tier=args.get("tier") or "auto",
        accepts=args.get("accept") or None,
        only_new=bool(args.get("only_new")),
        artifacts=bool(args.get("artifacts", True)),
        review_md=bool(args.get("review_md", True)),
        against=args.get("against") or None,
    )
    if "error" in rep:
        # 路径不存在这类输入错误也要以 isError 返回，不能伪装成一次「跑过了」的验证。
        if fmt == "json":
            return json.dumps(rep, ensure_ascii=False, indent=1), True
        return f"✗ {rep['error']}", True

    run_id = f"run-{len(LAST) + 1}"
    rep["run_id"] = run_id
    rep["version"] = verify_core.VERSION
    LAST[run_id] = rep
    is_error = rep.get("verdict") == "FAIL"
    if fmt == "json":
        return json.dumps(rep, ensure_ascii=False, indent=1), is_error
    if fmt == "sarif":
        import sarif as sarif_mod
        return sarif_mod.dumps(rep, verify_core.VERSION), is_error
    return verify_core.render(rep), is_error


def tool_verify_report(args: dict) -> tuple[str, bool]:
    rid = (args or {}).get("run_id")
    if rid:
        rep = LAST.get(rid)
        if not rep:
            return json.dumps({"error": f"没有这个 run_id：{rid}"}, ensure_ascii=False), True
    else:
        if not LAST:
            return json.dumps({"error": "还没有跑过任何验证"}, ensure_ascii=False), True
        rid = list(LAST)[-1]
        rep = LAST[rid]
    return json.dumps(rep, ensure_ascii=False, indent=1), False


def tool_verify_accept(args: dict) -> tuple[str, bool]:
    """管理 .verify-accept.json（必须写理由的接受机制）。"""
    import lifecycle as LC
    action = (args or {}).get("action") or "list"
    path = (args or {}).get("path") or ""
    if not path:
        return json.dumps({"error": "缺少 path 参数"}, ensure_ascii=False), True
    root = Path(path)
    data = LC.load_accepts(root)
    entries = list(data.get("accepted") or [])

    if action == "list":
        return json.dumps({"path": data.get("path") or str(root / LC.ACCEPT_FILE),
                           "accepted": entries, "count": len(entries)},
                          ensure_ascii=False, indent=2), False

    if action == "clear":
        LC.save_accepts(root, [])
        return json.dumps({"ok": True, "cleared": len(entries)}, ensure_ascii=False), False

    fid = (args.get("id") or "").strip()
    reason = (args.get("reason") or "").strip()
    if not fid or not reason:
        return json.dumps({"error": "add 需要 id 与 reason（不接受无理由的接受）"},
                          ensure_ascii=False), True
    if ":secrets:" in fid or "security:secrets" in fid:
        return json.dumps({"error": "凭据类 finding 不接受，必须真正修掉"}, ensure_ascii=False), True
    entries = [e for e in entries if e.get("id") != fid]
    entries.append({"id": fid, "reason": reason, "at": time.strftime("%Y-%m-%d")})
    written = LC.save_accepts(root, entries)
    return json.dumps({"ok": True, "file": written, "count": len(entries)},
                      ensure_ascii=False, indent=2), False


def tool_verify_checks(args: dict) -> tuple[str, bool]:
    rows = []
    for spec in verify_core.S.SPECS:
        rows.append({
            "id": spec.id,
            "title": spec.title,
            "risk": spec.risk,
            "riskLabel": verify_core.S.RISK_LABEL[spec.risk],
            "blocking": spec.blocking,
            "category": spec.category,
            "doc": spec.doc,
            "remediation": spec.remediation,
            "refs": list(spec.refs),
        })
    return json.dumps({"checks": rows, "count": len(rows),
                       "version": verify_core.VERSION},
                      ensure_ascii=False, indent=1), False


HANDLERS = {
    "verify_start": tool_verify_start,
    "verify_report": tool_verify_report,
    "verify_checks": tool_verify_checks,
    "verify_accept": tool_verify_accept,
}


# ──────────────────────────────────────────────────────────────────────
# 自刷新：改了 verify_core.py 不用重启 MCP 子进程
#
# 子进程一启动就把模块读进内存了。之前每改一版内核都得杀掉子进程重来，
# 而重启要靠改 profile 的配置（还不一定触发 respawn）。改成每次调用前
# 比一下 mtime，变了就 reload —— 开发循环从此不用碰进程。
# ──────────────────────────────────────────────────────────────────────
_DEPS = ("check_specs.py", "directions.py", "sarif.py", "verify_core.py")


def _stamp() -> int:
    stamps = []
    for name in _DEPS:
        try:
            stamps.append((name, (HERE / name).stat().st_mtime_ns))
        except OSError:
            stamps.append((name, 0))
    return hash(tuple(stamps))


# 必须在**导入时**就记下基线。
# 之前初始化成 0，然后 `if _CORE_MTIME and ...` 判断 —— 结果是：
# 进程启动后如果一直没人调用，等第一次调用时文件已经改过，那一次只会记基线、
# 不会 reload，于是子进程一直跑旧代码（run-14 报 v1.6.2 而实际已是 v1.7.0）。
_CORE_MTIME = _stamp()


def _maybe_reload_core():
    """任一依赖文件变了就整组重新加载。

    只 reload verify_core 是不够的：它 `import check_specs as S`，而 sys.modules
    里那份 check_specs 还是旧的 —— 新加的常量会报 has no attribute。
    """
    global _CORE_MTIME
    cur = _stamp()
    if cur != _CORE_MTIME:
        import importlib
        # 依赖在前，使用者在后
        for name in _DEPS:
            mod = name[:-3]
            try:
                if mod in sys.modules:
                    importlib.reload(sys.modules[mod])
            except Exception:
                log(f"[reload] {mod} 失败：", traceback.format_exc())
        log(f"[reload] 已刷新（{len(verify_core.CHECKS)} 项检查，v{verify_core.VERSION}）")
    _CORE_MTIME = cur


# ──────────────────────────────────────────────────────────────────────
# JSON-RPC
# ──────────────────────────────────────────────────────────────────────
def send(obj: dict):
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def result(msg_id, payload):
    send({"jsonrpc": "2.0", "id": msg_id, "result": payload})


def error(msg_id, code: int, message: str):
    send({"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}})


def handle(msg: dict):
    method = msg.get("method")
    msg_id = msg.get("id")

    if method == "initialize":
        result(msg_id, {
            "protocolVersion": PROTOCOL,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "version": _version()},
        })
        return

    if method in ("notifications/initialized", "initialized"):
        return                      # 通知不需要回

    if method == "ping":
        result(msg_id, {})
        return

    if method == "tools/list":
        result(msg_id, {"tools": TOOLS})
        return

    if method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        _maybe_reload_core()
        fn = HANDLERS.get(name)
        if fn is None:
            error(msg_id, -32602, f"未知工具：{name}")
            return
        try:
            text, is_error = fn(args)
        except Exception as e:                       # 工具内部异常也要变成可读结果
            log("tool error:", traceback.format_exc())
            text, is_error = f"工具执行出错：{type(e).__name__}: {e}", True
        result(msg_id, {
            "content": [{"type": "text", "text": text}],
            "isError": is_error,
        })
        return

    if msg_id is not None:
        error(msg_id, -32601, f"不支持的方法：{method}")


def main():
    log(f"{SERVER_NAME} v{_version()} 已启动（stdio）")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError as e:
            error(None, -32700, f"JSON 解析失败：{e}")
            continue
        if isinstance(msg, list):                    # 兼容批量请求
            for m in msg:
                handle(m)
        else:
            try:
                handle(msg)
            except Exception:
                log("handler error:", traceback.format_exc())
                if msg.get("id") is not None:
                    error(msg.get("id"), -32603, "服务器内部错误")


if __name__ == "__main__":
    main()
