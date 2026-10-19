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
SERVER_VERSION = verify_core.VERSION
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

    rep = verify_core.verify(path, checks=checks, include_git=include_git,
                             fast=fast, use_cache=not no_cache, workers=workers)
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
}


# ──────────────────────────────────────────────────────────────────────
# 自刷新：改了 verify_core.py 不用重启 MCP 子进程
#
# 子进程一启动就把模块读进内存了。之前每改一版内核都得杀掉子进程重来，
# 而重启要靠改 profile 的配置（还不一定触发 respawn）。改成每次调用前
# 比一下 mtime，变了就 reload —— 开发循环从此不用碰进程。
# ──────────────────────────────────────────────────────────────────────
_CORE_MTIME = 0
_DEPS = ("check_specs.py", "sarif.py", "verify_core.py")


def _maybe_reload_core():
    """任一依赖文件变了就整组重新加载。

    只 reload verify_core 是不够的：它 `import check_specs as S`，而 sys.modules
    里那份 check_specs 还是旧的 —— 新加的常量会报 has no attribute。
    """
    global _CORE_MTIME
    stamps = []
    for name in _DEPS:
        try:
            stamps.append((name, (HERE / name).stat().st_mtime_ns))
        except OSError:
            stamps.append((name, 0))
    cur = hash(tuple(stamps))
    if _CORE_MTIME and cur != _CORE_MTIME:
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
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
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
    log(f"{SERVER_NAME} v{SERVER_VERSION} 已启动（stdio）")
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
