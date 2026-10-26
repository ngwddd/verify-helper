# -*- coding: utf-8 -*-
"""项目验证内核 v1 —— 11 项检查，并行执行，逐文件语法缓存。

设计约束（来自用户的三条回答）：
  · 对象任意：不预设是网页，靠文件类型自动判断该跑哪些检查
  · 跑在 host 侧：能起子进程、能读整个目录
  · 只在被叫到时跑：不做文件监听、不自动触发

三态规则（写死在这里，任何检查都逃不掉）：
  PASS    检查跑了，且通过
  FAIL    检查跑了，且不通过
  UNKNOWN 没跑 / 跑不了 / 判不了 —— 永远不许当 PASS
  另有一个 applicable 标志：项目里根本没有这类文件时记 UNKNOWN + applicable=False，
  它不参与总判定（那不是「判不了」，是「不适用」）。

v1 相对 v0 的变化：
  · 检查项 6 → 11：新增 html 结构、编码、Python 未用 import、运行时（HTTP）、TODO 统计
  · 并行：所有检查同时跑，墙钟≈最慢那一项，而不是相加
  · 缓存：node --check 的结果按 (mtime, size) 缓存，重复跑几乎零成本
  · 每项检查报告自己的耗时，总耗时写进报告
"""
from __future__ import annotations

import ast
import fnmatch
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import tomllib
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from pathlib import Path

import check_specs as S
import directions as DIR

VERSION = "1.10.7"


def _wrap(text: str, width: int = 50) -> list[str]:
    """按字数折行。中文没有空格，textwrap 在这里不适用。

    额外一条：不要把英文单词/路径从中间劈开（"h|tml" 这种很伤可读性）。
    切点落在长串 ASCII 里时往回退到词首；退得太远（超过半行）就宁可硬切。
    """
    text = " ".join(str(text or "").split())
    if not text:
        return [""]
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        end = min(i + width, n)
        if end < n:
            j = end
            while j > i and (text[j - 1].isalnum() or text[j - 1] in "._-/"):
                j -= 1
            if j > i + width // 2:
                end = j
        out.append(text[i:end])
        i = end
    return out


# Windows 控制台默认 GBK，印 ✓ / ✗ 会直接 UnicodeEncodeError（本项目踩过多次）。
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# 备份/草稿目录：默认不扫（与正本重名，重复报同一问题）
BACKUP_DIR_RE = re.compile(r"(\.backup-|\.bak-|\.old$|\.orig$|^backup-|^bak-)", re.I)
_SKIPPED_BACKUPS: list[str] = []

SKIP_DIRS = {
    ".verify-artifacts",
    "node_modules", ".git", "__pycache__", ".venv", "venv", "env",
    "dist", "build", "vendor", ".pnpm", ".next", ".cache", "shots",
    ".pytest_cache", ".mypy_cache", ".ruff_cache", ".state", "site-packages",
    ".idea", ".vscode", "coverage", "htmlcov", ".tox", ".nuxt", "out",
}

PY_EXT = {".py"}
JS_EXT = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"}
HTML_EXT = {".html", ".htm"}
JSON_EXT = {".json"}
CSS_EXT = {".css"}
TEXT_EXT = PY_EXT | JS_EXT | HTML_EXT | JSON_EXT | CSS_EXT | {
    ".md", ".txt", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".env"}

MAX_FILE_BYTES = 5 * 1024 * 1024
JS_CHECK_CAP = 120               # node --check 单次运行的检查上限
CACHE_DIR = Path(os.environ.get("TEMP", ".")) / "project-verify"

SECRET_PATTERNS = [
    ("OpenAI/DeepSeek 风格密钥", re.compile(r"\bsk-[A-Za-z0-9]{16,}")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}")),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("私钥块", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
]
# 「password = "..."」这种只看代码/配置，不看笔记：
# 课程笔记里全是 password = "" 这类教学示例，扫进去就是一堆假阳性。
CRED_PATTERN = ("疑似明文密码赋值",
                re.compile(r"(?i)\b(password|passwd|pwd|secret|token)\s*[=:]\s*[\"'][^\"'\s]{8,}[\"']"))
CODE_EXT = PY_EXT | JS_EXT | {".env", ".ini", ".cfg", ".conf", ".yml", ".yaml", ".json", ".toml"}
TODO_RE = re.compile(r"\b(TODO|FIXME)\b")


def _comment_marker_pos(line: str, ext: str) -> int:
    """返回这一行「注释」开始的下标；没有注释返回 -1。

    必须跳过引号里的内容 —— 否则 `x = 'a # TODO b'` 会被当成注释里的待办，
    而它其实只是一个字符串（自检时踩到过）。
    """
    if ext in HTML_EXT:
        markers = ("<!--",)
    elif ext in JS_EXT:
        markers = ("//", "/*")
    elif ext == ".css":
        markers = ("/*",)
    else:
        markers = ("#",)

    quote = ""
    i, n = 0, len(line)
    while i < n:
        ch = line[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = ""
            i += 1
            continue
        if ch in "\"'":
            quote = ch
            i += 1
            continue
        for m in markers:
            if line.startswith(m, i):
                return i
        i += 1
    return -1

LOCAL_PATH_PATTERNS = [
    ("Windows 用户绝对路径", re.compile(r"[A-Za-z]:\\Users\\[^\\\s\"']+")),
    ("POSIX home 绝对路径", re.compile(r"/(?:home|Users)/[^/\s\"']+/")),
]

# 当前这台机器的主人是谁 —— 用来把「你的路径」和「别人资料里的路径」分开。
# 注意：Windows 账号名不一定等于用户目录名（两者可能不同），
# 所以两个都收，任一命中就算本人。
_CURRENT_USERS = {
    x.lower() for x in (
        os.environ.get("USERNAME", ""),
        os.environ.get("USER", ""),
        Path.home().name,
    ) if x
}


def _is_own_path(matched: str) -> bool:
    """当前用户家目录下的路径算自己的；别人资料里出现的家目录路径不算泄漏。"""
    m = re.match(r"(?i)^[A-Za-z]:\\Users\\([^\\]+)", matched)
    if not m:
        m = re.match(r"(?i)^/(?:home|Users)/([^/]+)/", matched)
    if not m:
        return True                      # 认不出来就当自己的，宁可多报
    return _CURRENT_USERS and m.group(1).lower() in _CURRENT_USERS


# 文档里的占位符不是路径：C:\Users\<you>、/Users/yourname/、C:\Users\%USERNAME%
_PLACEHOLDER = re.compile(
    r"(?i)([<>%]|\\Users\\(you|your|yourname|username|user|name|me)\b"
    r"|/(?:Users|home)/(you|your|yourname|username|user|name|me)/)")


def _is_placeholder_path(matched: str) -> bool:
    return bool(_PLACEHOLDER.search(matched))


# ──────────────────────────────────────────────────────────────────────
# 数据结构
# ──────────────────────────────────────────────────────────────────────
@dataclass
class Check:
    id: str
    title: str
    state: str = "UNKNOWN"          # PASS / FAIL / UNKNOWN
    applicable: bool = True
    blocking: bool = True           # False = 只报告，不影响总判定（由 risk 推导）
    risk: str = "medium"            # critical / high / medium / low
    remediation: str = ""           # 不通过时怎么改
    refs: tuple = ()                # 标准出处
    detail: str = ""
    command: str = ""
    exit_code: int | None = None
    output: str = ""
    findings: list = field(default_factory=list)
    # 不是问题、但值得说一声的观察（例如「站点根绝对路径，本地无法判」）。
    # 和 findings 分开：findings 只装真问题，PASS 就不该有 findings。
    hints: list = field(default_factory=list)
    seconds: float = 0.0
    # 证据文件（截图等）的临时目录。检查自己不做清理，交给 write_artifacts：
    # 有 artifacts 就复制进去再删，没 artifacts 就直接删 —— 两头都不留垃圾。
    evidence: dict | None = None

    def as_dict(self) -> dict:
        d = asdict(self)
        d["refs"] = list(self.refs)
        return d


@dataclass
class Report:
    project: str
    started: str
    seconds: float
    files: int
    by_ext: dict
    checks: list
    verdict: str
    git: dict
    notes: list
    cache: dict

    def as_dict(self) -> dict:
        return {
            "project": self.project,
            "version": VERSION,
            "started": self.started,
            "seconds": round(self.seconds, 3),
            "files": self.files,
            "by_ext": self.by_ext,
            "verdict": self.verdict,
            "git": self.git,
            "notes": self.notes,
            "cache": self.cache,
            "checks": [c.as_dict() for c in self.checks],
        }


# ──────────────────────────────────────────────────────────────────────
# 基础工具
# ──────────────────────────────────────────────────────────────────────
def _glob_match(rel: str, name: str, pattern: str) -> bool:
    """fnmatch 的 `**/x` 不会匹配根目录下的 x（它把 * 当普通字符，但要求有斜杠）。
    这里补一条：`**/x` 同时匹配 x 本身。"""
    if fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(name, pattern):
        return True
    if pattern.startswith("**/"):
        p = pattern[3:]
        return fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(name, p)
    return False


def _ignore_patterns(f: Path) -> list[str]:
    if not f.exists():
        return []
    try:
        lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    out = []
    for ln in lines:
        s = ln.strip()
        if not s or s.lstrip().startswith("#"):
            continue
        out.append(s.rstrip("/"))          # `_sp/` 与 `_sp` 等价
    return out


def scan_files(root: Path, limit: int = 200_000,
               ignores: list[str] | None = None) -> tuple[list[Path], dict, int, int]:
    """遍历项目。`.verifyignore` 按**目录**生效（像 .gitignore）。

    只在根读 ignore 是不够的：对工作区跑的时候，子项目自己的 .verifyignore
    全被忽略，于是子项目里排掉的模板又会冒出来。
    """
    out: list[Path] = []
    by_ext: dict[str, int] = {}
    skipped = 0
    ignored = 0
    root_ig = list(ignores or [])
    # 目录 → 该目录自己的 ignore 规则
    dir_ig: dict[Path, list[str]] = {}

    for dirpath, dirnames, filenames in os.walk(root):
        d = Path(dirpath)
        if d not in dir_ig:
            dir_ig[d] = _ignore_patterns(d / ".verifyignore")
        # 该目录所有祖先（含自身）生效的规则
        chain: list[tuple[Path, list[str]]] = []
        cur = d
        while True:
            if cur in dir_ig:
                pats = dir_ig[cur]
            elif cur == root:
                pats = root_ig
            else:
                pats = []
            if pats:
                chain.append((cur, pats))
            if cur == root or cur.parent == cur:
                break
            cur = cur.parent

        def hit(path: Path, name: str) -> bool:
            for base, pats in chain:
                try:
                    rel = path.relative_to(base).as_posix()
                except ValueError:
                    continue
                if any(_glob_match(rel, name, pat) for pat in pats):
                    return True
            return False

        # 目录也要过滤：`_sp/` 这种规则是要整棵子树都不扫的
        keep = []
        for name in dirnames:
            if name.lower() in SKIP_DIRS:
                continue
            # 备份/草稿目录默认跳过：它们和正本重名，会把同一条 finding 报两遍。
            # （实测：my-site.backup-20260924 让 each finding 翻倍）
            if BACKUP_DIR_RE.search(name):
                _SKIPPED_BACKUPS.append(name)
                ignored += 1
                continue
            if chain and hit(d / name, name):
                ignored += 1
                continue
            keep.append(name)
        dirnames[:] = keep

        for name in filenames:
            p = d / name
            if chain and hit(p, name):
                ignored += 1
                continue
            try:
                if p.stat().st_size > MAX_FILE_BYTES:
                    skipped += 1
                    continue
            except OSError:
                continue
            out.append(p)
            ext = p.suffix.lower() or "(无扩展名)"
            by_ext[ext] = by_ext.get(ext, 0) + 1
            if len(out) >= limit:
                return out, by_ext, skipped, ignored
    return out, by_ext, skipped, ignored


def _read(path: Path) -> str | None:
    """读文本。走共享缓存 —— 同一份文件会被 6 个检查各读一遍，
    11k 文件的项目上这一点就是十几秒的差别。"""
    if _READER is not None:
        return _READER.get(path)
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


class _Reader:
    """按字节预算缓存文件内容；多线程共用。"""

    def __init__(self, budget_mb: int = 256):
        self.lock = threading.Lock()
        self.cache: dict[Path, str] = {}
        self.bytes = 0
        self.budget = budget_mb * 1024 * 1024

    def get(self, p: Path) -> str | None:
        with self.lock:
            if p in self.cache:
                return self.cache[p]
        try:
            t = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
        self.put(p, t)
        return t

    def put(self, p: Path, t: str) -> None:
        with self.lock:
            if p in self.cache:
                return
            if self.bytes + len(t) <= self.budget:
                self.cache[p] = t
                self.bytes += len(t)


_READER: _Reader | None = None


def _strip_bom(s: str) -> str:
    """Python 的 ast.parse / json.loads 看到开头的 U+FEFF 会直接报错，
    但真实解释器按 utf-8-sig 读是能跑的 —— 读进来先去掉，免得把
    「文件带 BOM」误报成「语法错误」。（BOM 本身由 bom 检查单独记。）"""
    return s[1:] if s.startswith("\ufeff") else s


def _rel(root: Path, p: Path) -> str:
    try:
        return p.relative_to(root).as_posix()
    except ValueError:
        return str(p)


def _tail(text: str, n: int = 1200) -> str:
    return (text or "").strip()[-n:]


def _which(cmd: str) -> str:
    """Windows 上 npm / npx 是 .cmd，直接 spawn "npm" 会 FileNotFoundError。
    先 which，找不到再试 .cmd —— 不这样就永远 127，测试检查形同虚设。"""
    p = shutil.which(cmd)
    if p:
        return p
    if os.name == "nt":
        for ext in (".cmd", ".exe", ".bat"):
            p = shutil.which(cmd + ext)
            if p:
                return p
    return cmd


def _run(cmd: list[str], cwd: Path, timeout: int) -> tuple[int, str]:
    argv = [_which(cmd[0])] + list(cmd[1:])
    try:
        r = subprocess.run(argv, cwd=str(cwd), capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=timeout)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except FileNotFoundError:
        return 127, f"命令不存在：{cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, f"超时（>{timeout}s）：{' '.join(cmd)}"
    except OSError as e:
        return 126, f"起不来：{e}"


def _node_error_line(out: str) -> str:
    for ln in (out or "").splitlines():
        s = ln.strip()
        if s and "Error" in s:
            return s[:200]
    s = (out or "").strip()
    return s.splitlines()[0][:200] if s else "node --check 失败"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ──────────────────────────────────────────────────────────────────────
# 语法缓存：(路径, mtime_ns, size) → 结果
# ──────────────────────────────────────────────────────────────────────
class Cache:
    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self.path = CACHE_DIR / "syntax-cache.json"
        self.data: dict[str, dict] = {}
        self.hits = 0
        self.misses = 0
        if enabled:
            try:
                self.data = json.loads(self.path.read_text(encoding="utf-8"))
            except Exception:
                self.data = {}

    def key(self, p: Path) -> tuple[str, dict]:
        try:
            st = p.stat()
        except OSError:
            return "", {}
        return str(p.resolve()), {"mtime": st.st_mtime_ns, "size": st.st_size}

    def get(self, p: Path) -> dict | None:
        if not self.enabled:
            return None
        k, meta = self.key(p)
        hit = self.data.get(k)
        if hit and hit.get("mtime") == meta["mtime"] and hit.get("size") == meta["size"]:
            self.hits += 1
            return hit
        return None

    def put(self, p: Path, ok: bool, msg: str = ""):
        if not self.enabled:
            return
        k, meta = self.key(p)
        if k:
            self.data[k] = {"mtime": meta["mtime"], "size": meta["size"],
                            "ok": ok, "msg": msg}

    def save(self):
        if not self.enabled:
            return
        try:
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            # 只留最近 5000 条，别让缓存无限长
            if len(self.data) > 5000:
                keys = list(self.data)[-5000:]
                self.data = {k: self.data[k] for k in keys}
            self.path.write_text(json.dumps(self.data, ensure_ascii=False),
                                 encoding="utf-8")
        except Exception:
            pass


# ──────────────────────────────────────────────────────────────────────
# 1. 语法
# ──────────────────────────────────────────────────────────────────────
def check_syntax(root: Path, files: list[Path], ctx: "Ctx") -> Check:
    c = Check("syntax", "语法：每个源文件都要能被解析")
    t0 = time.time()
    pys = [p for p in files if p.suffix.lower() in PY_EXT]
    jss = [p for p in files if p.suffix.lower() in JS_EXT]
    jsonf = [p for p in files if p.suffix.lower() in JSON_EXT]
    tomlf = [p for p in files if p.suffix.lower() == ".toml"]
    if not (pys or jss or jsonf or tomlf):
        c.state, c.applicable = "UNKNOWN", False
        c.detail = "项目里没有 .py / .js / .json / .toml 文件"
        return c

    bad: list[dict] = []
    for p in pys:
        src = _read(p)
        if src is None:
            bad.append({"file": _rel(root, p), "line": 0, "message": "读不出来"})
            continue
        try:
            ast.parse(_strip_bom(src), filename=str(p))
        except SyntaxError as e:
            bad.append({"file": _rel(root, p), "line": e.lineno or 0, "message": f"{e.msg}"})
    for p in jsonf:
        try:
            json.loads(_strip_bom(_read(p) or ""))
        except json.JSONDecodeError as e:
            bad.append({"file": _rel(root, p), "line": e.lineno, "message": f"JSON: {e.msg}"})
    for p in tomlf:
        try:
            tomllib.loads(_strip_bom(_read(p) or ""))
        except Exception as e:
            bad.append({"file": _rel(root, p), "line": 0, "message": f"TOML: {e}"[:160]})

    # JS：先查缓存，只对没命中/变了的文件起 node --check，并行
    todo: list[Path] = []
    for p in jss:
        hit = ctx.cache.get(p)
        if hit is not None:
            if not hit.get("ok"):
                bad.append({"file": _rel(root, p), "line": 0,
                            "message": hit.get("msg") or "node --check 失败"})
            continue
        todo.append(p)

    capped = todo[:JS_CHECK_CAP]
    js_skipped = len(todo) - len(capped)
    no_node = False
    if capped:
        def one(p: Path):
            code, out = _run(["node", "--check", str(p)], root, 30)
            return p, code, out

        with ThreadPoolExecutor(max_workers=ctx.workers) as ex:
            for p, code, out in ex.map(one, capped):
                if code == 127:
                    no_node = True
                    break
                if code == 0:
                    ctx.cache.put(p, True)
                else:
                    msg = _node_error_line(out)
                    ctx.cache.put(p, False, msg)
                    bad.append({"file": _rel(root, p), "line": 0, "message": msg})
        if no_node:
            c.state, c.applicable = "UNKNOWN", False
            c.detail = "这台机器上没有 node，JS 语法无法检查"
            c.seconds = time.time() - t0
            return c

    c.findings = bad
    c.state = "FAIL" if bad else "PASS"
    c.detail = (f"py {len(pys)} / js {len(jss)}（缓存命中 {ctx.cache.hits}）/ "
                f"json {len(jsonf)} / toml {len(tomlf)}；失败 {len(bad)}"
                + (f"；另有 {js_skipped} 个 js 超出单次上限未查" if js_skipped else ""))
    c.command = "ast.parse + node --check + json.loads + tomllib"
    c.exit_code = 0 if not bad else 1
    c.seconds = time.time() - t0
    return c


# ──────────────────────────────────────────────────────────────────────
# 2. 链接与锚点
# ──────────────────────────────────────────────────────────────────────
INLINE_SCRIPT = re.compile(r"(?is)<script(?![^>]*\bsrc=)[^>]*>.*?</script>")
INLINE_STYLE = re.compile(r"(?is)<style[^>]*>.*?</style>")


def _strip_inline(t: str) -> str:
    return INLINE_STYLE.sub("", INLINE_SCRIPT.sub("", t))


def check_links(root: Path, files: list[Path], ctx: "Ctx") -> Check:
    c = Check("links", "链接：相对链接与锚点都要能落地")
    t0 = time.time()
    htmls = [p for p in files if p.suffix.lower() in HTML_EXT]
    if not htmls:
        c.state, c.applicable = "UNKNOWN", False
        c.detail = "项目里没有 HTML 文件"
        return c

    texts = {p: _strip_inline(_read(p) or "") for p in htmls}
    ids = {p: set(re.findall(r'''(?i)\bid\s*=\s*["']([^"']+)["']''', t))
           for p, t in texts.items()}
    dead, anchors, abs_paths = [], [], []
    for p, t in texts.items():
        for m in re.finditer(r'''(?i)(?:href|src)\s*=\s*["']([^"']+)["']''', t):
            raw = m.group(1).strip()
            if not raw or re.match(r"^(?:https?:|mailto:|tel:|data:|javascript:|//)", raw, re.I):
                continue
            line = t.count("\n", 0, m.start()) + 1
            if raw.startswith("#"):
                if raw[1:] and raw[1:] not in ids[p]:
                    anchors.append({"file": _rel(root, p), "line": line,
                                    "message": f"页内锚点不存在：{raw}"})
                continue
            if raw.startswith("/"):
                abs_paths.append({"file": _rel(root, p), "line": line,
                                  "message": f"站点根绝对路径，本地无法判定：{raw}"})
                continue
            path = raw.split("#")[0].split("?")[0]
            if not path:
                continue
            tgt = (p.parent / path).resolve()
            if not tgt.exists():
                dead.append({"file": _rel(root, p), "line": line, "message": f"死链：{raw}"})
            elif "#" in raw:
                frag = raw.split("#", 1)[1]
                if tgt in ids and frag and frag not in ids[tgt]:
                    anchors.append({"file": _rel(root, p), "line": line,
                                    "message": f"跨页锚点不存在：{raw}"})

    real = dead + anchors
    # 「站点根绝对路径」不是问题，只是本地没法判 —— 放进 hints。
    # findings 必须只装真问题：PASS 却带着一堆 findings，会让人以为哪儿坏了。
    c.findings = real
    c.hints = abs_paths
    c.state = "FAIL" if real else "PASS"
    c.detail = (f"{len(htmls)} 个页面；死链 {len(dead)}、坏锚点 {len(anchors)}"
                + (f"、站点根绝对路径 {len(abs_paths)}（本地无法判，见提示）" if abs_paths else ""))
    c.command = "内置解析（href/src）"
    c.exit_code = 0 if not real else 1
    c.seconds = time.time() - t0
    return c


# ──────────────────────────────────────────────────────────────────────
# 3. HTML 结构
# ──────────────────────────────────────────────────────────────────────
VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link",
        "meta", "param", "source", "track", "wbr"}
BLOCK_P = re.compile(r"<(?:div|table|ul|ol|section|h[1-6]|p|form|blockquote)\b", re.I)


def _scan_html(p: Path, t: str, root: Path) -> tuple[list[dict], list[dict]]:
    """返回 (结构性, 规范性)。结构性问题算 bug；规范性只提示。

    分开的原因：`h1 有两个` 在双语 404 页上是故意的，`img 缺 alt` 是风格问题，
    它们不该让整个项目判 FAIL；而标签没闭合、id 重复会真的坏功能。
    """
    structural: list[dict] = []
    polish: list[dict] = []
    t = _strip_inline(t)
    rel = _rel(root, p)

    # 标签配平
    stack: list[tuple[str, int]] = []
    for m in re.finditer(r"<(/?)([a-zA-Z][\w:-]*)([^>]*?)(/?)>", t):
        closing, tag, attrs, selfclose = m.group(1), m.group(2).lower(), m.group(3), m.group(4)
        line = t.count("\n", 0, m.start()) + 1
        if tag in VOID or selfclose:
            continue
        if not closing:
            stack.append((tag, line))
        else:
            if stack and stack[-1][0] == tag:
                stack.pop()
            else:
                idx = next((i for i in range(len(stack) - 1, -1, -1) if stack[i][0] == tag), None)
                if idx is None:
                    structural.append({"file": rel, "line": line, "message": f"孤立的 </{tag}>"})
                else:
                    skipped = [x[0] for x in stack[idx + 1:]]
                    structural.append({"file": rel, "line": line,
                                       "message": f"</{tag}> 收尾时还有未闭合的 {skipped}"})
                    del stack[idx:]
    for tag, line in stack[:5]:
        structural.append({"file": rel, "line": line, "message": f"未闭合的 <{tag}>"})

    # 重复 id（会让锚点失效，算结构问题）
    seen: dict[str, int] = {}
    for m in re.finditer(r'''(?i)\bid\s*=\s*["']([^"']+)["']''', t):
        v = m.group(1)
        line = t.count("\n", 0, m.start()) + 1
        if v in seen:
            structural.append({"file": rel, "line": line, "message": f"重复 id「{v}」"})
        else:
            seen[v] = line

    # 以下只提示
    for m in re.finditer(r"<img\b([^>]*)>", t, re.I):
        if not re.search(r"\balt\s*=", m.group(1), re.I):
            polish.append({"file": rel, "line": t.count("\n", 0, m.start()) + 1,
                           "message": "<img> 缺 alt"})
    n_h1 = len(re.findall(r"<h1\b", t, re.I))
    if n_h1 > 1:
        polish.append({"file": rel, "line": 0, "message": f"h1 有 {n_h1} 个"})
    if not re.search(r"<title>[^<]*\S[^<]*</title>", t, re.I):
        polish.append({"file": rel, "line": 0, "message": "缺 <title> 或为空"})
    if not re.search(r"<html[^>]*\slang=", t, re.I):
        polish.append({"file": rel, "line": 0, "message": "<html> 缺 lang"})
    for m in re.finditer(r"<a\b[^>]*target\s*=\s*[\"']_blank[\"'][^>]*>", t, re.I):
        if "noopener" not in m.group(0) and "noreferrer" not in m.group(0):
            polish.append({"file": rel, "line": t.count("\n", 0, m.start()) + 1,
                           "message": "target=_blank 缺 rel=noopener"})
    return structural, polish


def check_html(root: Path, files: list[Path], ctx: "Ctx") -> Check:
    c = Check("html", "HTML 结构：标签配平、重复 id")
    t0 = time.time()
    htmls = [p for p in files if p.suffix.lower() in HTML_EXT]
    if not htmls:
        c.state, c.applicable = "UNKNOWN", False
        c.detail = "项目里没有 HTML 文件"
        return c
    hits: list[dict] = []
    for p in htmls:
        structural, _ = _scan_html(p, _read(p) or "", root)
        hits.extend(structural)
    c.findings = hits
    c.state = "FAIL" if hits else "PASS"
    c.detail = f"{len(htmls)} 个页面，结构问题 {len(hits)} 处"
    c.command = "内置结构扫描"
    c.exit_code = 0 if not hits else 1
    c.seconds = time.time() - t0
    return c


def check_a11y(root: Path, files: list[Path], ctx: "Ctx") -> Check:
    c = Check("a11y", "HTML 规范性：alt / h1 / title / lang / rel（默认不阻断）", blocking=False)
    t0 = time.time()
    htmls = [p for p in files if p.suffix.lower() in HTML_EXT]
    if not htmls:
        c.state, c.applicable = "UNKNOWN", False
        c.detail = "项目里没有 HTML 文件"
        return c
    hits: list[dict] = []
    for p in htmls:
        _, polish = _scan_html(p, _read(p) or "", root)
        hits.extend(polish)
    c.findings = hits
    c.state = "FAIL" if hits else "PASS"
    c.detail = f"{len(htmls)} 个页面，提示 {len(hits)} 处"
    c.command = "内置结构扫描（只报告）"
    c.exit_code = 0 if not hits else 1
    c.seconds = time.time() - t0
    return c


# ──────────────────────────────────────────────────────────────────────
# 4-6. 一次扫描，喂五项检查（secrets / paths / todos / encoding / bom）
#
# 为什么合并：这五项都是「逐文件逐行」。分开做就是五遍 11k 文件的
# 读 + decode + splitlines —— 实测在 6.6GB 语料上要 13.5 秒，而且因为
# GIL 串行，开更多线程没用。合成一遍后约为原来的 1/5。
# ──────────────────────────────────────────────────────────────────────
BOM = b"\xef\xbb\xbf"
LOCKFILES = ("package-lock.json", "pnpm-lock.yaml", "yarn.lock")
# 廉价预筛：这 16 个字面量一个都不出现，就不可能命中任何一条正则。
# 绝大多数文件（尤其中文笔记、数据）一个都没有，直接跳过逐行扫描。
MARKERS = (b"sk-", b"ghp", b"akia", b"-----begin", b"password", b"passwd",
           b"pwd", b"secret", b"token", b"users\\", b"/home/", b"/users/",
           b"todo", b"fixme", b"xxx", b"hack")
BIG_SKIP = 2 * 1024 * 1024      # 超过 2MB 的文件只验编码，不做逐行扫描


def scan_text_once(root: Path, files: list[Path]) -> dict:
    secrets_hits, path_hits, todo_hits = [], [], []
    todo_in_string = 0          # 出现在字符串里的待办标记：是标签不是待办，只用于说明
    path_other: list[dict] = []
    enc_bad, bom_hits = [], []
    n_files = 0
    for p in files:
        ext = p.suffix.lower()
        if ext not in TEXT_EXT:
            continue
        n_files += 1
        try:
            raw = p.read_bytes()
        except OSError:
            enc_bad.append({"file": _rel(root, p), "line": 0, "message": "读不出来"})
            continue
        if raw.startswith(BOM):
            bom_hits.append({"file": _rel(root, p), "line": 1, "message": "文件带 UTF-8 BOM"})
            raw_body = raw[3:]
        else:
            raw_body = raw
        # UTF-16：字节层面第一处就解不出来，报「第 0 字节」等于没说，直接点明编码
        if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
            enc_bad.append({"file": _rel(root, p), "line": 0,
                            "message": "UTF-16 编码（带 BOM），不是 UTF-8"})
            continue
        # 先验编码（纯 C 速度），再决定要不要逐行扫
        try:
            raw_body.decode("utf-8")
            text_ok = True
        except UnicodeDecodeError as e:
            enc_bad.append({"file": _rel(root, p), "line": 0,
                            "message": f"不是合法 UTF-8（第 {e.start} 字节）"})
            text_ok = False
        if len(raw_body) > BIG_SKIP:
            continue                      # 大文件只验编码，不逐行扫
        low = raw_body.lower()
        if not any(m in low for m in MARKERS):
            # 一个标记都没有 → 不可能命中任何正则，连解码都省了
            if text_ok and _READER is not None:
                _READER.put(p, raw_body.decode("utf-8", "replace"))
            continue
        text = raw_body.decode("utf-8", "replace")
        if _READER is not None:
            _READER.put(p, text)          # 后面 links / html 检查不必再读一遍
        if not text:
            continue

        is_lock = p.name.lower() in LOCKFILES
        is_code = ext in CODE_EXT
        rel = _rel(root, p)
        for i, line in enumerate(text.splitlines(), 1):
            if not is_lock:
                hit = False
                for label, rx in SECRET_PATTERNS:
                    if rx.search(line):
                        secrets_hits.append({"file": rel, "line": i,
                                             "message": f"{label}：{line.strip()[:90]}"})
                        hit = True
                        break
                if not hit and is_code and CRED_PATTERN[1].search(line):
                    secrets_hits.append({"file": rel, "line": i,
                                         "message": f"{CRED_PATTERN[0]}：{line.strip()[:90]}"})
            for label, rx in LOCAL_PATH_PATTERNS:
                m = rx.search(line)
                if m:
                    # 文档占位符（C:\Users\<you>）既不是泄漏也不是别人的路径，直接跳过
                    if _is_placeholder_path(m.group(0)):
                        break
                    item = {"file": rel, "line": i,
                            "message": f"{label}：{m.group(0)[:60]}"}
                    # 只把「你自己的用户目录」当成问题；别人的（课程资料、
                    # 别人写的示例）是提示。否则一份课程资料能刷出几百条噪声。
                    if _is_own_path(m.group(0)):
                        path_hits.append(item)
                    else:
                        path_other.append(item)
                    break
            if TODO_RE.search(line):
                # 只在**代码文件**里数，且只数**注释里的**待办标记：
                #   · 文档里提到这个词不该算一处待办
                #   · UI 字符串里的「待办统计」也是标签，不是待办
                # 业界（flake8-todo 等）同样只认注释。
                if ext in CODE_EXT or ext in HTML_EXT or ext == ".css":
                    m = TODO_RE.search(line)
                    cpos = _comment_marker_pos(line, ext)
                    if cpos != -1 and cpos < m.start():
                        todo_hits.append({"file": rel, "line": i, "message": line.strip()[:100]})
                    else:
                        todo_in_string += 1
    return {"files": n_files, "secrets": secrets_hits, "paths": path_hits,
            "paths_other": path_other, "todo_in_string": todo_in_string,
            "todos": todo_hits, "encoding": enc_bad, "bom": bom_hits}


def _bundle(ctx: "Ctx", root: Path, files: list[Path]) -> dict:
    # 双检锁：五个检查并行跑时会同时到这里，没有锁就会各扫一遍
    # （实测 5 份并发扫描把 13.8s 拖成 61.9s）。
    if ctx.bundle is None:
        with ctx.bundle_lock:
            if ctx.bundle is None:
                ctx.bundle = scan_text_once(root, files)
    return ctx.bundle


def _mk(cid: str, title: str, ctx: "Ctx", root: Path, files: list[Path],
        key: str, command: str, ok: str, bad: str, blocking: bool = True,
        cap: int | None = None) -> Check:
    c = Check(cid, title, blocking=blocking)
    t0 = time.time()
    if not any(p.suffix.lower() in TEXT_EXT for p in files):
        c.state, c.applicable = "UNKNOWN", False
        c.detail = "没有可扫描的文本文件"
        return c
    b = _bundle(ctx, root, files)
    hits = b.get(key, [])
    c.findings = hits[:cap] if cap else hits
    c.state = "FAIL" if hits else "PASS"
    c.detail = (bad.format(n=len(hits)) if hits else ok.format(n=b.get("files", 0)))
    c.command = command
    c.exit_code = 0 if not hits else 1
    c.seconds = time.time() - t0
    return c


def check_secrets(root: Path, files: list[Path], ctx: "Ctx") -> Check:
    return _mk("secrets", "密钥：代码里不该出现真凭据", ctx, root, files, "secrets",
               "内置正则（4 类真凭据 + 代码里的明文密码）",
               "{n} 个文本文件里没命中", "命中 {n} 处")


def check_paths(root: Path, files: list[Path], ctx: "Ctx") -> Check:
    """本机绝对路径：默认不参与总判定（本地脚本写死路径很常见，发布前才要紧）。

    只把**当前用户**的路径算问题；课程资料、别人写的示例里的 `/Users/xxx`
    进 hints —— 那不是你的泄漏。
    """
    c = _mk("paths", "本机绝对路径（默认不阻断）", ctx, root, files, "paths",
            "内置正则（Windows / POSIX 家目录）",
            "{n} 个文本文件里没命中", "命中 {n} 处", blocking=False)
    if ctx.bundle:
        others = ctx.bundle.get("paths_other") or []
        c.hints = others[:50]
        if others:
            c.detail += f"（另有 {len(others)} 处是别人的路径，见提示）"
    return c


def check_encoding(root: Path, files: list[Path], ctx: "Ctx") -> Check:
    return _mk("encoding", "编码：文本文件必须是合法 UTF-8", ctx, root, files, "encoding",
               "bytes.decode('utf-8')",
               "检查 {n} 个文件，全部合法", "非法 {n} 个")


def check_bom(root: Path, files: list[Path], ctx: "Ctx") -> Check:
    """UTF-8 BOM：非阻断。多数场景无害，但会让 CSS/JS 首行规则失效、git diff 多一个隐形字符。"""
    return _mk("bom", "UTF-8 BOM（默认不阻断）", ctx, root, files, "bom",
               "前 3 字节 == EF BB BF",
               "没有文件带 BOM", "{n} 个文件带 BOM", blocking=False)


# ──────────────────────────────────────────────────────────────────────
# 9b. 浏览器运行时（Playwright）
#
# runtime-web 只证明「文件取得到」，证明不了「页面跑起来是对的」。
# 这一层真的把页面跑起来，抓 JS 异常、console.error、资源 404。
# 没有 playwright 就老实记 UNKNOWN —— 不假装验过。
# ──────────────────────────────────────────────────────────────────────
def _find_playwright(root: Path) -> Path | None:
    """找一个 node 能 require 到 playwright 的目录。"""
    here = Path(__file__).resolve().parent
    home = Path.home()
    for d in (root, here, home / "AppData/Roaming/npm", home / ".npm-global",
              Path.home() / "node_modules"):
        try:
            if (d / "node_modules" / "playwright").is_dir():
                return d
        except OSError:
            continue
    return None


def check_browser(root: Path, files: list[Path], ctx: "Ctx") -> Check:
    c = Check("browser", "浏览器运行时：页面跑起来有没有报错")
    t0 = time.time()
    htmls = [p for p in files if p.suffix.lower() in HTML_EXT]
    if not htmls:
        c.state, c.applicable = "UNKNOWN", False
        c.detail = "项目里没有 HTML，跳过"
        return c
    site_root = _find_site_root(root, htmls)
    if site_root is None:
        c.state, c.applicable = "UNKNOWN", False
        c.detail = "没有 index.html，无法确定站点根"
        return c
    pw_dir = _find_playwright(root) or _find_playwright(site_root)
    if pw_dir is None:
        c.state, c.applicable = "UNKNOWN", False
        c.detail = "没找到 playwright（npm i -D playwright && npx playwright install chromium）"
        return c
    node = shutil.which("node")
    if not node:
        c.state, c.applicable = "UNKNOWN", False
        c.detail = "这台机器上没有 node"
        return c

    import tempfile
    tmp = Path(tempfile.mkdtemp(prefix="vh-browser-"))
    pages_file = tmp / "pages.json"
    out_file = tmp / "out.json"
    shots = tmp / "shots"
    entries = []
    for p in htmls[:30]:
        try:
            rel = p.relative_to(site_root).as_posix()
        except ValueError:
            continue
        entries.append({"rel": rel, "url": f"http://127.0.0.1:0/{rel}"})
    if not entries:
        c.state, c.applicable = "UNKNOWN", False
        c.detail = "页面都不在站点根之下"
        return c

    port = _free_port()
    base = _detect_base(htmls)
    for e in entries:
        e["url"] = f"http://127.0.0.1:0{base}/{e['rel']}"
    pages_file.write_text(json.dumps(entries, ensure_ascii=False), encoding="utf-8")

    httpd = None
    try:
        httpd, port = _serve(site_root, base)
        for e in entries:
            e["url"] = f"http://127.0.0.1:{port}{base}/{e['rel']}"
        pages_file.write_text(json.dumps(entries, ensure_ascii=False), encoding="utf-8")

        probe = Path(__file__).resolve().parent / "browser_probe.mjs"
        cmd = [node, str(probe), "--module", str(pw_dir),
               "--base", f"http://127.0.0.1:{port}",
               "--pages", str(pages_file), "--out", str(out_file),
               "--shots", str(shots)]
        code, out = _run(cmd, root, ctx.browser_timeout)
        if code != 0 or not out_file.exists():
            c.state = "UNKNOWN"
            c.detail = f"探针没跑成（退出码 {code}）：{_tail(out, 200)}"
        else:
            data = json.loads(out_file.read_text(encoding="utf-8"))
            # 截图现在会被 rmtree 掉（实测：报「截图 12 张」但 artifacts 里 0 张）。
            # 先搬到独立的证据目录，再让 write_artifacts 决定「归档还是删除」。
            try:
                if shots.is_dir() and any(shots.iterdir()):
                    ev = Path(tempfile.mkdtemp(prefix="vh-evidence-")) / "browser"
                    shutil.move(str(shots), str(ev))
                    c.evidence = {"dir": str(ev), "kind": "browser-screenshots",
                                  "count": len(list(ev.glob("*.png")))}
            except Exception:
                pass
            findings = []
            for pg in data.get("pages", []):
                rel = pg.get("rel", "?")
                if pg.get("error"):
                    findings.append({"file": rel, "line": 0,
                                     "message": f"页面加载失败：{pg['error']}",
                                     "severity": "high"})
                if pg.get("status") and pg["status"] != 200:
                    findings.append({"file": rel, "line": 0,
                                     "message": f"HTTP {pg['status']}",
                                     "severity": "high"})
                for err in pg.get("pageerrors", []):
                    findings.append({"file": rel, "line": 0,
                                     "message": f"未捕获异常：{err}"[:300],
                                     "severity": "high"})
                for msg in pg.get("console", []):
                    if msg.get("type") == "error":
                        findings.append({"file": rel, "line": 0,
                                         "message": f"console.error：{msg.get('text')}"[:300],
                                         "severity": "medium"})
                for f in pg.get("failed", []):
                    findings.append({"file": rel, "line": 0,
                                     "message": f"资源失败 {f.get('reason')}：{f.get('url')}"[:300],
                                     "severity": "high"})
            c.findings = findings
            c.state = "FAIL" if findings else "PASS"
            shots_n = len(data.get("shots", []))
            c.detail = (f"站点根 {_rel(root, site_root) or '.'}"
                        + (f"（部署前缀 {base}）" if base else "")
                        + f"，真跑 {len(data.get('pages', []))} 页，"
                        f"问题 {len(findings)} 处" + (f"，截图 {shots_n} 张" if shots_n else ""))
            c.command = f"playwright(chromium) + http.server:{port}"
            c.exit_code = 0 if not findings else 1
    except Exception as e:
        c.state = "UNKNOWN"
        c.detail = f"浏览器层出错：{type(e).__name__}: {e}"
    finally:
        if httpd:
            httpd.shutdown()
            httpd.server_close()
        shutil.rmtree(tmp, ignore_errors=True)
    c.seconds = time.time() - t0
    return c


# ──────────────────────────────────────────────────────────────────────
# 9c. 交互测试：真的点、填、选，然后断言结果
#
# browser 检查只证明「页面能打开」；这一层证明「点了有反应」。
# 流程写在 verify.toml 的 [[flows]] 里，由 flow_runner.mjs 逐条执行。
# ──────────────────────────────────────────────────────────────────────
FLOW_ACTIONS = {"goto", "click", "fill", "select", "press", "wait", "expect"}
EXPECT_KEYS = {"selector", "visible", "text_contains", "url_contains",
               "input_value", "no_console_error", "timeout"}


def _load_flows(root: Path) -> tuple[list[dict], str]:
    """读 verify.toml 的 [[flows]]。返回 (flows, 错误说明)。"""
    cfg = root / "verify.toml"
    if not cfg.exists():
        return [], "没有 verify.toml"
    try:
        data = tomllib.loads(_strip_bom(cfg.read_text(encoding="utf-8")))
    except Exception as e:
        return [], f"verify.toml 解析失败：{e}"

    raw = data.get("flows")
    if raw is None:
        return [], "verify.toml 里没有 [[flows]]"
    if not isinstance(raw, list):
        return [], "[[flows]] 必须是数组"

    flows: list[dict] = []
    for i, f in enumerate(raw, 1):
        if not isinstance(f, dict):
            return [], f"第 {i} 条流程不是表"
        name = str(f.get("name") or f"flow{i}")
        steps = f.get("steps")
        if not isinstance(steps, list) or not steps:
            return [], f"「{name}」没有 steps"
        clean = []
        for j, s in enumerate(steps, 1):
            if not isinstance(s, dict):
                return [], f"「{name}」第 {j} 步不是表"
            acts = set(s) & FLOW_ACTIONS
            if not acts:
                return [], (f"「{name}」第 {j} 步没有可识别的动作"
                            f"（可用：{', '.join(sorted(FLOW_ACTIONS))}）")
            if len(acts) > 1:
                return [], f"「{name}」第 {j} 步写了多个动作：{', '.join(sorted(acts))}"
            if "expect" in acts:
                exp = s["expect"]
                if not isinstance(exp, dict):
                    return [], f"「{name}」第 {j} 步的 expect 必须是表"
                unknown = set(exp) - EXPECT_KEYS
                if unknown:
                    return [], (f"「{name}」第 {j} 步的 expect 有不认识的键："
                                f"{', '.join(sorted(unknown))}")
                if not (exp.get("no_console_error") or exp.get("url_contains")
                        or exp.get("selector")):
                    return [], f"「{name}」第 {j} 步的 expect 缺少 selector / url_contains / no_console_error"
            clean.append(s)
        flows.append({"name": name, "steps": clean})
    return flows, ""


def check_interaction(root: Path, files: list[Path], ctx: "Ctx") -> Check:
    c = Check("interaction", "交互测试：点击 / 表单 / 跳转之后对不对")
    t0 = time.time()
    flows, why = _load_flows(root)
    if not flows:
        c.state, c.applicable = "UNKNOWN", False
        c.detail = why
        return c
    if ctx.fast:
        c.state, c.applicable = "UNKNOWN", False
        c.detail = f"{len(flows)} 条流程（fast 模式跳过交互测试）"
        return c

    htmls = [p for p in files if p.suffix.lower() in HTML_EXT]
    site_root = _find_site_root(root, htmls) or root
    pw_dir = _find_playwright(root) or _find_playwright(site_root)
    if pw_dir is None:
        c.state, c.applicable = "UNKNOWN", False
        c.detail = "没找到 playwright，交互测试跑不了"
        return c
    node = shutil.which("node")
    if not node:
        c.state, c.applicable = "UNKNOWN", False
        c.detail = "这台机器上没有 node"
        return c

    import tempfile
    tmp = Path(tempfile.mkdtemp(prefix="vh-flow-"))
    spec_file = tmp / "spec.json"
    out_file = tmp / "out.json"
    shots = tmp / "shots"

    base = _detect_base(htmls)
    httpd = None
    try:
        httpd, port = _serve(site_root, base)
        spec_file.write_text(json.dumps(
            {"base": f"http://127.0.0.1:{port}{base}", "timeoutMs": ctx.flow_timeout,
             "flows": flows}, ensure_ascii=False), encoding="utf-8")

        runner = Path(__file__).resolve().parent / "flow_runner.mjs"
        code, out = _run([node, str(runner), "--module", str(pw_dir),
                          "--spec", str(spec_file), "--out", str(out_file),
                          "--shots", str(shots)], root, ctx.flow_total_timeout)
        if code != 0 or not out_file.exists():
            c.state = "UNKNOWN"
            c.detail = f"流程执行器没跑成（退出码 {code}）：{_tail(out, 200)}"
        else:
            data = json.loads(out_file.read_text(encoding="utf-8"))
            results = data.get("flows", [])
            failed = [r for r in results if not r.get("passed")]
            findings = []
            for r in failed:
                fs = r.get("failedStep") or {}
                msg = f"「{r.get('name')}」第 {fs.get('index')} 步 {fs.get('action')} 失败：{fs.get('detail')}"
                line = fs.get("index") if isinstance(fs.get("index"), int) and fs["index"] > 0 else 0
                findings.append({"file": r.get("name", "flow"), "line": line,
                                 "message": msg[:400],
                                 "shot": r.get("shot")})
            c.findings = findings
            c.state = "FAIL" if failed else "PASS"
            c.detail = f"{len(flows)} 条流程，通过 {len(results) - len(failed)}，失败 {len(failed)}"
            if base:
                c.detail += f"（部署前缀 {base}）"
            c.command = f"playwright(chromium) 逐条执行 verify.toml [[flows]]"
            c.exit_code = 0 if not failed else 1
    except Exception as e:
        c.state = "UNKNOWN"
        c.detail = f"交互测试出错：{type(e).__name__}: {e}"
    finally:
        if httpd:
            httpd.shutdown()
            httpd.server_close()
        if c.state != "FAIL":
            shutil.rmtree(tmp, ignore_errors=True)   # 失败时保留截图作为证据
        else:
            c.detail += f"；证据在 {tmp}"
    c.seconds = time.time() - t0
    return c


# ──────────────────────────────────────────────────────────────────────
# 13. 变异门（opt-in）
#
# 覆盖率只说明「执行到了」，变异测试说明「断言有效」。
# 全量变异太慢，所以：只打 git diff 的行，最多 max_mutants 个。
# 默认不跑（不在 ORDER 里），需要 --checks mutation 显式打开。
# ──────────────────────────────────────────────────────────────────────
MUTATIONS_PY = [
    (" == ", " != "), (" != ", " == "),
    (" >= ", " > "), (" <= ", " < "),
    (" > ", " >= "), (" < ", " <= "),
    (" + ", " - "), (" and ", " or "),
    ("True", "False"), ("False", "True"),
]


def _changed_lines(root: Path) -> dict[str, set[int]]:
    """git diff 里改动的行（按文件）。不在 git 里就返回空。"""
    if not (root / ".git").exists():
        return {}
    code, out = _run(["git", "diff", "--unified=0", "HEAD"], root, 60)
    if code != 0:
        return {}
    changed: dict[str, set[int]] = {}
    cur = None
    for ln in out.splitlines():
        if ln.startswith("+++ b/"):
            cur = ln[6:].strip()
            changed.setdefault(cur, set())
        elif ln.startswith("@@") and cur:
            m = re.search(r"\+(\d+)(?:,(\d+))?", ln)
            if m:
                start = int(m.group(1))
                count = int(m.group(2) or 1)
                changed[cur].update(range(start, start + count))
    return changed


def check_mutation(root: Path, files: list[Path], ctx: "Ctx") -> Check:
    c = Check("mutation", "变异门：测试能不能发现改坏的行")
    t0 = time.time()
    if ctx.fast:
        c.state, c.applicable = "UNKNOWN", False
        c.detail = "fast 模式跳过变异"
        return c
    cmd, why, _ = _detect_test_command(root)
    if cmd is None:
        c.state, c.applicable = "UNKNOWN", False
        c.detail = "没有测试入口，变异门无从判定"
        return c

    pys = [p for p in files if p.suffix.lower() in PY_EXT]
    if not pys:
        c.state, c.applicable = "UNKNOWN", False
        c.detail = "没有 .py 文件，变异门目前只支持 Python"
        return c

    changed = _changed_lines(root)
    candidates: list[tuple[Path, int, str, str]] = []
    for p in pys:
        rel = _rel(root, p)
        t = _read(p) or ""
        lines = t.splitlines()
        want = changed.get(rel)
        for i, line in enumerate(lines, 1):
            if want is not None and i not in want:
                continue
            if line.lstrip().startswith("#") or "def " in line or "import " in line:
                continue
            for src_tok, dst_tok in MUTATIONS_PY:
                if src_tok in line:
                    candidates.append((p, i, src_tok, dst_tok))
                    break
    if not candidates:
        c.state, c.applicable = "UNKNOWN", False
        c.detail = "在改动行里没找到可变异的位置"
        return c

    budget = ctx.mutation_max
    survivors, killed, errors = [], 0, []
    for p, lineno, src_tok, dst_tok in candidates[:budget]:
        original = p.read_text(encoding="utf-8", errors="replace")
        lines = original.splitlines(keepends=True)
        if lineno - 1 >= len(lines):
            continue
        mutated_line = lines[lineno - 1].replace(src_tok, dst_tok, 1)
        if mutated_line == lines[lineno - 1]:
            continue
        lines[lineno - 1] = mutated_line
        try:
            p.write_text("".join(lines), encoding="utf-8")
            code, out = _run(cmd, root, ctx.mutation_timeout)
        finally:
            p.write_text(original, encoding="utf-8")     # 一定要还原
        if code == 0:
            survivors.append({
                "file": _rel(root, p), "line": lineno,
                "message": f"把 {src_tok.strip()} 改成 {dst_tok.strip()} 后测试仍然通过 —— 这行没有有效断言",
                "severity": "medium",
            })
        elif code in (124, 127):
            errors.append(f"{_rel(root, p)}:{lineno} 运行时出错（{code}）")
        else:
            killed += 1

    c.findings = survivors
    total = killed + len(survivors)
    if errors:
        c.detail = f"试了 {total} 个变异，存活 {len(survivors)}（另有 {len(errors)} 个跑不起来）"
    else:
        c.detail = f"试了 {total} 个变异，被杀 {killed}，存活 {len(survivors)}"
    c.state = "FAIL" if survivors else ("PASS" if total else "UNKNOWN")
    c.command = " ".join(cmd) + "（逐个变异重跑）"
    c.exit_code = 0 if not survivors else 1
    c.seconds = time.time() - t0
    return c


def check_todos(root: Path, files: list[Path], ctx: "Ctx") -> Check:
    return _mk("todos", "TODO / FIXME 数量（只报告）", ctx, root, files, "todos",
               "正则 TODO|FIXME",
               "没有 TODO", "{n} 处", blocking=False, cap=200)


# ──────────────────────────────────────────────────────────────────────
# 7. 测试
# ──────────────────────────────────────────────────────────────────────
def _looks_like_tests(p: Path) -> bool:
    """文件里真的有测试吗？

    为什么需要：`*_test.py` 会匹配到 `_desktop_mcp_test.py` 这类**探针脚本**
    （里面一个用例都没有，但有 import 副作用）。把它们当测试入口，
    跑 unittest 只会得到 "NO TESTS RAN"，而且可能执行到脚本里的代码。
    """
    try:
        text = p.read_text(encoding="utf-8", errors="ignore")[:120_000]
    except OSError:
        return False
    if p.suffix == ".py":
        return bool(re.search(r"^\s*class\s+\w+\s*\(\s*(unittest\.)?TestCase", text, re.M)
                    or re.search(r"^\s*def\s+test_\w+\s*\(", text, re.M))
    return bool(re.search(r"\b(?:test|it|describe)\s*\(\s*['\"`]", text))


def _py_for(root: Path) -> str:
    """跑 Python 测试用哪个解释器。

    优先**项目自己的 venv**：很多项目的依赖只装在那儿，而且 ABI 可能和系统
    Python 不同（实测：desktop-mcp 的 venv 是 3.12，系统是 3.14，用系统解释器
    跑测试会 import 失败 → 全部用例被跳过 → 看着"绿"其实什么都没验）。
    """
    # ① 显式指定（环境变量）—— 用来对付「仓库里没有 venv，但本机有」的情况
    env = os.environ.get("DSH_TEST_PYTHON")
    if env and Path(env).is_file():
        return env
    # ② 项目根的 .verify-python 文件：一行路径，适合本机配置且可 .gitignore
    ptr = root / ".verify-python"
    if ptr.is_file():
        try:
            cand = ptr.read_text(encoding="utf-8", errors="ignore").strip().splitlines()[0].strip()
            if cand and Path(cand).is_file():
                return cand
        except Exception:
            pass
    # ③ 项目自带的 venv
    for rel in (("venv", "Scripts", "python.exe"), (".venv", "Scripts", "python.exe"),
                ("venv", "bin", "python"), (".venv", "bin", "python")):
        cand = root.joinpath(*rel)
        if cand.is_file():
            return str(cand)
    return sys.executable


def _detect_test_command(root: Path) -> tuple[list[str] | None, str, int]:
    pkg = root / "package.json"
    if pkg.exists():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8"))
            script = (data.get("scripts") or {}).get("test") or ""
            if script and "no test specified" not in script:
                return ["npm", "test", "--silent"], "package.json 的 scripts.test", 300
        except Exception:
            pass
    pyproj = root / "pyproject.toml"
    if pyproj.exists():
        try:
            if "pytest" in pyproj.read_text(encoding="utf-8", errors="replace").lower():
                return [_py_for(root), "-m", "pytest", "-q"], "pytest", 300
        except Exception:
            pass
    if (root / "pytest.ini").exists() or (root / "conftest.py").exists():
        return [_py_for(root), "-m", "pytest", "-q"], "pytest", 300
    tests = root / "tests"
    if tests.is_dir():
        if any(tests.glob("*.py")):
            return [_py_for(root), "-m", "unittest", "discover", "-s", "tests"], \
                "tests/ 下的 unittest", 300
        if any(list(tests.glob("*.mjs")) + list(tests.glob("*.js"))):
            return ["node", "--test", "tests"], "tests/ 下的 node --test", 300
    if (root / "test").is_dir() and any((root / "test").glob("*.py")):
        return [_py_for(root), "-m", "unittest", "discover", "-s", "test"], \
            "test/ 下的 unittest", 300

    # 散落的测试文件：只在本项目和它的 tests/ 里找 ——
    # 去子目录里翻会把「工作区」当成有测试的项目，然后在错误的根上跑。
    def _has(patterns: list[str], dirs: list[Path]) -> bool:
        for d in dirs:
            if not d.is_dir():
                continue
            for pat in patterns:
                try:
                    if next(d.glob(pat), None) is not None:
                        return True
                except OSError:
                    continue
        return False

    dirs = [root] + [root / x for x in ("tests", "test", "src", "__tests__")
                     if (root / x).is_dir()]
    if _has(["*.test.js", "*.test.mjs", "*.test.cjs", "*.spec.js", "*.spec.mjs"], dirs):
        return ["node", "--test"], "node --test 自动发现 *.test.*", 300
    if _has(["*.test.ts", "*.spec.ts"], dirs):
        return ["npx", "vitest", "run"], "vitest（TypeScript 测试）", 420
    # 散落的 test_*.py：必须记清是**哪个目录**命中的 ——
    # 命中 root/tests 却用默认 start dir（=root）去 discover，会收集 0 个用例，
    # 得到一个假的 FAIL（实测：工作区根目录 62 个 py、0 个 test_*.py，退出码 5）。
    probe_dirs = [root] + ([root / "tests"] if (root / "tests").is_dir() else [])
    suspects: list[str] = []
    for d in probe_dirs:
        for pat in ("test_*.py", "*_test.py"):
            try:
                hits = [p for p in d.glob(pat) if p.is_file()]
            except OSError:
                continue
            if not hits:
                continue
            real = [p for p in hits if _looks_like_tests(p)]
            if not real:
                suspects += [f"{d.name}/{p.name}" if d != root else p.name for p in hits[:3]]
                continue
            cmd = [sys.executable, "-m", "unittest", "discover"]
            if d != root:
                cmd += ["-s", d.name]
            # 关键：把**真正命中的模式**带进去。
            # 之前一律 -p test_*.py，于是 `*_test.py` 命中的文件根本没被跑。
            cmd += ["-p", pat]
            where = "根目录" if d == root else f"{d.name}/"
            return cmd, f"{where}下 {pat}（{len(real)} 个文件含用例）", 300

    if suspects:
        return None, ("找到疑似测试文件但里面没有用例："
                      + "、".join(suspects[:4])
                      + "（是脚本的话改个名，或补上 TestCase）"), 0

    return None, ("没有识别到测试入口"
                  "（scripts.test / pytest / tests/*.py / tests/*.mjs / *.test.js / test_*.py）"), 0


def _test_counts(out: str) -> tuple[int, int]:
    """从测试输出里抠出 (跑了几个用例, 跳过几个)。

    unittest: "Ran 10 tests in 0.000s" + "OK (skipped=10)"
    pytest:   "10 skipped in 0.02s" / "5 passed, 3 skipped"
    """
    ran = 0
    m = re.search(r"^Ran (\d+) tests? in", out, re.M)
    if m:
        ran = int(m.group(1))
    else:
        m = re.search(r"(\d+) (?:passed|failed|skipped)", out)
        if m:
            ran = int(m.group(1))
    skipped = 0
    m = re.search(r"skipped=(\d+)", out)
    if m:
        skipped = int(m.group(1))
    else:
        m = re.search(r"(\d+) skipped", out)
        if m:
            skipped = int(m.group(1))
    return ran, skipped


def check_tests(root: Path, files: list[Path], ctx: "Ctx") -> Check:
    c = Check("tests", "测试：跑得起来，且真的通过")
    t0 = time.time()
    if ctx.fast:
        c.state, c.applicable = "UNKNOWN", False
        c.detail = "fast 模式跳过测试"
        return c
    cmd, why, timeout = _detect_test_command(root)
    if cmd is None:
        c.state, c.applicable = "UNKNOWN", False
        c.detail = why
        return c
    code, out = _run(cmd, root, min(timeout, ctx.test_timeout))
    c.command = " ".join(cmd)
    c.exit_code = code
    c.output = _tail(out, 2000)
    if code == 127:
        c.state, c.detail = "UNKNOWN", f"命令跑不起来：{why}"
    elif code == 124:
        c.state, c.detail = "UNKNOWN", f"超时：{why}"
    elif code == 0 and _test_counts(out)[0] > 0 and _test_counts(out)[1] >= _test_counts(out)[0]:
        # 全跳过 = 一个用例都没真跑（典型：解释器 ABI / 依赖不匹配 → import 失败被 skip）。
        # 这种情况判 PASS 就是谎报 —— 它和「0 个用例」一样属于「测不了」。
        ran, skipped = _test_counts(out)
        c.state = "UNKNOWN"
        c.detail = (f"{why}；退出码 0，但 {ran} 个用例里 {skipped} 个被跳过 —— "
                    "没验到任何东西，多半是测试用的解释器或依赖与项目不匹配"
                    "（例如 venv 是 3.12、系统 python 是 3.14）")
    elif code == 5 or "NO TESTS RAN" in out:
        # 识别到了入口，但一个用例都没收集到 —— 这是「测不了」，不是「测不过」。
        # 判成 FAIL 会把"模式没匹配上"说成"测试挂了"，属于谎报。
        c.state = "UNKNOWN"
        c.detail = (f"{why}；但收集到 0 个用例（退出码 {code}）—— "
                    "多半是匹配模式或目录不对，不是用例失败。")
    else:
        c.state = "PASS" if code == 0 else "FAIL"
        c.detail = f"{why}；退出码 {code}"
        # 从输出里抠出失败的用例名，省得再去翻日志
        names = re.findall(r"^(?:FAIL|ERROR):\s+(\S+)", out, re.M)[:10]
        if names:
            c.findings = [{"file": why, "line": 0, "message": n} for n in names]
    c.seconds = time.time() - t0
    return c


# ──────────────────────────────────────────────────────────────────────
# 8. Python 未使用的 import
# ──────────────────────────────────────────────────────────────────────
def check_imports(root: Path, files: list[Path], ctx: "Ctx") -> Check:
    """未使用的 import：非阻断。

    为什么非阻断：`__all__` 再导出、`import x  # noqa` 这类合法写法会被误判，
    它适合当提示，不适合当闸门。
    """
    c = Check("imports", "Python 未使用的 import（默认不阻断）", blocking=False)
    t0 = time.time()
    pys = [p for p in files if p.suffix.lower() in PY_EXT]
    if not pys:
        c.state, c.applicable = "UNKNOWN", False
        c.detail = "项目里没有 .py 文件"
        return c
    hits = []
    for p in pys:
        src = _read(p)
        if not src:
            continue
        try:
            tree = ast.parse(_strip_bom(src))
        except SyntaxError:
            continue                          # 语法错由 syntax 检查负责
        body = src
        # 带 `# noqa` 的行不参与判定 —— 副作用导入（import _bootstrap）、
        # 条件导入、公开再导出都用这个写法，标准 linter 也是这么处理的。
        noqa_lines = {i for i, ln in enumerate(src.splitlines(), 1) if "# noqa" in ln}
        for node in ast.walk(tree):
            if getattr(node, "lineno", 0) in noqa_lines:
                continue
            names: list[tuple[str, int, str]] = []
            if isinstance(node, ast.Import):
                for a in node.names:
                    names.append((a.asname or a.name.split(".")[0], node.lineno, a.name))
            elif isinstance(node, ast.ImportFrom):
                # `from __future__ import annotations` 是编译器指令，不是名字绑定，
                # 永远「用不到」——不能算未使用 import。
                if (node.module or "") == "__future__":
                    continue
                for a in node.names:
                    if a.name == "*":
                        continue
                    names.append((a.asname or a.name, node.lineno, a.name))
            for local, line, orig in names:
                # 去掉 import 行本身再数出现次数
                rest = "\n".join(l for i, l in enumerate(body.splitlines(), 1)
                                 if i != line)
                if not re.search(rf"\b{re.escape(local)}\b", rest):
                    hits.append({"file": _rel(root, p), "line": line,
                                 "message": f"导入了但没用到：{orig}"})
    c.findings = hits
    c.state = "FAIL" if hits else "PASS"
    c.detail = f"扫了 {len(pys)} 个 py 文件，可疑 {len(hits)} 处"
    c.command = "AST 扫描"
    c.exit_code = 0 if not hits else 1
    c.seconds = time.time() - t0
    return c


# ──────────────────────────────────────────────────────────────────────
# 9. 运行时（HTTP）
# ──────────────────────────────────────────────────────────────────────
# ──────────────────────────────────────────────────────────────────────
# 本地静态服务 + 部署前缀
#
# 站点常被部署在子路径下（GitHub Pages 的 /repo/），页面里就写
# `/ausmat-guide/assets/x.css`。直接在根上起服务，这种链接必然 404 ——
# 那是本地环境的假阳性，不是 bug。所以先推断前缀，再把它挂到前缀下。
# ──────────────────────────────────────────────────────────────────────
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer  # noqa: E402
from functools import partial  # noqa: E402


def _detect_base(htmls: list[Path]) -> str:
    """从站点根绝对路径里推断部署前缀，如 `/ausmat-guide`。样本不足就不猜。"""
    counts: dict[str, int] = {}
    for p in htmls[:60]:
        t = _read(p) or ""
        for m in re.finditer(r'''(?i)(?:href|src)\s*=\s*["'](/[^/"']+/[^"']*)["']''', t):
            seg = m.group(1).split("/")[1]
            counts[seg] = counts.get(seg, 0) + 1
    if not counts:
        return ""
    seg, n = max(counts.items(), key=lambda kv: kv[1])
    return f"/{seg}" if n >= 3 else ""


class _PrefixHandler(SimpleHTTPRequestHandler):
    prefix = ""

    def translate_path(self, path: str) -> str:
        if self.prefix:
            if path == self.prefix:
                path = "/"
            elif path.startswith(self.prefix + "/"):
                path = path[len(self.prefix):]
        return super().translate_path(path)

    def log_message(self, *args):
        pass


def _serve(directory: Path, prefix: str = "") -> tuple[ThreadingHTTPServer, int]:
    _PrefixHandler.prefix = prefix
    handler = partial(_PrefixHandler, directory=str(directory))
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, httpd.server_address[1]


def _find_site_root(root: Path, htmls: list[Path]) -> Path | None:
    """找静态站点根：优先项目根的 index.html，其次任意含 index.html 的目录
    （取收录页面最多的那个）。找不到就说明这不是一个可服务的站点。"""
    if (root / "index.html").exists() or (root / "index.htm").exists():
        return root
    cands = {p.parent for p in htmls if p.name.lower() in ("index.html", "index.htm")}
    if not cands:
        return None
    return max(cands, key=lambda d: sum(1 for h in htmls if h.parent == d or d in h.parents))


def check_runtime_web(root: Path, files: list[Path], ctx: "Ctx") -> Check:
    """真起一个静态服务器，逐个 GET 页面 —— 验的是「文件存在」之外的那一层：

    大小写写错、路径多一层、目录索引缺失，只有在 HTTP 语义下才会露出来。
    没有浏览器，所以抓不到 JS 报错（那是 v1.5 的事，这里如实写明）。
    """
    c = Check("runtime-web", "运行时：静态服务器起来后每页都能 200")
    t0 = time.time()
    htmls = [p for p in files if p.suffix.lower() in HTML_EXT]
    if not htmls:
        c.state, c.applicable = "UNKNOWN", False
        c.detail = "项目里没有 HTML，跳过"
        return c
    site_root = _find_site_root(root, htmls)
    if site_root is None:
        c.state, c.applicable = "UNKNOWN", False
        c.detail = "没有 index.html，无法确定站点根（不是可服务的静态站）"
        return c
    port = _free_port()
    base = _detect_base(htmls)
    httpd = None
    try:
        httpd, port = _serve(site_root, base)
        import urllib.request
        import urllib.error
        bad = []
        served = 0
        for p in htmls[:200]:
            try:
                rel = p.relative_to(site_root).as_posix()
            except ValueError:
                continue
            served += 1
            url = f"http://127.0.0.1:{port}{base}/{rel}"
            try:
                with urllib.request.urlopen(url, timeout=5) as r:
                    if r.status != 200:
                        bad.append({"file": rel, "line": 0, "message": f"HTTP {r.status}"})
            except urllib.error.HTTPError as e:
                bad.append({"file": rel, "line": 0, "message": f"HTTP {e.code}"})
            except Exception as e:
                bad.append({"file": rel, "line": 0, "message": f"{type(e).__name__}"})
        c.findings = bad
        c.state = "FAIL" if bad else "PASS"
        c.detail = (f"站点根 {_rel(root, site_root) or '.'}"
                    + (f"（部署前缀 {base}）" if base else "")
                    + f"，起 http.server:{port}，GET {served} 个页面，失败 {len(bad)}")
        c.command = f"内置 http.server:{port} + urllib GET"
        c.exit_code = 0 if not bad else 1
    except Exception as e:
        c.state = "UNKNOWN"
        c.detail = f"起不来静态服务器：{type(e).__name__}: {e}"
    finally:
        if httpd:
            httpd.shutdown()
            httpd.server_close()
    c.seconds = time.time() - t0
    return c


# ──────────────────────────────────────────────────────────────────────
# 11. git
# ──────────────────────────────────────────────────────────────────────
def check_git(root: Path, files: list[Path], ctx: "Ctx") -> Check:
    c = Check("git", "工作区状态（默认不阻断）", blocking=False)
    t0 = time.time()
    if not (root / ".git").exists():
        c.state, c.applicable = "UNKNOWN", False
        c.detail = "不是 git 仓库"
        return c
    code, out = _run(["git", "status", "--porcelain"], root, 60)
    if code != 0:
        c.state = "UNKNOWN"
        c.detail = f"git status 失败：{_tail(out, 200)}"
        return c
    dirty = [ln for ln in out.splitlines() if ln.strip()]
    c.findings = [{"file": ln[3:].strip(), "line": 0, "message": ln[:2].strip()}
                  for ln in dirty[:50]]
    c.state = "PASS" if not dirty else "FAIL"
    c.detail = "工作区干净" if not dirty else f"有 {len(dirty)} 个未提交改动"
    c.command = "git status --porcelain"
    c.exit_code = code
    c.seconds = time.time() - t0
    return c


# ──────────────────────────────────────────────────────────────────────
# 注册表
# ──────────────────────────────────────────────────────────────────────
# ──────────────────────────────────────────────────────────────────────
# 12. 自定义规则（verify.toml）—— 规则即数据
#
# 抄的是 Semgrep 的思路：加一条检查不该改引擎。项目在根目录放 verify.toml：
#
#   [[rules]]
#   id = "no-console-log"
#   pattern = 'console\.log\('
#   paths = ["**/*.js", "**/*.mjs"]
#   message = "生产代码里不要留 console.log"
#   risk = "medium"
# ──────────────────────────────────────────────────────────────────────
def check_custom(root: Path, files: list[Path], ctx: "Ctx") -> Check:
    c = Check("custom", "自定义规则（verify.toml）")
    t0 = time.time()
    cfg = root / "verify.toml"
    if not cfg.exists():
        c.state, c.applicable = "UNKNOWN", False
        c.detail = "没有 verify.toml"
        return c
    try:
        data = tomllib.loads(_strip_bom(cfg.read_text(encoding="utf-8")))
    except Exception as e:
        c.state = "FAIL"
        c.findings = [{"file": "verify.toml", "line": 0, "message": f"解析失败：{e}"}]
        c.detail = "verify.toml 解析失败"
        c.exit_code = 1
        c.seconds = time.time() - t0
        return c

    rules = data.get("rules") or []
    if not isinstance(rules, list):
        rules = []
    findings = []
    compiled = 0
    for idx, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        rid = str(rule.get("id") or f"rule{idx + 1}")
        pat = rule.get("pattern")
        if not pat:
            findings.append({"file": "verify.toml", "line": 0,
                             "message": f"规则 {rid} 缺 pattern"})
            continue
        try:
            rx = re.compile(pat)
        except re.error as e:
            findings.append({"file": "verify.toml", "line": 0,
                             "message": f"规则 {rid} 的正则无效：{e}"})
            continue
        compiled += 1
        globs = rule.get("paths") or ["**/*"]
        if isinstance(globs, str):
            globs = [globs]
        msg = str(rule.get("message") or pat)
        # risk 是正式键名；severity 是很多人会顺手写的别名（各 linter 的惯例不同），
        # 静默忽略会让规则「看起来配了等级、实际没生效」，所以两个都收。
        sev = str(rule.get("risk") or rule.get("severity") or "medium").lower()
        for p in files:
            if p.suffix.lower() not in TEXT_EXT:
                continue
            rel = _rel(root, p)
            if not any(_glob_match(rel, p.name, g) for g in globs):
                continue
            t = _read(p)
            if not t:
                continue
            for i, line in enumerate(t.splitlines(), 1):
                if rx.search(line):
                    findings.append({"file": rel, "line": i,
                                     "message": f"[{rid}] {msg}", "severity": sev})
    c.findings = findings
    c.state = "FAIL" if findings else "PASS"
    c.detail = f"{len(rules)} 条规则（{compiled} 条可用），命中 {len(findings)} 处"
    c.command = "verify.toml + 内置正则"
    c.exit_code = 0 if not findings else 1
    c.risk = "high" if any(f.get("severity") in ("critical", "high") for f in findings) else "medium"
    c.seconds = time.time() - t0
    return c


@dataclass
class Ctx:
    cache: Cache
    workers: int = 8
    fast: bool = False
    test_timeout: int = 300
    browser_timeout: int = 180
    mutation_max: int = 5
    mutation_timeout: int = 90
    flow_timeout: int = 10000          # 单步超时（毫秒）
    flow_total_timeout: int = 180      # 整个交互检查的墙钟上限（秒）
    bundle: dict | None = None       # 一次扫描的结果，五个检查共用
    bundle_lock: threading.Lock = field(default_factory=threading.Lock)


# 函数表；标题 / 风险 / 说明 / 修复建议全部来自 check_specs.py，这里只负责「怎么跑」。
CHECKS: dict[str, object] = {
    "syntax": check_syntax,
    "links": check_links,
    "html": check_html,
    "secrets": check_secrets,
    "encoding": check_encoding,
    "tests": check_tests,
    "runtime-web": check_runtime_web,
    "browser": check_browser,
    "interaction": check_interaction,
    "mutation": check_mutation,
    "a11y": check_a11y,
    "bom": check_bom,
    "paths": check_paths,
    "imports": check_imports,
    "todos": check_todos,
    "custom": check_custom,
    "git": check_git,
}
ORDER = [s.id for s in S.SPECS if s.id in CHECKS]


# ──────────────────────────────────────────────────────────────────────
# 入口
# ──────────────────────────────────────────────────────────────────────
def _disk_lifecycle_version() -> str:
    """从磁盘读出 lifecycle.py 声明的版本号（不 import，纯文本）。"""
    try:
        src = Path(__file__).with_name("lifecycle.py").read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""
    m = re.search(r'^VERSION\s*=\s*"([^"]+)"', src, re.M)
    return m.group(1) if m else ""


def _ensure_lifecycle() -> None:
    """磁盘上的 lifecycle 版本与内存里不一致就 reload。

    为什么用版本号而不是 mtime：
    第一次实现用「导入时记 mtime、变了再 reload」，结果首调用只记了基线、
    之后文件没再变 → **永远不 reload**（和 _CORE_MTIME 那次踩的是同一个坑）。
    版本号比对是幂等的：只要不一致就 reload 一次，一致就什么都不做。
    """
    disk = _disk_lifecycle_version()
    if not disk:
        return
    mod = sys.modules.get("lifecycle")
    if mod is None:
        # 首次使用：这只是 import，不是 reload，别刷日志
        try:
            import lifecycle  # noqa: F401
        except Exception:
            pass
        return
    if getattr(mod, "VERSION", "") == disk:
        return
    try:
        import importlib
        importlib.reload(mod)
        print(f"[reload] lifecycle → v{getattr(mod, 'VERSION', '?')}", file=sys.stderr)
    except Exception:
        pass


def verify(project: str, checks: list[str] | None = None,
           include_git: bool = False, fast: bool = False,
           use_cache: bool = True, workers: int = 8,
           stage: str | None = None, tier: str = "auto",
           accepts: list[dict] | None = None, only_new: bool = False,
           artifacts: bool = True, review_md: bool = True,
           against: str | None = None, artifacts_dir: str | None = None) -> dict:
    """跑一轮验证。

    stage / tier / accepts / only_new / artifacts / review_md / against
    是 v1.9 的生命周期参数，交给 lifecycle.py 做后处理（见该模块文档）。
    """
    _ensure_lifecycle()
    root = Path(project).expanduser().resolve()
    if not root.is_dir():
        return {"error": f"不是目录：{root}", "verdict": "UNKNOWN"}

    t_all = time.time()
    _SKIPPED_BACKUPS.clear()
    global _READER
    ignores = _ignore_patterns(root / ".verifyignore")
    files, by_ext, skipped_big, ignored = scan_files(root, ignores=ignores)
    _READER = _Reader()

    if checks:
        selected = [c for c in checks if c in CHECKS]
        unknown = [c for c in checks if c not in CHECKS]
    else:
        selected = [k for k in ORDER if k not in S.OPT_IN or k == "git" and include_git]
        unknown = []
    if include_git and "git" not in selected:
        selected.append("git")

    ctx = Ctx(cache=Cache(use_cache), workers=max(1, min(workers, 16)), fast=fast)

    # 这五项共用一次逐行扫描：先在这里算好（一次），再并行跑其余检查。
    # 不预计算的话，五个线程会各自从头扫一遍，反而更慢。
    BUNDLED = {"secrets", "paths", "todos", "encoding", "bom"}
    if BUNDLED & set(selected):
        ctx.bundle = scan_text_once(root, files)

    results: list[Check] = []
    t_par = time.time()
    with ThreadPoolExecutor(max_workers=min(ctx.workers, max(1, len(selected)))) as ex:
        futs = {ex.submit(CHECKS[k], root, files, ctx): k for k in selected}
        for fut in as_completed(futs):
            k = futs[fut]
            spec = S.get(k)
            try:
                res = fut.result()
            except Exception as e:
                res = Check(k, spec.title, "UNKNOWN", True, spec.blocking,
                            spec.risk, spec.remediation, spec.refs,
                            detail=f"检查内部异常：{type(e).__name__}: {e}")
            res.title = spec.title
            res.remediation = spec.remediation
            res.refs = spec.refs
            # custom 的等级可以由 config 里的 risk 抬高（例如声明成 high 就要阻断）
            if k != "custom":
                res.risk = spec.risk
            res.blocking = res.risk in S.BLOCKING_RISKS
            results.append(res)
    parallel_seconds = time.time() - t_par
    for k in unknown:
        results.append(Check(k, k, "UNKNOWN", False, "未知检查项"))
    order_index = {k: i for i, k in enumerate(ORDER)}
    results.sort(key=lambda c: order_index.get(c.id, 99))

    # 方向卡（v6）：只对已经失败的项填，通过的项一个字段都不加。
    # 填卡是纯字符串处理，不新增检查、不读盘、不跑浏览器。
    t_dir = time.time()
    directed = 0
    for c in results:
        if c.state != "FAIL":
            continue
        for f in c.findings:
            if directed >= DIR.MAX_CARDS:      # 病态情况下别把响应撑爆
                break
            card = DIR.build(c.id, f, blocking=c.blocking)
            if card:
                f["direction"] = card
                directed += 1
    direction_seconds = time.time() - t_dir

    # 生成文件提醒：改产物没用，下次构建就覆盖回去
    try:
        _annotate_generated(root, results)
    except Exception:
        pass

    ctx.cache.save()

    blocking_fail = [c for c in results if c.state == "FAIL" and c.applicable and c.blocking]
    unknown_blocking = [c for c in results if c.state == "UNKNOWN" and c.applicable and c.blocking]
    passed = [c for c in results if c.state == "PASS" and c.applicable and c.blocking]
    warned = [c for c in results if c.state == "FAIL" and c.applicable and not c.blocking]

    verdict = "FAIL" if blocking_fail else ("UNKNOWN" if unknown_blocking else
                                            ("PASS" if passed else "UNKNOWN"))

    git_info = {}
    if (root / ".git").exists():
        code, out = _run(["git", "rev-parse", "--short", "HEAD"], root, 30)
        git_info["head"] = out.strip() if code == 0 else ""
        code, out = _run(["git", "status", "--porcelain"], root, 30)
        git_info["dirty"] = len([x for x in out.splitlines() if x.strip()]) if code == 0 else None

    notes = []
    # 口径统一：用画像（含文件的目录）而不是另一套启发式 ——
    # 之前正文说"识别到 10 个"，画像却列 15 个，自相矛盾。
    ws_profile = _workspace_profile(root, files)
    ws = len(ws_profile)
    if ws >= 3:
        notes.append(
            f"这看起来是**工作区**（识别到 {ws} 个子项目）。工具不会替你挑项目，"
            "草稿、备份、资料都会被算进来。建议对单个项目跑，或先写 .verifyignore。")
    if not any(c.applicable for c in results):
        notes.append("这个目录里没有识别出任何可检查的源文件 —— 结论是 UNKNOWN，不是 PASS。")
    elif not (passed or blocking_fail or unknown_blocking) and results:
        notes.append("这轮只跑了非阻断检查，没有任何能定性的检查 —— 所以是 UNKNOWN，不是 PASS。")

    # 根上没有测试入口，但子项目里有 —— 说清楚，别让人以为「没测试」
    t = next((c for c in results if c.id == "tests"), None)
    if t is not None and not t.applicable and ws >= 2:
        with_tests = []
        for d in root.iterdir():
            if not d.is_dir() or d.name.lower() in SKIP_DIRS or d.name.startswith("."):
                continue
            try:
                if _detect_test_command(d)[0] is not None:
                    with_tests.append(d.name)
            except OSError:
                continue
        if with_tests:
            notes.append(
                "根目录没有测试入口，但子项目里有：" + "、".join(with_tests[:5])
                + "。要对它们跑测试，请把 path 指到那个子项目。")
    if warned:
        notes.append("有 " + str(len(warned)) + " 项提示（不影响判定）："
                     + "、".join(c.id for c in warned))
    if skipped_big:
        notes.append(f"{skipped_big} 个超过 5MB 的文件未扫描")
    if ignored:
        notes.append(f".verifyignore 跳过了 {ignored} 个文件")
    if _SKIPPED_BACKUPS:
        notes.append("默认跳过备份目录：" + "、".join(sorted(set(_SKIPPED_BACKUPS))[:5])
                     + "（与正本重名，重复报同一问题）")

    profile = ws_profile
    if len(profile) >= 2:
        with_tests = [r["path"] for r in profile if r["test_entry"]]
        notes.append(
            "子项目画像：" + "、".join(f"{r['path']}({r['files']} 文件"
                                      + ("，有测试" if r["test_entry"] else "") + ")"
                                      for r in profile[:6])
            + (f" …共 {len(profile)} 个" if len(profile) > 6 else ""))
        if with_tests:
            notes.append("这些子项目有测试入口，想验测试请把 path 指过去："
                         + "、".join(with_tests[:5]))

    _report = Report(
        project=str(root),
        started=time.strftime("%Y-%m-%dT%H:%M:%S"),
        seconds=time.time() - t_all,
        files=len(files),
        by_ext=dict(sorted(by_ext.items(), key=lambda kv: -kv[1])[:12]),
        checks=results,
        verdict=verdict,
        git=git_info,
        notes=notes,
        cache={"hits": ctx.cache.hits, "misses": ctx.cache.misses,
               "parallel_seconds": round(parallel_seconds, 3),
               "direction_seconds": round(direction_seconds, 4),
               "directed": directed,
               "checks": len(selected)},
    ).as_dict()

    _report["workspace"] = ws_profile

    # v1.9：生命周期后处理（分层 / tier / 接受 / 噪声 / 收敛 / 回归 / 安全 / 度量）
    try:
        import lifecycle as _LC
        _report["lifecycle"] = {}
        _LC.apply_review(_report, _LC.load_review_md(root)) if review_md else None
        _LC.apply(_report, root, {
            "stage": stage, "tier": tier, "accepts": accepts,
            "only_new": only_new, "artifacts": artifacts,
            "review_md": review_md, "against": against,
            "artifacts_dir": artifacts_dir,
        })
    except Exception as _e:
        _report.setdefault("notes", []).append(
            f"lifecycle 后处理失败（不影响检查结果）：{type(_e).__name__}: {_e}")
    return _report


def render(report: dict) -> str:
    if "error" in report:
        return f"✗ {report['error']}"
    v = report["verdict"]
    mark = {"PASS": "✓ PASS", "FAIL": "✗ FAIL", "UNKNOWN": "? UNKNOWN"}.get(v, v)
    lines = [f"{mark}  {report['project']}   ·  v{report.get('version') or VERSION}"]
    ext = ", ".join(f"{k} {n}" for k, n in list(report["by_ext"].items())[:8])
    cch = report.get("cache", {})
    lines.append(f"  文件 {report['files']} 个（{ext}）· 总耗时 {report['seconds']}s"
                 f" · {cch.get('checks', '?')} 项检查并行 {cch.get('parallel_seconds', '?')}s"
                 f" · 语法缓存命中 {cch.get('hits', 0)}")
    ws = report.get("workspace") or []
    if len(ws) >= 2:
        lines.append("  工作区：" + "、".join(
            f"{w['path']}({w['files']}" + ("，有测试" if w.get("test_entry") else "") + ")"
            for w in ws[:5]) + (f" …共 {len(ws)} 个" if len(ws) > 5 else ""))

    lc = report.get("lifecycle") or {}
    if lc:
        st = lc.get("stage") or {}
        tier = lc.get("tier") or {}
        acc = lc.get("accept") or {}
        m = lc.get("metrics") or {}
        conv = lc.get("convergence") or {}
        sec = lc.get("security") or {}
        reg = lc.get("regression") or {}
        lines.append(f"  层 {st.get('stage')}（{st.get('title')}）· "
                     f"风险档 {tier.get('tier')}（需要 {tier.get('human_approvals')} 人）· "
                     f"闸门 {st.get('verdict')}")
        if tier.get("reasons"):
            lines.append("    档位理由：" + "；".join(tier["reasons"])[:160])
        if st.get("blocked_by"):
            for b in st["blocked_by"]:
                lines.append("    ✗ " + str(b.get("reason")) +
                             (f"（{b.get('count')} 条）" if b.get("count") else "") +
                             (("：" + "、".join(b.get("checks") or [])) if b.get("checks") else ""))
        if sec.get("count"):
            groups = sec.get("groups") or []
            if groups:
                lines.append(f"    安全层：{sec['count']} 条 / {len(groups)} 类"
                             + ("（有阻塞项）" if sec.get("blocked") else ""))
            else:
                # 没有分组信息 = 跑的是旧 lifecycle 模块，别显示成「0 类」误导人
                lines.append(f"    安全层：{sec['count']} 条（分类信息缺失：lifecycle 模块未更新）"
                             + ("（有阻塞项）" if sec.get("blocked") else ""))
            for g in groups[:4]:
                lines.append(f"      · {g['count']}× {g['message']} —— "
                             + "、".join(g.get("files", [])[:2])
                             + ("…" if g["count"] > 2 else ""))
                if g.get("advice"):
                    lines.append("        → " + str(g["advice"])[:76])
        top_un = (m.get("unresolved_by_check") or {})
        if top_un:
            lines.append("    未回应来源：" + "、".join(
                f"{k} {v}" for k, v in list(top_un.items())[:4]))
        lines.append(
            f"    未回应 {acc.get('unresolved_count', 0)} 条"
            f"（中风险以上 {st.get('unresolved_blocking', 0)} / 低风险 {st.get('unresolved_low', 0)}）"
            f" · 已接受 {acc.get('accepted', 0)} 条"
            f" · 本轮新增 {m.get('noise_new', 0)} / 重复 {m.get('noise_repeat', 0)} / 修好 {m.get('noise_fixed', 0)}")
        if conv.get("advice"):
            lines.append(f"    收敛（第 {conv.get('rounds')} 轮）：{conv['advice']}")
        if reg.get("cases"):
            lines.append(f"    回归集 {reg['cases']} 条 · 缺检查 {len(reg.get('missing') or [])} 条")
        arts = lc.get("artifacts") or {}
        if arts.get("dir"):
            lines.append(f"    证据留档：{arts.get('count')} 个文件 → {arts['dir']}")
    if report.get("git", {}).get("head"):
        lines.append(f"  HEAD {report['git']['head']} · 未提交 {report['git'].get('dirty')}")
    lines.append("")
    for c in report["checks"]:
        # 不阻断的问题用 ⚠ 而不是 ✗：它不是失败，不该长得像失败。
        # 之前一律打 ✗，报告里就变成「又挂了 2 项」，其实判定是 PASS。
        if c["state"] == "FAIL" and c["applicable"] and not c["blocking"]:
            icon = "⚠"
        else:
            icon = {"PASS": "✓", "FAIL": "✗", "UNKNOWN": "?"}.get(c["state"], "?")
        if not c["applicable"]:
            tag = "（不适用）"
        elif c["blocking"]:
            tag = f"【{S.RISK_LABEL.get(c.get('risk', 'medium'), '中')}】"
        else:
            tag = f"（{S.RISK_LABEL.get(c.get('risk', 'low'), '低')}·仅提示）"
        lines.append(f"  {icon} {c['title']}{tag} — {c['detail']}  [{c['seconds']:.2f}s]")
        if c.get("command"):
            lines.append(f"      命令：{c['command']}"
                         + (f"（退出码 {c['exit_code']}）" if c["exit_code"] is not None else ""))
        # 方向卡在文本里最多打 3 条：同一检查有 30 条同类问题时，
        # 逐条重复同一段建议只会把报告冲成噪声（JSON 里是全的）。
        shown_dir = 0
        for f in c["findings"][:6]:
            loc = f["file"] + (f":{f['line']}" if f.get("line") else "")
            lines.append(f"      · {loc} {f['message']}")
            d = f.get("direction")
            if d and shown_dir < 3:
                shown_dir += 1
                # 上一行已经打了位置，这里不再重复「index.html:5 」
                cause = d["root_cause"]
                ev = d.get("evidence") or ""
                if ev and cause.startswith(ev + " "):
                    cause = cause[len(ev) + 1:]
                text = f"{cause} → {d['action']}"
                for i, chunk in enumerate(_wrap(text, 50)):
                    lines.append(("        方向：" if i == 0 else "              ") + chunk)
                lines.append(f"        别动：{' / '.join(d['must_not_touch'])}")
                lines.append(f"        验证：{d['verify']}")
        if len(c["findings"]) > 6:
            lines.append(f"      · …另有 {len(c['findings']) - 6} 条")
        for h in (c.get("hints") or [])[:3]:
            loc = h["file"] + (f":{h['line']}" if h.get("line") else "")
            lines.append(f"      ~ 提示：{loc} {h['message']}")
        if len(c.get("hints") or []) > 3:
            lines.append(f"      ~ …另有 {len(c['hints']) - 3} 条提示")
        # 已经有方向卡时不再打通用的「怎么改」——否则等于同一条问题给两句建议，
        # 而且那句通用的正是「模型可以随便选」的根源。
        has_dir = any(f.get("direction") for f in c["findings"])
        if c["state"] == "FAIL" and c.get("remediation") and c["applicable"] and not has_dir:
            lines.append(f"      → 怎么改：{c['remediation']}")
        if c["state"] == "FAIL" and c.get("output"):
            last = c["output"].strip().splitlines()
            if last:
                lines.append("      输出尾部：" + last[-1][:160])
    if report.get("notes"):
        lines.append("")
        for n in report["notes"]:
            lines.append(f"  注意：{n}")
    if report.get("baseline"):
        lines.append("")
        lines.extend(render_baseline(report["baseline"]))
    if report.get("baseline_error"):
        lines.append("")
        lines.append(f"  基线：{report['baseline_error']}")
    return "\n".join(lines)


# ──────────────────────────────────────────────────────────────────────
# 基线：上次全绿是什么样，这次多了什么
#
# 只做「差异」，不做「通过/不通过」—— 判定已经有三态了。
# 指纹用 文件 + 消息 的哈希，行号会漂移，消息不会。
# ──────────────────────────────────────────────────────────────────────
BASELINE_NAME = ".verify-baseline.json"


def _fingerprint(f: dict) -> str:
    raw = f"{f.get('file', '')}|{f.get('message', '')[:120]}"
    import hashlib
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


def baseline_snapshot(report: dict) -> dict:
    return {
        "version": VERSION,
        "saved": report.get("started", ""),
        "verdict": report.get("verdict"),
        "checks": {
            c["id"]: {
                "state": c["state"],
                "findings": [_fingerprint(f) for f in c.get("findings", [])],
            }
            for c in report.get("checks", [])
        },
    }


def baseline_compare(report: dict, snap: dict) -> dict:
    """返回新增了哪些问题、修好了哪些、哪些检查恶化了。"""
    old = snap.get("checks", {})
    new_items, fixed_items, regressed, improved = [], [], [], []
    for c in report.get("checks", []):
        cid = c["id"]
        now = {_fingerprint(f): f for f in c.get("findings", [])}
        before = set(old.get(cid, {}).get("findings", []))
        before_state = old.get(cid, {}).get("state")
        for fp, f in now.items():
            if fp not in before:
                new_items.append({"check": cid, "file": f.get("file"),
                                  "line": f.get("line"), "message": f.get("message", "")[:120]})
        gone = before - set(now)
        if gone:
            fixed_items.append({"check": cid, "count": len(gone)})
        if before_state == "PASS" and c["state"] == "FAIL":
            regressed.append(cid)
        if before_state == "FAIL" and c["state"] == "PASS":
            improved.append(cid)
    return {"new": new_items, "fixed": fixed_items,
            "regressed": regressed, "improved": improved,
            "saved_at": snap.get("saved"), "saved_verdict": snap.get("verdict")}


def render_baseline(b: dict) -> list[str]:
    lines = []
    if b["new"]:
        lines.append(f"  与基线相比：新增 {len(b['new'])} 条问题")
        for x in b["new"][:8]:
            loc = (x["file"] or "") + (f":{x['line']}" if x.get("line") else "")
            lines.append(f"    + [{x['check']}] {loc} {x['message']}")
        if len(b["new"]) > 8:
            lines.append(f"    + …另有 {len(b['new']) - 8} 条")
    if b["fixed"]:
        total = sum(x["count"] for x in b["fixed"])
        lines.append(f"  与基线相比：修好 {total} 条"
                     + "（" + "、".join(x["check"] for x in b["fixed"]) + "）")
    if b["regressed"]:
        lines.append(f"  恶化的检查：{'、'.join(b['regressed'])}")
    if b["improved"]:
        lines.append(f"  转好的检查：{'、'.join(b['improved'])}")
    if not (b["new"] or b["fixed"] or b["regressed"]):
        lines.append("  与基线相比：没有变化")
    return lines


# ──────────────────────────────────────────────────────────────────────
# 生成文件识别
#
# 真实踩过的坑：404.html 有两个 h1，照着报告去改 404.html —— 下次构建就覆盖回去。
# 真正该改的是 site-build.py。
# 工具没法知道谁生成了谁，但能在文件头里认出「这是生成物」的常见标记。
# ──────────────────────────────────────────────────────────────────────
GENERATED_MARKERS = re.compile(
    r"(?i)(do not edit|don't edit|generated by|auto-?generated|machine[- ]generated"
    r"|此文件(由|为)|自动生成|不要手动修改|请勿手动修改|勿手动编辑)")


def _looks_generated(p: Path) -> bool:
    try:
        if p.stat().st_size > 2 * 1024 * 1024:
            return False
        with p.open(encoding="utf-8", errors="replace") as f:
            head = "".join(next(f, "") for _ in range(25))
    except OSError:
        return False
    return bool(GENERATED_MARKERS.search(head))


def _annotate_generated(root: Path, results: list) -> None:
    """给「生成文件里的告警」补一条提示：改生成脚本，不要改产物。"""
    seen: dict[str, bool] = {}
    for c in results:
        files = {f.get("file") for f in (c.findings or []) if f.get("file")}
        for rel in files:
            if rel not in seen:
                seen[rel] = _looks_generated(root / rel)
            if seen[rel]:
                c.hints.append({
                    "file": rel, "line": 0,
                    "message": "这看起来是生成文件 —— 改生成它的脚本，否则下次构建会被覆盖",
                })


def _workspace_profile(root: Path, files: list[Path]) -> list[dict]:
    """列出子项目：规模、是否有测试入口、是否 git 仓库。

    为什么需要：对工作区跑的时候，"测试在哪个子项目里"、"该对谁下结论"
    光看一个总判定是看不出来的（实测 10 个子项目、tests 判在错误的根上）。
    """
    rows: list[dict] = []
    try:
        subs = [d for d in sorted(root.iterdir())
                if d.is_dir() and d.name.lower() not in SKIP_DIRS
                and not d.name.startswith(".") and not BACKUP_DIR_RE.search(d.name)]
    except OSError:
        return rows
    for d in subs[:20]:
        rel = d.relative_to(root).as_posix()
        n_files = sum(1 for f in files if str(f).startswith(str(d)))
        if n_files == 0:
            continue
        try:
            cmd, why, _ = _detect_test_command(d)
        except Exception:
            cmd, why = None, "探测失败"
        rows.append({
            "path": rel,
            "files": n_files,
            "test_entry": bool(cmd),
            "test_hint": why if cmd else "",
            "git": (d / ".git").exists(),
        })
    rows.sort(key=lambda r: -r["files"])
    return rows


def _count_subprojects(root: Path) -> int:      # 旧口径，保留给外部调用；内部已改用画像
    """数一下子目录里有几个像「独立项目」——用来看这是不是工作区。"""
    markers = ("package.json", "pyproject.toml", "index.html", "Cargo.toml",
               "go.mod", "setup.py", ".git")
    n = 0
    try:
        for d in root.iterdir():
            if not d.is_dir() or d.name.lower() in SKIP_DIRS or d.name.startswith("."):
                continue
            if any((d / m).exists() for m in markers):
                n += 1
    except OSError:
        return 0
    return n


def worst_risk(report: dict) -> str | None:
    worst = None
    for c in report.get("checks", []):
        if c.get("state") != "FAIL" or not c.get("applicable", True):
            continue
        findings = c.get("findings") or [{}]
        for f in findings:
            sev = f.get("severity") or c.get("risk") or "medium"
            if worst is None or S.RISK_ORDER.get(sev, 9) < S.RISK_ORDER.get(worst, 9):
                worst = sev
    return worst


def list_checks_text() -> str:
    lines = [f"{'id':<13}{'风险':<5}{'阻断':<5}判定什么"]
    lines.append("-" * 78)
    for s in S.SPECS:
        lines.append(f"{s.id:<13}{S.RISK_LABEL[s.risk]:<5}{'是' if s.blocking else '否':<5}{s.doc}")
    return "\n".join(lines)


def main_cli(argv=None):
    import argparse
    ap = argparse.ArgumentParser(
        prog="verify-helper",
        description=f"验证助手 v{VERSION} —— 给任意项目目录跑一组机械检查，返回三态结论与证据。")
    ap.add_argument("project", nargs="?", help="项目目录（--list-checks 时可省略）")
    ap.add_argument("--checks", default="", help="逗号分隔；省略=默认全部（不含 git）")
    ap.add_argument("--git", action="store_true", help="把 git 状态也算进总判定")
    ap.add_argument("--fast", action="store_true",
                    help="跳过测试与变异（保留运行时与浏览器：那才是抓真问题的两层）")
    ap.add_argument("--no-cache", action="store_true", help="忽略语法缓存")
    ap.add_argument("--workers", type=int, default=8, help="并行度，默认 8")
    ap.add_argument("--json", action="store_true", help="输出完整 JSON 报告")
    ap.add_argument("--sarif", metavar="FILE", help="写出 SARIF 2.1.0（给 GitHub Code Scanning 用）")
    ap.add_argument("--fail-on", default="high",
                    choices=["critical", "high", "medium", "low"],
                    help="退出码阈值：该等级及以上的问题会让退出码为 1（默认 high）")
    ap.add_argument("--list-checks", action="store_true", help="列出全部检查项")
    ap.add_argument("--baseline", default="off", choices=["off", "save", "check"],
                    help="基线：save 存一份，check 与上次比对")
    ap.add_argument("--baseline-file", default="", help="基线文件路径（默认项目根 .verify-baseline.json）")
    # ── v1.9 生命周期 ──
    ap.add_argument("--stage", default="pr",
                    choices=["precommit", "pr", "merge", "postdeploy"],
                    help="这一轮属于哪一层（默认 pr）")
    ap.add_argument("--tier", default="auto", choices=["auto", "low", "medium", "high"],
                    help="风险档；auto = 按 git 改动自动判定")
    ap.add_argument("--accept", default="",
                    help="接受某条 finding：id::理由（多个用 ; 分隔；也可用 | 分隔）")
    ap.add_argument("--accept-file", default="",
                    help="接受记录文件（默认项目根 .verify-accept.json）")
    ap.add_argument("--only-new", action="store_true", help="只报本轮新出现的 finding")
    ap.add_argument("--against", default="", help="合并队列：与目标分支组合后再判定")
    ap.add_argument("--no-artifacts", action="store_true", help="不写 .verify-artifacts 证据")
    ap.add_argument("--artifacts-dir", default="",
                    help="证据写到哪里（默认项目根 .verify-artifacts）")
    ap.add_argument("--no-review-md", action="store_true", help="忽略 REVIEW.md")
    a = ap.parse_args(argv)

    if a.list_checks:
        print(list_checks_text())
        return 0
    if not a.project:
        ap.error("缺少 project 参数（或用 --list-checks）")

    sel = [x.strip() for x in a.checks.split(",") if x.strip()] or None

    accepts = []
    for chunk in [x for x in a.accept.split(";") if x.strip()]:
        # finding id 形如 check:file:line:hash，本身就带冒号 ——
        # 所以优先用 "::" 或 "|" 分隔；退化时才从最右边切一个冒号。
        if "::" in chunk:
            fid, _, reason = chunk.partition("::")
        elif "|" in chunk:
            fid, _, reason = chunk.partition("|")
        else:
            fid, _, reason = chunk.rpartition(":")
        if fid.strip() and reason.strip():
            accepts.append({"id": fid.strip(), "reason": reason.strip(),
                            "at": time.strftime("%Y-%m-%d")})

    # 从 --accept-file 读一批「已接受」（长期豁免放文件里，命令行只做临时接受）
    if a.accept_file:
        try:
            import json as _json
            data = _json.loads(Path(a.accept_file).read_text(encoding="utf-8"))
            rows = data.get("accepted") if isinstance(data, dict) else data
            for e in rows or []:
                if isinstance(e, dict) and e.get("id") and e.get("reason"):
                    accepts.append(e)
        except Exception as _e:
            print(f"（--accept-file 读失败：{_e}）", file=sys.stderr)

    # 接受记录落盘：写下就是「我回答过了」，可审计、可入库
    if accepts:
        try:
            import lifecycle as _LC
            cur = _LC.load_accepts(Path(a.project))
            merged = {e["id"]: e for e in (cur.get("accepted") or []) if e.get("id")}
            for e in accepts:
                merged[e["id"]] = e
            _LC.save_accepts(Path(a.project), list(merged.values()))
        except Exception as _e:
            print(f"（接受记录未写盘：{_e}）", file=sys.stderr)

    # 合并队列：先与目标分支组合，再对合并结果跑检查
    merge = {}
    target = a.project
    if a.against:
        import lifecycle as _LC
        merge = _LC.merge_probe(Path(a.project), a.against)
        if merge.get("ok"):
            target = merge["path"]

    rep = verify(target, sel, include_git=a.git, fast=a.fast,
                 use_cache=not a.no_cache, workers=a.workers,
                 stage=a.stage, tier=a.tier, accepts=accepts,
                 only_new=a.only_new, artifacts=not a.no_artifacts,
                 review_md=not a.no_review_md, against=a.against or None,
                 artifacts_dir=a.artifacts_dir or None)
    if a.against:
        rep["merge_probe"] = {"ok": merge.get("ok"), "note": merge.get("note")}
        if merge.get("ok"):
            import lifecycle as _LC
            _LC.cleanup_worktree(Path(a.project), merge.get("path", ""))

    if a.baseline != "off" and "error" not in rep:
        bpath = Path(a.baseline_file) if a.baseline_file else Path(rep["project"]) / BASELINE_NAME
        try:
            if a.baseline == "save":
                bpath.write_text(json.dumps(baseline_snapshot(rep), ensure_ascii=False, indent=1),
                                 encoding="utf-8")
                rep["baseline_saved"] = str(bpath)
            else:
                if bpath.exists():
                    snap = json.loads(bpath.read_text(encoding="utf-8"))
                    rep["baseline"] = baseline_compare(rep, snap)
                else:
                    rep["baseline_error"] = f"基线文件不存在：{bpath}（先跑一次 --baseline save）"
        except Exception as e:
            rep["baseline_error"] = f"{type(e).__name__}: {e}"

    if a.sarif:
        import sarif as sarif_mod
        Path(a.sarif).write_text(sarif_mod.dumps(rep, VERSION), encoding="utf-8")
        print(f"SARIF 已写入：{a.sarif}")

    print(json.dumps(rep, ensure_ascii=False, indent=1) if a.json else render(rep))

    worst = worst_risk(rep)
    order = S.RISK_ORDER
    if worst is not None and order.get(worst, 9) <= order.get(a.fail_on, 1):
        return 1
    return 0 if rep.get("verdict") == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main_cli())
