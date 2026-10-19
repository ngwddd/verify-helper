# -*- coding: utf-8 -*-
"""检查项注册表 —— 全部是数据，不是散落在代码里的 if。

这一层存在的理由（来自 OpenSSF Scorecard 的做法）：
  · 一项检查的「标题 / 风险等级 / 判定什么 / 怎么修 / 标准出处」应该是同一份数据，
    README 的表格、MCP 的工具描述、SARIF 的 rule 定义，都从这一份生成 ——
    否则三处必然互相漂移。
  · 风险等级决定它阻不阻断，而不是反过来先写死 blocking 再补等级。

风险等级 → 行为：
  critical / high  → 阻断（FAIL 会让总判定失败）
  medium / low     → 只报告
"""
from __future__ import annotations

from dataclasses import dataclass

RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
BLOCKING_RISKS = {"critical", "high"}
RISK_LABEL = {"critical": "严重", "high": "高", "medium": "中", "low": "低"}
SARIF_LEVEL = {"critical": "error", "high": "error",
               "medium": "warning", "low": "note"}


@dataclass(frozen=True)
class CheckSpec:
    id: str
    title: str
    risk: str            # critical | high | medium | low
    category: str        # 语法 / 结构 / 安全 / 运行时 / 卫生
    doc: str             # 它判定什么（一句话）
    remediation: str     # 不通过时怎么改（一句话，动词开头）
    refs: tuple = ()     # 标准出处，如 ("CWE-798",)

    @property
    def blocking(self) -> bool:
        return self.risk in BLOCKING_RISKS


SPECS: tuple[CheckSpec, ...] = (
    CheckSpec(
        "syntax", "语法解析", "high", "语法",
        "每个 .py / .js / .json / .toml 文件都要能被对应的解析器接受。",
        "按报错的行号修掉；JS 可用 node --check 单文件复现。",
    ),
    CheckSpec(
        "links", "链接与锚点", "high", "结构",
        "HTML 里的相对链接目标必须存在，页内与跨页锚点必须真实存在。",
        "改链接指向真实文件，或补上被引用的 id；站点根绝对路径请用线上预览确认。",
        ("URL 规范 RFC 3986",),
    ),
    CheckSpec(
        "html", "HTML 结构", "high", "结构",
        "标签必须配平（无孤立闭合、无未闭合），同一页面 id 不得重复。",
        "补齐缺失的闭合标签；重复 id 改名并同步修改引用它的锚点。",
        ("HTML 标准",),
    ),
    CheckSpec(
        "secrets", "密钥", "critical", "安全",
        "源码与配置里不得出现真实凭据（API key、token、私钥、明文密码）。",
        "立即吊销该凭据并改用环境变量；已提交历史也需清理。",
        ("CWE-798", "CWE-259"),
    ),
    CheckSpec(
        "encoding", "UTF-8 编码", "high", "语法",
        "文本文件必须是合法 UTF-8（UTF-16 与 GBK 会被 Windows 工具链悄悄弄坏）。",
        "转存为 UTF-8（无 BOM）；批量转换时注意先备份。",
        ("Unicode 标准",),
    ),
    CheckSpec(
        "tests", "测试", "high", "运行时",
        "项目自带的测试套件必须真的跑起来并通过（以退出码为准）。",
        "先修失败的用例；没有测试入口的话，至少补一个冒烟测试。",
    ),
    CheckSpec(
        "runtime-web", "运行时（HTTP）", "high", "运行时",
        "静态站点的每个页面通过 HTTP 请求都必须返回 200（大小写、路径层级只有这一层能验出来）。",
        "核对文件实际路径与链接大小写；确认站点根目录正确。",
    ),
    CheckSpec(
        "browser", "浏览器运行时", "high", "运行时",
        "用真实浏览器打开每个页面，抓 JS 未捕获异常、console.error 与资源 404（需要本机装有 playwright）。",
        "按报错栈修脚本；资源 404 通常是路径或大小写写错。",
        ("Playwright",),
    ),
    CheckSpec(
        "a11y", "HTML 规范性", "low", "结构",
        "img 有 alt、单页一个 h1、有 title 与 lang、target=_blank 带 rel=noopener。",
        "补 alt / 调整标题层级 / 加 lang；外链加 rel=\"noopener\"。",
        ("WCAG 2.2",),
    ),
    CheckSpec(
        "bom", "UTF-8 BOM", "low", "卫生",
        "文件开头不应有 UTF-8 BOM（会让 CSS/JS 首行规则失效、diff 多一个隐形字符）。",
        "用编辑器或脚本去掉开头的 EF BB BF 三字节。",
    ),
    CheckSpec(
        "paths", "本机绝对路径", "low", "卫生",
        "代码与文档里不应写死本机绝对路径（发布时会泄漏用户名与目录结构）。",
        "改成相对路径或环境变量。",
        ("CWE-200",),
    ),
    CheckSpec(
        "imports", "未使用的 import", "low", "卫生",
        "Python 里导入了却没用到的名字（会拖慢启动、掩盖真实依赖）。",
        "删掉未使用的 import；若是再导出，加进 __all__ 或用 # noqa 说明。",
    ),
    CheckSpec(
        "todos", "TODO 统计", "low", "卫生",
        "代码里 TODO / FIXME / XXX / HACK 的数量（只报告，不判定对错）。",
        "要么做完，要么改成 issue 编号。",
    ),
    CheckSpec(
        "custom", "自定义规则", "medium", "自定义",
        "项目 verify.toml 里声明的正则规则（规则即数据，不用改引擎）。",
        "按规则里写的 message 修改。",
    ),
    CheckSpec(
        "mutation", "变异门", "medium", "运行时",
        "把改动行里的运算符/布尔值改坏，重跑测试：测试还能通过，说明这行没有有效断言（opt-in，默认不跑）。",
        "给这些行补上真正会失败的断言，或删掉死代码。",
        ("PIT mutation testing",),
    ),
    CheckSpec(
        "git", "工作区状态", "low", "卫生",
        "工作区是否有未提交改动（默认不参与总判定）。",
        "确认这些改动是有意保留的，或提交/ stash 掉。",
    ),
)

BY_ID = {s.id: s for s in SPECS}

# 默认不跑的检查：太慢（变异门）或必须显式要（git 状态）。
# 需要时用 --checks mutation,git 显式打开。
OPT_IN = {"mutation", "git"}


def get(check_id: str) -> CheckSpec:
    return BY_ID.get(check_id) or CheckSpec(
        check_id, check_id, "low", "未知", "未知检查项。", "检查 id 是否拼错。")


def ordered_ids() -> list[str]:
    return [s.id for s in SPECS]


def blocking_ids() -> list[str]:
    return [s.id for s in SPECS if s.blocking]


def markdown_table() -> str:
    """README 的检查表由这里生成 —— 文档不会和代码漂移。"""
    rows = ["| 检查 | 风险 | 阻断 | 判定什么 | 不通过怎么改 |",
            "|---|---|:--:|---|---|"]
    for s in SPECS:
        rows.append(
            f"| `{s.id}` | {RISK_LABEL[s.risk]} | {'✅' if s.blocking else '—'} "
            f"| {s.doc} | {s.remediation} |")
    return "\n".join(rows)


if __name__ == "__main__":
    import sys
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    print(markdown_table())
