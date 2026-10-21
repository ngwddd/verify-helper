# -*- coding: utf-8 -*-
"""把失败项翻译成「往哪修」。

**这是 v6 的全部实现**：不加检查、不加调用、不碰浏览器。
验证跑完之后，对每条**已经失败**的项，用已有的证据填一张方向卡；
通过的项一个字段都不加。

四道闸（任一不过 → 返回 None，这一条就不写方向）：

  ① 有证据     卡里必须带具体位置（构造时强制写入 evidence，取自 finding）
  ② 可验证     必须给出一条能执行的 `--checks <id>` 命令
  ③ 有边界     必须写明至少一条「不要动 X」
  ④ 最小       动作里不许出现「重写整个文件」「删掉测试」这类话

原则：**宁缺勿滥**。一句「请检查相关代码」比不写更糟 ——
它让模型以为自己拿到了信息。
"""
from __future__ import annotations

MAX_MSG = 120
MIN_CAUSE = 10

# 一次运行最多填这么多张卡。防的是「100 条失败项 → 响应暴涨」这种病态情况；
# 正常项目远到不了这个数，真到了说明问题本身需要先收敛。
MAX_CARDS = 50

# ④ 最小性：动作里出现这些词一律拒收
FORBIDDEN = (
    "重写整个文件", "重写文件", "重构整个", "推倒重来",
    "删掉测试", "删除测试", "跳过测试",
    "关闭这项检查", "关掉这项检查", "禁用检查",
)

SCALES = ("low", "medium", "high")

# 这些检查不产生方向：统计类、或者没有「正确做法」这回事
NO_DIRECTION = frozenset({"todos", "git"})


def _clip(text: str, n: int = MAX_MSG) -> str:
    text = " ".join(str(text or "").split())
    return text if len(text) <= n else text[: n - 1] + "…"


def _where(f: dict) -> str:
    """把 finding 的位置写成 `文件:行`；没有就空串。"""
    file = str(f.get("file") or "").strip()
    line = f.get("line") or 0
    if file and line:
        return f"{file}:{line}"
    return file


def _card(f: dict, cls, cause, action, must_not, check_id, scale="low", cite=True):
    """造一张方向卡。

    cite=True 时把位置自动写进根因 —— 保证每张卡都引用具体证据，
    而不是靠调用方记得写。
    """
    where = _where(f) if cite else ""
    head = f"{where} " if where else ""
    return {
        "class": cls,
        "evidence": where,
        "root_cause": _clip(head + cause, 160),
        "action": action,
        "must_not_touch": list(must_not),
        # 两种调用方式都写上：读这份报告的主体通常是 agent（走 MCP），
        # 只写命令行会让它去跑一个它根本没有的工具；只写 MCP 又顾不上命令行用户。
        "verify": (f'verify_start(checks=["{check_id}"]) 应 PASS'
                   f'（命令行 --checks {check_id}）'),
        "scale": scale,
    }


def _target(message: str) -> str:
    """"死链：xxx" 这类消息里取出对象名。"""
    for sep in ("：", ":"):
        if sep in message:
            return _clip(message.split(sep, 1)[1], 60)
    return _clip(message, 60)


# ── 每种检查一个填卡函数 ────────────────────────────────────────────

def _b_syntax(f):
    return _card(
        f, "A",
        f"这一行的写法让解析器拒绝了：{_clip(f.get('message'))}",
        "只改报错那一行；改完单独再解析这个文件，不要同时改别处",
        ["同文件里报错之外的行"],
        "syntax",
    )


def _b_links(f):
    msg = _clip(f.get("message", ""))
    t = _target(msg)
    if "页内锚点" in msg:
        return _card(
            f, "A",
            f"这一行指向的锚点 {t} 在当前页里没有对应的 id",
            f"二选一：在页面里给某个元素加 id=\"{t.lstrip('#')}\"，或把这个链接改成指向真实存在的锚点",
            ["页面里其他锚点与 id"],
            "links",
        )
    if "跨页锚点" in msg:
        page = t.split("#", 1)[0] if "#" in t else t
        return _card(
            f, "A",
            f"目标页 {page} 里没有这个 id（页面本身存在，只是锚点对不上）",
            f"去 {page} 里补上这个 id，或把链接改成指向该页已有的锚点",
            [f"{page} 的其他内容", "同页的其他链接"],
            "links",
        )
    return _card(
        f, "A",
        f"站点里没有 {t} 这个文件，但这一行在引用它",
        "把这一行的引用改成真实存在的文件；如果文件名是构建时被改掉的，"
        "改构建脚本，别改生成出来的页面",
        [".verifyignore（加进去只是掩盖，不算修好）", "同页的其他链接"],
        "links",
    )


def _b_html(f):
    return _card(
        f, "A",
        f"标签没有配平或 id 重复：{_clip(f.get('message'))}",
        "补齐缺失的闭合标签；若是重复 id，改 id 并同步改所有引用它的锚点",
        ["页面的文案与结构布局"],
        "html",
    )


def _b_secrets(f):
    return _card(
        f, "B",
        f"疑似真实凭据：{_clip(f.get('message'))} —— 这需要你决定，工具不替你改",
        "先确认它是不是真凭据：是的话立刻去平台吊销并换新，再改成读环境变量；"
        "不是的话改成明显的占位符（如 sk-xxx）",
        ["不要只在源码里删掉字符串就完事（git 历史里还在）"],
        "secrets",
        scale="high",
    )


def _b_encoding(f):
    return _card(
        f, "A",
        f"按 UTF-8 解不开：{_clip(f.get('message'))} —— 常见于 GBK 保存的文件或 UTF-16 导出",
        "转存为 UTF-8（无 BOM）；转之前先备份，转完看 diff 有没有意外改动",
        ["同目录其他文件的编码"],
        "encoding",
    )


def _b_bom(f):
    return _card(
        f, "A",
        f"文件开头有 3 个字节的 BOM（EF BB BF）：{_clip(f.get('message'))}",
        "去掉开头这 3 个字节，不要动其余内容",
        ["文件正文"],
        "bom",
    )


def _b_paths(f):
    return _card(
        f, "B",
        f"{_clip(f.get('message'))} —— 要不要改取决于会不会发布它",
        "如果这个文件会进仓库或发布：换成相对路径或环境变量；"
        "如果只是本机脚本：可以不改，但要知道它会泄漏用户名和目录结构",
        ["同一项目里其他只在本机跑的文件"],
        "paths",
    )


def _b_imports(f):
    return _card(
        f, "A",
        f"{_clip(f.get('message'))} —— 删掉它不影响程序行为，只是让真实依赖更清楚",
        "删掉这一行 import；如果它是给外部再导出的，加进 __all__ 或加 # noqa 说明",
        ["同文件里其他 import"],
        "imports",
    )


def _b_a11y(f):
    msg = _clip(f.get("message"))
    low = msg.lower()
    if "h1" in low:
        return _card(
            f, "B",
            f"标题层级有问题：{msg} —— 怎么排是内容决定，工具不替你定",
            "先定这一页的主标题是哪一个，再把其余降级；改完检查页内锚点是否还有效",
            ["页面正文内容"],
            "a11y",
        )
    if "alt" in low:
        return _card(
            f, "A",
            f"图片没有替代文字：{msg} —— 读屏软件读不出它，图片挂了也看不出该显示什么",
            "给这个 img 补 alt：描述图里传达的信息，纯装饰图用 alt=\"\"",
            ["页面的视觉样式"],
            "a11y",
        )
    if "<title>" in low or "title" in low:
        return _card(
            f, "A",
            f"这一页没有标题：{msg} —— 浏览器标签页、搜索结果、读屏都靠它识别页面",
            "在 <head> 里补一个能说清这页是什么的 <title>，别用「未命名」占位",
            ["页面正文内容"],
            "a11y",
        )
    if "lang" in low:
        return _card(
            f, "A",
            f"没有声明页面语言：{msg} —— 读屏会按错误语言的发音规则念",
            "给 <html> 补 lang（中文用 zh-CN），双语页各自写对",
            ["页面正文内容"],
            "a11y",
        )
    if "noopener" in low or "target" in low:
        return _card(
            f, "A",
            f"外链缺安全属性：{msg} —— 新标签页能通过 window.opener 反向操作原页面",
            "给这个链接补 rel=\"noopener\"（现代浏览器再加 noreferrer 更稳）",
            ["链接地址本身"],
            "a11y",
        )
    return _card(
        f, "A",
        f"可访问性缺失：{msg}",
        "按报错补上缺失的属性；改完用读屏或键盘 Tab 自己走一遍确认",
        ["页面的视觉样式"],
        "a11y",
    )


def _b_tests(f):
    return _card(
        f, "A",
        f"测试套件没有通过：{_clip(f.get('message'))}",
        "先用项目自己的命令单独复现这一条失败的用例，确认稳定失败再动手；"
        "改的时候只碰被这条用例覆盖的代码",
        ["把测试改成跳过或删掉", "为了让测试过而放宽断言"],
        "tests",
        scale="medium",
    )


def _b_runtime(f):
    return _card(
        f, "A",
        f"通过 HTTP 请求这个页面拿不到 200：{_clip(f.get('message'))}",
        "核对文件的真实路径与大小写；本地能开、线上 404，通常是大小写或目录层级不一致",
        ["页面内容"],
        "runtime-web",
        scale="medium",
    )


def _b_browser(f):
    return _card(
        f, "A",
        f"真实浏览器里出问题了：{_clip(f.get('message'))}",
        "按报错栈找脚本里对应那一行；资源 404 就核对路径与大小写，别改页面结构",
        ["其他页面的脚本"],
        "browser",
        scale="medium",
    )


def _b_interaction(f):
    step = f.get("line") or 0
    return _card(
        f, "A",
        f"第 {step} 步失败：{_clip(f.get('message'))}",
        "选择器写错就改选择器；点了没反应就去查这一步触发的脚本，别去改流程里其他已经通过的步骤",
        ["流程里其他已经通过的步骤", "把这一步从流程里删掉"],
        "interaction",
        cite=False,   # file 是流程名，不是真实文件
    )


def _b_custom(f):
    return _card(
        f, "A",
        f"命中自定义规则：{_clip(f.get('message'))}",
        "按规则里写的 message 改；如果规则本身写错了，改 verify.toml 里的规则，别绕过去",
        ["把规则从 verify.toml 里删掉"],
        "custom",
    )


def _b_mutation(f):
    return _card(
        f, "B",
        f"这些行改坏之后测试仍然通过：{_clip(f.get('message'))} —— 说明没有有效断言",
        "这属于设计决定：要么给这些行补一条真正会失败的断言，要么确认它们是死代码后删掉",
        ["为了通过变异检查而降低测试标准"],
        "mutation",
        scale="medium",
    )


_BUILDERS = {
    "syntax": _b_syntax,
    "links": _b_links,
    "html": _b_html,
    "secrets": _b_secrets,
    "encoding": _b_encoding,
    "bom": _b_bom,
    "paths": _b_paths,
    "imports": _b_imports,
    "a11y": _b_a11y,
    "tests": _b_tests,
    "runtime-web": _b_runtime,
    "browser": _b_browser,
    "interaction": _b_interaction,
    "custom": _b_custom,
    "mutation": _b_mutation,
}


def _gate(card: dict, finding: dict) -> bool:
    """四道闸。返回 False 表示这一条不该写方向。"""
    if not card:
        return False
    # ① 有证据：finding 必须能指到文件，卡里必须写出了这个位置
    file = str(finding.get("file") or "").strip()
    if not file:
        return False
    if card.get("evidence") and card["evidence"] not in card.get("root_cause", ""):
        return False
    # ② 可验证：必须同时给出 MCP 调用与命令行两种形式
    verify = card.get("verify") or ""
    if "verify_start(" not in verify or "--checks" not in verify:
        return False
    # ③ 有边界：至少一条「不要动」
    must_not = card.get("must_not_touch") or []
    if not must_not or not all(isinstance(x, str) and x.strip() for x in must_not):
        return False
    # ④ 最小：动作里不许出现毁灭性建议
    if any(word in (card.get("action") or "") for word in FORBIDDEN):
        return False
    # 结构完整性
    if card.get("class") not in ("A", "B", "C"):
        return False
    if card.get("scale") not in SCALES:
        return False
    if len(card.get("root_cause") or "") < MIN_CAUSE:
        return False
    if not (card.get("action") or "").strip():
        return False
    return True


def build(check_id: str, finding: dict) -> dict | None:
    """给一条失败项生成方向卡；不该生成时返回 None。"""
    if check_id in NO_DIRECTION:
        return None
    fn = _BUILDERS.get(check_id)
    if fn is None:
        return None
    finding = finding or {}
    try:
        card = fn(finding)
    except Exception:
        # 填卡失败绝不能影响验证本身
        return None
    return card if _gate(card, finding) else None
