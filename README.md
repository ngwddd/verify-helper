# 验证助手 · verify-helper

[![CI](https://github.com/ngwddd/verify-helper/actions/workflows/ci.yml/badge.svg)](https://github.com/ngwddd/verify-helper/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-3776ab.svg)](https://www.python.org/)

给**任意项目目录**跑一遍机械检查，返回 **PASS / FAIL / UNKNOWN** 三态结论，
每条结论都带证据（命令、退出码、`文件:行号`）、**风险等级**和**修复建议**。

既是一个命令行工具，也是一个 MCP 服务器（agent 可以直接调用）。

---

## 为什么做这个

Agent 的自验经常很水：跑个构建看到「成功」就宣称完成，但页面点了没反应、链接 404、
测试里根本没断言。有研究统计过 20,574 个真实编码会话，**22.58% 的失败来自「把没验证的状态说成已完成」**。

这个工具把「完成」的判定从模型的自我叙述里拿出来，交给可复核的输出：

- **没有 oracle（判定标准）的检查，一律记 UNKNOWN，绝不当 PASS。**
- **每条 FAIL 都附证据**：跑了什么命令、退出码多少、哪一行出问题。
- **每条 FAIL 都附修复建议**，不是只告诉你错了。

## 快速开始

```bash
# 直接跑（零依赖，Python 3.11+）
python verify_core.py /path/to/project

# 列出全部检查项
python verify_core.py --list-checks

# 快速模式：跳过测试与运行时，秒级返回
python verify_core.py /path/to/project --fast

# 输出 SARIF（给 GitHub Code Scanning 用）
python verify_core.py /path/to/project --sarif out.sarif
```

退出码：`0 = PASS`，`1 = FAIL / UNKNOWN / 参数错误`。

### 作为 MCP 服务器

```bash
python server.py     # stdio JSON-RPC 2.0，无第三方依赖
```

注册到支持 MCP 的客户端（以 DSH 为例）：

```yaml
- insert:
    - id: verify-helper
      name: '@deepseek-ai/dsh-mcp-client'
      config:
        serverName: verify-helper
        transport: stdio
        command: 'C:\Program Files\Python314\python.exe'
        args: ['C:\path\to\verify-helper\server.py']
        env:
          PYTHONIOENCODING: utf-8
        toolCallTimeoutMs: 600000
        failOnStartupError: false
```

工具：

| 工具 | 作用 |
|---|---|
| `verify_start(path, checks?, fast?, format?)` | 跑一遍验证，`format` 可选 `text` / `json` / `sarif` |
| `verify_report(run_id?)` | 取回完整报告，默认最近一次 |
| `verify_checks()` | 列出全部检查项、风险等级、修复建议 |

FAIL 时返回 `isError: true` —— 调用方不会被「静默通过」骗过去。

---

## 检查项

由 [`check_specs.py`](check_specs.py) 生成，代码与文档不会漂移：

<!-- TABLE:START -->
| 检查 | 风险 | 阻断 | 判定什么 | 不通过怎么改 |
|---|---|:--:|---|---|
| `syntax` | 高 | ✅ | 每个 .py / .js / .json / .toml 文件都要能被对应的解析器接受。 | 按报错的行号修掉；JS 可用 node --check 单文件复现。 |
| `links` | 高 | ✅ | HTML 里的相对链接目标必须存在，页内与跨页锚点必须真实存在。 | 改链接指向真实文件，或补上被引用的 id；站点根绝对路径请用线上预览确认。 |
| `html` | 高 | ✅ | 标签必须配平（无孤立闭合、无未闭合），同一页面 id 不得重复。 | 补齐缺失的闭合标签；重复 id 改名并同步修改引用它的锚点。 |
| `secrets` | 严重 | ✅ | 源码与配置里不得出现真实凭据（API key、token、私钥、明文密码）。 | 立即吊销该凭据并改用环境变量；已提交历史也需清理。 |
| `encoding` | 高 | ✅ | 文本文件必须是合法 UTF-8（UTF-16 与 GBK 会被 Windows 工具链悄悄弄坏）。 | 转存为 UTF-8（无 BOM）；批量转换时注意先备份。 |
| `tests` | 高 | ✅ | 项目自带的测试套件必须真的跑起来并通过（以退出码为准）。 | 先修失败的用例；没有测试入口的话，至少补一个冒烟测试。 |
| `runtime-web` | 高 | ✅ | 静态站点的每个页面通过 HTTP 请求都必须返回 200（大小写、路径层级只有这一层能验出来）。 | 核对文件实际路径与链接大小写；确认站点根目录正确。 |
| `browser` | 高 | ✅ | 用真实浏览器打开每个页面，抓 JS 未捕获异常、console.error 与资源 404（需要本机装有 playwright）。 | 按报错栈修脚本；资源 404 通常是路径或大小写写错。 |
| `a11y` | 低 | — | img 有 alt、单页一个 h1、有 title 与 lang、target=_blank 带 rel=noopener。 | 补 alt / 调整标题层级 / 加 lang；外链加 rel="noopener"。 |
| `bom` | 低 | — | 文件开头不应有 UTF-8 BOM（会让 CSS/JS 首行规则失效、diff 多一个隐形字符）。 | 用编辑器或脚本去掉开头的 EF BB BF 三字节。 |
| `paths` | 低 | — | 代码与文档里不应写死本机绝对路径（发布时会泄漏用户名与目录结构）。 | 改成相对路径或环境变量。 |
| `imports` | 低 | — | Python 里导入了却没用到的名字（会拖慢启动、掩盖真实依赖）。 | 删掉未使用的 import；若是再导出，加进 __all__ 或用 # noqa 说明。 |
| `todos` | 低 | — | 代码里 TODO / FIXME / XXX / HACK 的数量（只报告，不判定对错）。 | 要么做完，要么改成 issue 编号。 |
| `custom` | 中 | — | 项目 verify.toml 里声明的正则规则（规则即数据，不用改引擎）。 | 按规则里写的 message 修改。 |
| `git` | 低 | — | 工作区是否有未提交改动（默认不参与总判定）。 | 确认这些改动是有意保留的，或提交/ stash 掉。 |
<!-- TABLE:END -->

**风险等级决定阻不阻断**：`严重` / `高` → 阻断（FAIL 会让总判定失败）；`中` / `低` → 只报告。

---

## 三态规则

```
PASS    检查跑了，且通过
FAIL    检查跑了，且不通过
UNKNOWN 没跑 / 跑不了 / 判不了 —— 永远不许当 PASS
```

另有一个 `applicable` 标志：项目里根本没有这类文件时（比如没有 HTML 却要查链接），
记 `UNKNOWN + applicable=false`，它**不参与总判定** —— 那是「不适用」，不是「判不了」。

总判定：

```
有阻断项 FAIL        → FAIL
否则有阻断项 UNKNOWN  → UNKNOWN
否则有阻断项 PASS     → PASS
只跑了非阻断检查      → UNKNOWN，并说明原因
```

这条规则的理论依据是测试领域的 **oracle 问题**：没有判定标准，跑再多遍也证明不了正确。

---

## 自定义规则（规则即数据）

在项目根放 `verify.toml`，不改引擎就能加检查：

```toml
[[rules]]
id = "no-console-log"
pattern = 'console\.log\('
paths = ["**/*.js", "**/*.mjs"]
message = "生产代码里不要留 console.log"
risk = "medium"          # medium/low 只报告；high/critical 会让总判定 FAIL

[[rules]]
id = "no-http"
pattern = 'src="http://'
paths = ["**/*.html"]
message = "站内资源不要用 http://"
risk = "high"
```

## 排除文件

`.verifyignore`（一行一个 glob，`#` 注释），用来排除模板片段、页面快照、示例代码：

```
src/current-index.html
templates/**/*.html
```

---

## SARIF 与 GitHub Code Scanning

```bash
python verify_core.py . --sarif verify.sarif
```

上传后，每条告警会直接出现在 PR 的 diff 行内。工作流示例见
[`examples/github-action.yml`](examples/github-action.yml)。

---

## 性能

不追求「全量」，追求「快到可以随手跑」：

| 项目规模 | 检查项 | 耗时 |
|---|---|---|
| 53 个文件 | 13 项 | 0.66s |
| 1,868 个文件 | 13 项 | 1.85s |
| 11,470 个文件 | 13 项 | **4.8s** |

做到这一点的四件事：

1. **合并扫描** —— 密钥 / 路径 / TODO / 编码 / BOM 五项共用一次逐行遍历；
2. **字面量预筛** —— 先在小写字节流里找 16 个标记（`sk-`、`password`、`TODO`…），一个都没有就完全不逐行扫；
3. **共享读缓存** —— 一份文件被多个检查读，只读一次；
4. **并行 + 缓存** —— 检查并行跑；`node --check` 结果按 `(mtime, size)` 缓存。

---

## 设计取舍

**保留的（我们的味道）**

- 三态而不是两态：`UNKNOWN` 是一等公民。
- 每条结论都带命令和退出码，可事后复核。
- 中文优先，输出给人看，不给人猜。
- 零第三方依赖，`git clone` 就能跑。

**抄来的（别人的精华）**

- 风险分级（OpenSSF Scorecard）：每项带 Critical/High/Medium/Low。
- 修复建议（Scorecard）：每条规则都有 remediation。
- SARIF（OASIS 标准）：结果能被 GitHub Code Scanning 直接消费。
- 规则即数据（Semgrep）：`verify.toml` 让用户加检查不改引擎。
- 配置生成文档（Scorecard）：README 的表格由 `check_specs.py` 生成。

**明确不做的（别人的糟粕）**

- ❌ 堆几百条规则 —— 规则越多越互相冲突，维护成本指数上升。
- ❌ 把覆盖率当唯一指标 —— 覆盖率说明「执行到」，不说明「断言有效」。
- ❌ 全量变异测试 —— 小项目也跑不动，只做静态 + 运行时。
- ❌ 用 LLM 评审当唯一闸门 —— 没有 oracle，正好是本工具要解决的问题。

---

## 局限（说清楚，不掩饰）

- **没有浏览器层**：`runtime-web` 只验 HTTP 200，抓不到 JS 报错、点击无反应、渲染错位。这是下一版（v1.2）的事。
- **没有变异测试**：只跑现有测试，不判断测试本身够不够强。
- **没有基线**：不做「这次比上次多了什么」的差分。
- **JS 语法检查单次上限 120 个文件**，超出会如实写「另有 N 个未检查」，不假装查过。
- **站点根绝对路径**（`/xxx`）离线不校验，只在报告里标注。

---

## 开发

```bash
python -m unittest discover -s tests -v     # 34 个测试，全部用临时目录造的 fixture
python verify_core.py . --fast              # 自己检查自己
```

测试不依赖任何本机真实项目：所有 fixture 在临时目录里现造、跑完即删。

## 许可证

MIT
