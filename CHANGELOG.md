# 更新日志

## v1.3.0 — 2026-10-20

**主题：判断「测试到底有没有用」和「这次比上次多了什么」。**

### 新增

- **`mutation` 检查（opt-in）**：把改动行里的运算符/布尔值改坏，重跑测试。
  测试还能通过，说明这行没有有效断言 —— 这正是「覆盖率很高但测试很水」的根因。
  默认不跑（太慢），用 `--checks mutation` 打开；只打 git diff 的行，最多 5 个变异，每个 90 秒超时，
  改完立刻还原源文件。
- **基线差分**：`--baseline save` 存一份，`--baseline check` 与上次比，
  报告「新增 N 条 / 修好 M 条 / 哪些检查恶化了」。指纹用「文件 + 消息」哈希，行号漂移不会误报。

### 质检

对着自己连跑 5 轮：结论稳定（5/5 PASS）、耗时 7.56–7.60s、有缓存与无缓存结果一致、退出码与结论匹配。
单元测试连跑 3 轮：49 个全过，7.15–7.19s，无抖动。

## v1.2.0 — 2026-10-20

**主题：真把页面跑起来** —— 补上 v1.1 承认的最大空白：浏览器运行时。

### 新增

- **`browser` 检查**：用 Playwright 真开 Chromium，逐页抓 JS 未捕获异常、`console.error`、
  资源 404，并留截图。这是唯一能抓到「点了没反应」「白屏」的层次。
  没有 playwright 时老实记 UNKNOWN，不假装验过。
- **部署前缀推断**：站点常部署在 `/repo/` 子路径下，页面里写 `/repo/assets/x.css`。
  本地直接在根上起服务会把这当成 404（假阳性）。现在会从站点根绝对路径里推断前缀，
  把站点挂到该前缀下再验。`runtime-web` 与 `browser` 都适用。
- **`--fail-on <critical|high|medium|low>`**：退出码阈值。默认 `high`，
  设成 `low` 就能让任何一条提示都卡住构建。
- **浏览器探针并发 4 路**：20 个页面从 20 秒降到 6 秒。

### 改进

- 内置 `ThreadingHTTPServer` 替代 `python -m http.server` 子进程：
  少一次进程启动、能挂前缀、关得更干净。
- `worst_risk()` 把「最严重那条问题的等级」暴露出来，供退出码和文档使用。

## v1.1.0 — 2026-10-20

**主题：从「能查」到「查得专业」** —— 把调研里真正有价价值的三件事吸收进来，
同时保留自己的三态判定与证据链。

### 新增

- **风险分级**：每项检查带 `critical / high / medium / low`，替代原来的布尔 `blocking`。
  等级决定阻不阻断，而不是反过来。参考 OpenSSF Scorecard。
- **修复建议**：每项检查都有 `remediation`，FAIL 时直接打印「怎么改」。
- **SARIF 2.1.0 输出**：`--sarif file.sarif` 或 MCP `format="sarif"`，
  可直接上传 GitHub Code Scanning，告警出现在 PR diff 行内。
- **自定义规则**：项目根 `verify.toml` 声明正则规则（`id / pattern / paths / message / risk`），
  加检查不用改引擎。规则声明 `risk = "high"` 时会升级为阻断项。
- **`--list-checks`**：列出全部检查项、风险等级、判定标准。
- **检查项注册表**：`check_specs.py` 是唯一事实来源，README 表格由它生成，代码与文档不会漂移。
- **34 个单元测试**：核心判定、SARIF 结构、MCP 协议全覆盖，全部用临时目录现造 fixture，
  不依赖任何本机项目。

### 改进

- `.verifyignore` 支持 `**/x` 匹配根目录下的 `x`（之前要求路径里必须有斜杠）。
- `custom` 检查的 glob 同样修好了 `**/*.js` 匹配根文件的问题。
- SARIF 不再把「不适用」的检查写成 result —— 那会把报告灌满噪声。

### 保留

- 三态判定（PASS / FAIL / UNKNOWN），UNKNOWN 永不当 PASS。
- 每条结论附命令、退出码、`文件:行号`。
- 五项检查共用一次扫描 + 字面量预筛 + 共享读缓存，11,470 文件 4.8 秒。

## v1.0.0 — 2026-10-20

- 13 项检查：syntax / links / html / secrets / encoding / tests / runtime-web /
  a11y / bom / paths / imports / todos / git。
- MCP stdio 服务器（零依赖）：`verify_start` / `verify_report` / `verify_checks`。
- 三态判定 + 证据链 + `.verifyignore`。
- 五项检查合并扫描 + 16 个字面量预筛 + 共享读缓存 + 并行，11,470 文件从 18.1 秒降到 5.1 秒。

## v0.1.0 — 2026-10-20

- 首个可用版本：6 项检查（syntax / links / secrets / tests / paths / git）。
- 三态判定与 PASS/FAIL 退出码。
