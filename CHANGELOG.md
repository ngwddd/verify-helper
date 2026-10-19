# 更新日志

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
