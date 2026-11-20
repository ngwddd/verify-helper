# Verify Helper

Verify Helper 通过 CLI 或 MCP 对项目运行完整验证，输出 PASS、FAIL 或 UNKNOWN，并留下 JSON、SARIF 和逐项证据。当前分支使用 Python MCP SDK v2，支持 MCP 2026-07-28 以及 SDK 支持的旧协议。

## 安装与运行

需要 Python 3.11 或更新版本。开发版可使用以下命令。

```sh
uv sync --locked
uv run verify-helper /path/to/project --trust-project-code --json
```

可信项目的测试和构建在临时副本中运行。CLI 启用项目代码执行后，子进程仍使用当前操作系统账户。请将未经信任的项目放在独立运行环境中处理。缺少执行授权、工具链、断言或完整覆盖时，适用的检查会影响最终裁决。退出码为 0（PASS）、1（FAIL）或 2（UNKNOWN）。

| 参数 | 用途 |
|---|---|
| --trust-project-code | 运行来自已审查项目的测试、构建、浏览器和契约 |
| --against main | 对干净 Git 工作树与指定提交的合并结果运行验证 |
| --evidence-dir PATH | 指定证据根目录 |
| --json | 把机器可读报告写入标准输出 |
| --sarif FILE | 另存 SARIF 2.1.0 报告 |
| --list-checks | 显示可用检查 |

## MCP

stdio 示例配置。将工作区限定到验证任务所需的目录。

```json
{
  "mcpServers": {
    "verify-helper": {
      "command": "verify-helper-mcp",
      "args": ["--workspace", "/path/to/projects"]
    }
  }
}
```

Streamable HTTP 使用相同的核心和工具。

```sh
verify-helper-mcp --workspace /path/to/projects --transport streamable-http --port 8765
```

HTTP 服务监听 127.0.0.1，在 /mcp 提供标准接口。跨主机连接需要加密通道。配置 VERIFY_HTTP_BEARER_TOKEN 后，HTTP 客户端必须发送对应的 Bearer 凭据。动态执行通过启动参数 --trust-project-code 启用，HTTP 模式同时要求配置凭据。工具 verify_start 接收工作区相对 path 和可选 against，返回结构化裁决和证据。代码修改 Agent 与验证进程可以各自在独立工作区运行，使用提交和快照摘要关联结果。

## 适用检查

| 项目 | 验证范围 |
|---|---|
| Python | 语法、编码、测试，及项目显式声明的变异和业务契约 |
| JavaScript | Node 语法、npm 或 Node 测试及运行契约 |
| TypeScript 与 JSX | TypeScript 编译器及测试入口，项目须提供 tsconfig.json |
| C/C++ | CMake 构建与 CTest，或项目声明的构建与运行契约 |
| Web | HTML 与链接、HTTP 页面、Chromium 及已声明的交互流程 |
| 交付物 | ZIP、wheel、Tar/Gzip 完整性与成员校验，wheel RECORD 哈希校验 |

适用的动态检查使用环境已安装的工具。可使用 VERIFY_TEST_PYTHON 指定可信 Python 解释器，使用 VERIFY_PLAYWRIGHT_ROOT 指定包含 node_modules/playwright 的目录，使用 PLAYWRIGHT_BROWSERS_PATH 指定浏览器缓存，使用 VERIFY_TSC 指定 TypeScript 编译器。验证进程保留一组工具链所需的环境变量，临时目录与用户配置目录按次分配。

Windows 工具链受路径长度限制时，可以用 VERIFY_SCRATCH_DIRECTORY 指定现有的短路径临时目录。每一轮仍创建独立子目录。

## 项目规则

在项目根放置 verify.toml。交互步骤与静态正则可参考 examples 下的配置。声明的运行命令需要返回退出码 0，并输出一行精确匹配的断言文本。

```toml
[verification]
mutation = false

[[verification.contracts]]
argv = ["python", "tests/verify_save_migration.py"]
expect_output = "Save migration verified"
```

交付约定可使用 [[verification.delivery]]，提供相对 path、sha256 与非空 members 列表。C/C++ 可以用 [verification.build] 与 [verification.runtime] 声明 argv 和 expect_output。

## 裁决与证据

每次运行的 UUID 对应一个证据目录，默认位于项目的 .verify-artifacts。report.json 包含项目提交、源快照 SHA-256、检查计划、各项状态、证据文件摘要及总裁决。已执行的页面、测试和命令覆盖可以在对应检查中核对。results.sarif 用于代码扫描服务。缺少必检项、写证据失败或只执行部分用例会阻止 PASS。PASS 表示当前验证计划已执行并通过，发布验证另有跨平台和独立审计要求。
