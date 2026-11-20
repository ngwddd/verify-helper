# Verify Helper

Verify Helper 通过 CLI 或 MCP 对项目运行完整验证，输出 PASS、FAIL 或 UNKNOWN，并留下 JSON、SARIF 和逐项证据。当前分支使用 Python MCP SDK v2，支持 MCP 2026-07-28 以及 SDK 支持的旧协议。

## 安装与运行

需要 Python 3.11 或更新版本。开发版可使用以下命令。

```sh
uv sync --locked
uv run verify-helper run /path/to/project --json report.json
```

RC4 是 Linux 隔离执行有限预览。默认 CLI 和 MCP 采用受保护的报告出口；隔离或覆盖证据缺失时返回 UNKNOWN。退出码为 0（PASS）、1（FAIL）或 2（UNKNOWN）。跨平台正式版仍为 NO-GO。 [RC4 整改记录](docs/v2/RC4-AUDIT.md)

| 参数 | 用途 |
|---|---|
| unsafe-local-run PROJECT | 只用于手动调试已审查的自有项目。以宿主身份执行，结果不可发布。 |
| --against main | 对干净 Git 工作树与指定提交的合并结果运行验证 |
| --evidence-dir PATH | 指定证据根目录 |
| --json [FILE] | 把机器可读报告写入文件，省略文件时输出到标准输出 |
| --sarif FILE | 另存 SARIF 2.1.0 报告 |
| --list-checks | 显示可用检查 |

## MCP

stdio 示例配置。将工作区限定到验证任务所需的目录。

```json
{
  "mcpServers": {
    "verify-helper": {
      "command": "verify-helper",
      "args": ["serve", "--transport", "stdio", "--workspace", "/path/to/projects"]
    }
  }
}
```

Streamable HTTP 使用相同的核心和工具。

```sh
verify-helper serve --workspace /path/to/projects --transport streamable-http --port 8765
```

HTTP 服务监听 127.0.0.1，在 /mcp 提供标准接口，拒绝外部 Origin。跨主机连接需要加密通道。启动 HTTP 模式前必须配置 VERIFY_HTTP_BEARER_TOKEN，所有 HTTP 请求均须携带对应的 Bearer 凭据。MCP 仅在 Linux 隔离候选由操作者显式启用时进行支持的动态检查。

工具 `verify_run_full` 接收工作区相对 `path`，可选 `policy_path`、`revision` 或合并基准 `source_ref`。使用返回的 `run_id` 调用 `verify_get_report`，直到任务结束。用 `verify_list_capabilities` 探测运行环境，用 `verify_cancel` 请求取消。Agent 应读取 `verdict` 与 `releasable` 决定是否放行。

### Linux 隔离候选

操作者可以用 `VERIFY_HELPER_SANDBOX_IMAGE=sha256:<本机镜像 ID>` 配置独立运行环境，服务为每次任务检验可用性。Docker 容器默认断网、无宿主映射并以非 root 运行，目前只调度标准库 unittest。管理员可用 `VERIFY_HELPER_SANDBOX_TIMEOUT_SECONDS` 设置单命令 5 至 180 秒的上限，默认为 60 秒。受保护模式不运行项目的宿主命令，也不采用项目自定义的 `.verifyignore`。目前 Git 修订、合并、其他动态适配器和不完整测试覆盖均保留 UNKNOWN。 [RC4 整改记录](docs/v2/RC4-AUDIT.md)

## 适用检查

| 项目 | 验证范围 |
|---|---|
| Python | 语法、编码、测试，及项目显式声明的变异和业务契约 |
| JavaScript | Node 语法、npm 或 Node 测试及运行契约 |
| 配置文件 | JSON、TOML 与 YAML 语法 |
| TypeScript 与 JSX | TypeScript 编译器及测试入口，项目须提供 tsconfig.json |
| C/C++ | CMake 构建与 CTest，或项目声明的构建与运行契约 |
| Web | HTML 与链接、HTTP 页面、Chromium 及已声明的交互流程 |
| 交付物 | ZIP、wheel、Tar/Gzip 完整性与成员校验，wheel RECORD 哈希校验 |

适用的动态检查使用环境已安装的工具。可使用 VERIFY_HELPER_TEST_PYTHON 指定可信 Python 解释器，使用 VERIFY_PLAYWRIGHT_ROOT 指定包含 node_modules/playwright 的目录，使用 PLAYWRIGHT_BROWSERS_PATH 指定浏览器缓存，使用 VERIFY_TSC 指定 TypeScript 编译器。验证进程保留一组工具链所需的环境变量，临时目录与用户配置目录按次分配。

Windows 工具链受路径长度限制时，可以用 VERIFY_SCRATCH_DIRECTORY 指定现有的短路径临时目录。每一轮仍创建独立子目录。

## 项目规则

在项目根放置 verify.toml。交互步骤与静态正则可参考 examples 下的配置。声明的运行命令需要返回退出码 0，并输出一行精确匹配的断言文本。

浏览器仅访问验证器启动的预览站点。跨站请求或 WebSocket 被阻断时，相应覆盖记为缺失。浏览器流程可以声明 viewport，例如 `{width=390, height=844}`。

```toml
[verification]
mutation = false

[[verification.contracts]]
argv = ["python", "tests/verify_save_migration.py"]
expect_output = "Save migration verified"
```

交付约定可使用 [[verification.delivery]]，提供相对 path、sha256 与非空 members 列表。C/C++ 可以用 [verification.build] 与 [verification.runtime] 声明 argv 和 expect_output。

## 裁决与证据

每次运行的 UUID 对应一个证据目录，默认位于用户的 `.verify-helper` 目录。report.json 记录源快照 SHA-256、策略与冻结计划摘要、覆盖率账本及裁决。受保护报告只导出允许的字段，项目诊断、路径、原始日志、截图和二进制附件留在出口之外。manifest.json 绑定报告、逐项收据与 SARIF。重取报告时会重新校验其摘要。缺少必检项、写证据失败或只执行部分用例会阻止 PASS。Windows Worker 使用 Job Object 收尾子进程，Windows 客户机隔离仍待验证。

从 1.x 升级请参阅 [迁移指南](docs/MIGRATION-v1-to-v2.md)。
