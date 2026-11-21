# Verify Helper · 验证助手

[English](#english)

Verify Helper 是验证文件和项目的 CLI 与 MCP 工具。它运行适用检查，输出 PASS、FAIL 或 UNKNOWN，并保存 JSON、SARIF 和逐项证据。

**2.0.1 系列在本机以当前用户身份运行项目测试和声明的命令，可访问本机文件和网络。只用于可信项目。** 单文件验证只做适用的静态与归档检查。

需要 Python 3.11 或更新版本。从 [Release](https://github.com/ngwddd/verify-helper/releases/tag/v2.0.1-rc3) 下载 wheel 和 SHA-256 清单，核对后安装。

```sh
python -m pip install ./verify_helper-2.0.1rc3-py3-none-any.whl
verify-helper run /path/to/project --json
verify-helper run /path/to/file.py --json
```

stdio MCP 客户端配置

```json
{
  "mcpServers": {
    "verify-helper": {
      "command": "verify-helper",
      "args": ["serve", "--workspace", "/path/to/projects"]
    }
  }
}
```

用 `verify_run_full` 提交相对文件或项目路径，用 `verify_get_report` 轮询终态。用 `verify_compare_runs` 对比同一工作区、同一目标和兼容计划的两次运行。多项目工作区需指定相对路径。默认使用 stdio，Streamable HTTP 仅在本机回环地址提供服务并要求 Bearer token。

项目模式会运行适用的 Python unittest 和 Node 内置测试。已配置的浏览器检查和业务契约在工具可用时运行。只有在 `verify.toml` 中设置 `[verification]` 下的 `npm_test = true` 才会自动运行 npm 测试脚本。验证器不会安装项目依赖。缺工具、零用例、跳过或覆盖不完整时，适用检查返回 UNKNOWN。命令退出码为 0（PASS）、1（FAIL）、2（UNKNOWN）。

unittest 默认核对 `test*.py` 和 `*_test.py`，可在 `verify.toml` 的 `[verification]` 下用 `unittest_patterns` 指定发现范围。pytest 使用项目的文件命名规则，并单独报告被过滤的用例。Python 优先使用原项目的虚拟环境，Node 测试和声明的业务命令可复用已安装的依赖。需要运行的 `smoke_*.py` 可在 `[[verification.contracts]]` 中声明。浏览器截图保存在本机私有证据目录，MCP 只返回证据摘要。

Git 修订验证核对源代码修订，并记录选用的 Python 或 Node 版本。报告以 `HOST_UNPINNED` 标记本机依赖的可复现性限制。

## English

Verify Helper checks files and projects through the CLI and MCP. It runs applicable checks and returns PASS, FAIL, or UNKNOWN with JSON, SARIF, and per-check evidence.

**The 2.0.1 series runs project tests and configured commands locally as the current user, with access to local files and the network. Use it for trusted projects.** An individual file receives applicable static and archive checks.

Python 3.11+ is required. Download and verify the wheel from the [GitHub Release](https://github.com/ngwddd/verify-helper/releases/tag/v2.0.1-rc3), then use the commands above. Standard use requires no Docker or custom environment variables.

Call `verify_run_full` with a project or file path and poll `verify_get_report` until it completes. Use `verify_compare_runs` to see changes between compatible reports for the same target. The server uses stdio by default. Loopback Streamable HTTP requires a bearer token.

Project runs use available unittest or Node tests and configured adapters. The verifier does not install dependencies. Add `npm_test = true` under `[verification]` to enable npm test scripts. Missing tools, empty suites or incomplete coverage yield UNKNOWN for required checks. Exit codes are 0 for PASS, 1 for FAIL and 2 for UNKNOWN.

Unittest checks both `test*.py` and `*_test.py` by default. Set `unittest_patterns` under `[verification]` in `verify.toml` to define discovery patterns. Pytest honors the project's file naming configuration and reports deselected cases separately. Tests and contracts can reuse installed project dependencies. Declare applicable `smoke_*.py` scripts in `[[verification.contracts]]`. Browser screenshots stay in the private local evidence directory. MCP returns an evidence summary.

Git verification checks the source revision and records the selected Python or Node version. `HOST_UNPINNED` identifies the reproducibility limit of the installed dependency environment.
