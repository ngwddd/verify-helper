# RC3 P0 防外泄基线

基线为 `d50cc36ee51bdcdfcb0f9443ba932e202bbba47c`。发布物包括 wheel、源码包、SHA256SUMS 和 provenance。基线运行覆盖 Windows 和 Linux 的 Python 3.11–3.14。 [RC2 发布](https://github.com/ngwddd/verify-helper/releases/tag/v2.0.0-rc2) · [基线 CI](https://github.com/ngwddd/verify-helper/actions/runs/44825941364)

| RC2 执行路径 | 涉及的信任边界 | RC3 开发状态 |
|---|---|---|
| `full_verify._source_git`、`_merge_snapshot` | Git 本地配置、合并驱动、宿主工作区 | 受保护入口停止调用宿主 Git，修订与合并验证记 UNKNOWN。显式可信 CLI 仍保留。 |
| `verify_core.check_syntax` | Node 语法检查读取宿主工作区上下文 | 受保护入口跳过宿主 Node，适用覆盖记 UNKNOWN。 |
| `verify_core.check_tests`、`check_mutation` | 项目测试及其子进程在宿主身份下运行 | Linux 隔离候选支持 Python unittest。其余适用项记 UNKNOWN。 |
| `verification_adapters` | CMake、CTest、TypeScript、构建和运行契约可执行项目命令 | 受保护入口判定适用性并记录缺失。 |
| `check_runtime_web`、`check_browser`、`check_interaction` | 浏览器预览、子进程、网络路由、截图 | 受保护出口不复制媒体。隔离浏览器适配器待实现。 |
| `full_verify._worker`、`run_evidence`、`server.RunStore` | 任意诊断、截图、文件名与报告完整性 | MCP 输出按固定字段重建。MCP 主进程认证报告清单，隔离候选输出的字节流被丢弃。 |
| `process_boundary` | 子进程生命周期 | Windows Job Object 负责回收。Linux 容器限制进程并在结束后销毁。 |

RC2 的文件读取、外部请求和证据写入风险来自源码路径分析。合成测试验证防护条件，使用假敏感值、假项目配置、宿主路径标记和测试网络地址。 [RC3 核验矩阵](RC3-SECURITY.md)
