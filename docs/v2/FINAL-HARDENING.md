# v2.0 发布加固 / Release hardening

基线 / Baseline: `52ef43fa88226d19d4e604f2965c4a655362ff64`

**通用正式版 NO-GO。RC4 维持 Linux 有限预览。**

**General release NO-GO. RC4 remains a limited Linux preview.**

| 编号 | 进度与证据 |
|---|---|
| P0-01 | 操作者批准的 Python 黑盒测试在 Linux 实际隔离中有独立比对与计数。通过的是行为检查本身，完整发布级隔离与项目套件覆盖证明未完成。 |
| P0-02 | 新增离线 Node 语法与行为检查。JS 套件覆盖、TS、C/C++、浏览器与其他契约仍缺受保护运行证据。 |
| P0-03 | Windows 客体未实现或验证。Windows CI 只说明宿主兼容性。 |
| P0-04 | L01–L18 尚未全量通过。保留原始 [验收矩阵](RC3-SECURITY.md)。 |
| P0-05 | 隔离 CI 覆盖 Python 与 Node 的真实行为。发布核验器要求独立签名和两个平台的完整受保护 PASS。完整正向自验仍待完成。 |
| P0-06 | 常规 SHA-1 仓库支持精确修订和干净工作树核对、合并树检查与冲突裁决。私有元数据仓库不读取源仓配置、钩子、对象 alternates。子模块、链接、导出属性导致内容不符及例外工作树仍保持 UNKNOWN。 |
| P0-07 | 真实项目与桌面 Agent 的独立验收待完成。 |
| P1-08 | 本地 CLI 可显式生成并校验查找索引。MCP 仍不发送原始路径。 |
| P1-09 | 正常取消和超时有回归。系统崩溃与 Docker 异常清理待验证。 |
| P1-10 | 证据绑定快照、策略及检查。独立签署身份待完成。 |
| P1-11 | Windows 在读取前核对文件句柄与预期位置。并发和路径变体矩阵未完成。 |
| P1-12 | 本地证据按快照导入、固定排除、私有排除、不安全或已变更分类计数。可影响覆盖的遗漏继续阻断 PASS。 |
| P1-13 | 正则遇限保留发现的确定性 FAIL，并记录覆盖缺口。测试包含单纯遇限及确定失败后遇限。独立资源耗尽测试仍待补。 |
| P1-14 | Linux CI 镜像固定到摘要。构建输出附带锁定依赖的 CycloneDX SBOM，镜像供应链签名和独立依赖扫描待完成。 |
| P1-15 | 任务仍提供排队、快照、验证和封存状态。异常重启后的恢复证据不足。 |
| P1-16 | 双语文档区分受保护范围、显式调试和已发表预览。其他语言完整能力待认证。 |
| P1-17 | 本地语法别名索引与其摘要绑定。其他检查的安全定位字段待完善。 |
| P2-18 | 更新正式版冻结清单。 |
| P2-19 | CI 示例固定 RC4 wheel 的 URL 与 SHA-256，UNKNOWN 仍返回退出码 2。 |
| P2-20 | 复杂工作区建议提供明确项目相对路径。深层发现策略待完成。 |
| P2-21 | 现有限额保持有效。大型项目容量验收待完成。 |
| P2-22 | 行为检查仅导出固定状态与计数。全量元数据出口策略待完成。 |

## 黑盒策略 / Black-box policy

操作者在项目之外保存一个绝对路径的私有 JSON 文件，配置 `VERIFY_HELPER_ORACLE_POLICY`。策略必须指定原始项目绝对路径、同一次源快照的 SHA-256、项目内相对 Python 或 JavaScript 入口和 2 至 8 个不同用例。用例具有不同输入，至少有两种不同的预期结果。运行者只能从 Linux 隔离进程接收有大小限制的输出，并在宿主计算匹配结果。原文及预期值不进入取回报告。运行时仍须配置固定本机镜像 ID。

The operator stores a private JSON policy outside the project and supplies its absolute path in `VERIFY_HELPER_ORACLE_POLICY`. Obtain the snapshot digest from local evidence for the same project state. The verifier requires two to eight distinct inputs and at least two distinct expected results. It compares bounded stdout and the observed exit status outside the tested process. The preview records the behavior verdict separately from the overall Full Verification verdict.

```json
{
  "project": "/work/project",
  "snapshot_sha256": "<local snapshot digest>",
  "entry": "entry.py",
  "cases": [
    {"argv": ["one"], "stdout": "1\n", "exit_code": 0},
    {"argv": ["two"], "stdout": "2\n", "exit_code": 0}
  ]
}
```

验证入口 / Reproduction: `uv run python -m unittest discover -s tests -p sandbox_acceptance.py -v` on Linux Docker, or check **Linux isolation acceptance** in the branch CI. The suite includes valid behavior, stale authorization and a zero-exit program with incorrect behavior. The independent general release review is pending.
