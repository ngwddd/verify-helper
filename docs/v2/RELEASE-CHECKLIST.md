# v2.0 正式版冻结清单 / General release checklist

| 冻结项 / Freeze item | 记录 / Record |
|---|---|
| 精确提交 / Exact candidate commit | 待冻结 / Pending |
| CI 运行、构件与 SHA-256 / CI run, artifacts and checksums | 待复核 / Pending |
| Windows/Linux 客体与工具链标识 / Guest and toolchain identities | Windows 未验收 / Windows pending |
| 独立复核人及结论 / Independent reviewer and decision | 未批准 / Not approved |

- 分别复核 Windows 和 Linux 的完整受保护自验。每个结果需要精确 SHA、隔离证明、冻结计划、用例覆盖和可核对收据。
- Review protected Full Verification independently on Windows and Linux. Require the exact commit, isolation evidence, the frozen plan, test coverage and authenticated receipts.
- 关闭 P0 和 P1 中的安全与判定阻断项。复验 L01–L18、多语言、Git 合并、真实项目和真实 MCP Agent 流程。
- Close security and verdict blockers. Re-run L01–L18 and cover language adapters, Git merges, real projects and real MCP agent workflows.
- 校验 wheel、源码包、SBOM、SHA-256、provenance 与同一候选提交一致。核对说明文档与实际支持范围。
- Match the wheel, sdist, SBOM, checksums and provenance to the same commit. Document only verified support.
- 由未参与实现的复核人根据冻结证据签发 GO 后发布正式版。
- Publish the general release only after an independent reviewer approves the frozen evidence.

## 独立签名核验 / Independent signature check

```sh
uv run --group release python release_approval.py COMMIT ASSET_DIRECTORY EVIDENCE_DIRECTORY APPROVAL_JSON DETACHED_SIGNATURE REVIEWER_PUBLIC_KEY
```

审批人预先从可信渠道提供 Ed25519 公钥，私钥只由审批人保管。验收者校验审核证据和收据清单后，用该私钥签署原始 JSON 文件。发布人使用已确认的公钥核对签名。候选包的 provenance 不代替正式放行。

The independent reviewer keeps the Ed25519 private key and publishes the trusted public key separately from the candidate checkout. After validating the underlying evidence and its receipts, the reviewer signs the exact approval JSON bytes. The publisher checks the signature with the previously trusted key. Candidate build provenance carries no release approval.

审批 JSON 绑定 `schema_version=1`、`repository=ngwddd/verify-helper`、版本、完整提交、`workflow_run`、`verdict=GO` 和空的 `open_blockers`。还须提供 `security_tests`（L01–L18）、`matrices`（多语言、Git/真实项目、桌面 Agent、独立证据）、`assets`（五个文件的 SHA-256）及 `reports`（Linux/Windows 全验报告 SHA-256）。字段名称以 [核验器](../../release_approval.py) 为准。
