# Migrate Verify Helper 1.x to 2.x

The full verification command and MCP tool use the same gate. Exit codes are 0 for PASS, 1 for FAIL and 2 for UNKNOWN. Reports require a valid evidence manifest when reopened.

| Previous interface | Version 2 |
|---|---|
| `python verify_core.py PROJECT` | `verify-helper run PROJECT` |
| `--fast`, `--checks` or `--stage` | Run full verification for the project. Removed options return a migration error. |
| `python server.py` / vendor toolbar | `verify-helper serve --transport stdio --workspace DIR` |
| `verify_start` | `verify_run_full`, followed by `verify_get_report` using the returned run ID |
| `verify_report`, `verify_checks` | `verify_get_report` and `verify_list_capabilities` |
| `verify_accept` | Agent-facing waiver writes were removed |
| `DSH_TEST_PYTHON` | Operator-provided `VERIFY_HELPER_TEST_PYTHON` |
| MCP `against` input | `source_ref` supplies the merge base for the clean checkout |

The CLI accepts `--json FILE`, `--json` for stdout and `--evidence-dir DIR` for a dedicated artifact directory. The default CLI report location is under the local user state outside the project. MCP stores runs by workspace and principal namespace. Verify Helper 2.0.1 runs installed project tools as the current user. Use it for trusted projects. `verdict` describes the checks that ran. The historical `releasable` field remains for report compatibility and is false for local project runs.

The last 1.x GitHub release remains available as v1.10.7. [v1.10.7 release](https://github.com/ngwddd/verify-helper/releases/tag/v1.10.7)
