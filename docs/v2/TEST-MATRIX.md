# v2 verification matrix

| Contract | Automated entry | Positive and negative cases |
|---|---|---|
| Complete gates | `tests/test_full_verify.py` | Real Python, Node, TypeScript, native and Chromium checks. Missing runner, skipped tests, damaged evidence and worker cleanup faults. |
| P0 boundary regressions | `tests/test_full_verify.py` | 121st JS file, secret output, merge conflict, lifecycle failure, program cancellation. |
| Browser assertions | `tests/test_full_verify.py`, `verification_resources.test.mjs` | Prefixed ES modules and combined assertions, screenshots and paths. |
| MCP interoperability | `tests/test_mcp.py` | SDK modern and legacy negotiation with both transports, HTTP auth and Origin rejection, cancellation and report retrieval after restart. |
| Packaging | CI distribution job | Both archive formats, wheel RECORD, installed entry points, code and report evidence. |
| Host support | CI on Windows and Linux | Python 3.11–3.14, Chromium and C/C++ on Python 3.12. Windows CI uses Zig/Clang. |

Independent interoperability was exercised locally with the TypeScript SDK 1.27.1 stdio client. It retrieved a PASS from the new run API and received a tool error on a path outside its workspace.

The final release audit still requires exact candidate CI, a desktop Agent, operating-system containment, and the remaining cross-repository and privacy acceptance tests.
