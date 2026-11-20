# Requirements and evidence

| Requirement | Implementation | Test or limitation |
|---|---|---|
| P0-01 credential handling | `verify_core.scan_text_once`, `full_verify.scrub` | Synthetic secret absent from JSON and saved outputs. Screenshots and private output channels need further acceptance. |
| P0-02 partial discovery | `check_syntax`, `check_runtime_web`, `check_browser` | 121st JS fixture. Browser and HTTP boundary cases should remain in the acceptance suite. |
| P0-03 original workspace | Temporary working copies, mutation copies, per-command cancellation | Source bytes and generated file checks, plus a running command cancellation test. OS-level descendant containment remains open. |
| P0-04 merge | Git merge-tree and archived tree verification | Real conflicting histories return FAIL; missing refs return UNKNOWN. |
| P0-05 lifecycle | Lifecycle exception binds UNKNOWN unless a check already failed | Injected failure reproduced PASS before the fix, UNKNOWN after. |
| P0-06 browser availability | Required Web rows remain applicable with missing prerequisites | Actual Chromium integration and full ledger tests. |
| P1-02 browser assertions | `flow_runner.mjs` | Real combined assertion reproduced false PASS and is now FAIL on mismatched text. |
| P1-03 cache identity | `verify_core.Cache` | Same-size and same-timestamp changed JS invalidates cache. |
| P1-04 RPC versus gate | `server.py`, `run_evidence.py` | Structured FAIL carries `releasable=false` under both protocol revisions. |
| Run durability | `RunStore`, manifest verification | Stdio restart can reopen the same terminal run; changed receipt fails verification. |
