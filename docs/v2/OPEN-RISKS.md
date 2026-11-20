# Open release risks

| Item | Status | Required evidence |
|---|---|---|
| OS-level and network containment | OPEN | Chromium preview routing is restricted to the preview origin. Untrusted execution remains disabled. A verified host sandbox and independent evidence writer are still required. |
| Cancellation of detached descendants | PARTIAL | Windows Job Object cleanup is verified. Detached POSIX descendants remain outside the tested guarantee. |
| Repository trial runs | NOT_RUN | Obtain explicit per-repository authorization and isolated environments. |
| Client matrix | PARTIAL | Official Python SDK and independent TypeScript SDK 1.27.1 exercised. Desktop Agent evidence is still required. |
| Workflow and ledger | PARTIAL | Dynamic requirements are frozen before project command execution. Immutable approved exceptions and complete tool/environment receipts remain open. |
| Adapter and release evidence | PARTIAL | YAML, viewport and Python package identity are tested. Dependency/security scanning, EXE installation and private-domain oracle coverage remain open. |
| Evidence authentication | PARTIAL | Manifest validates digests. Storage with a separate signing or writer identity is required against a co-privileged writer. |

These gaps keep the full 2.0.0 release at NO-GO. RC2 candidate evidence applies to the narrower trusted-project workflow.
