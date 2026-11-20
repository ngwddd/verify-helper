# Open release risks

| Item | Status | Required evidence |
|---|---|---|
| OS-level and network containment | PARTIAL | The RC3 branch adds a Linux-only offline container candidate. Windows guest isolation and independent security acceptance remain open. See [RC3 security evidence](RC3-SECURITY.md). |
| Cancellation of detached descendants | PARTIAL | Windows Job Object cleanup is verified. Detached POSIX descendants remain outside the tested guarantee. |
| Repository trial runs | NOT_RUN | Obtain explicit per-repository authorization and isolated environments. |
| Client matrix | PARTIAL | Official Python SDK and independent TypeScript SDK 1.27.1 exercised. Desktop Agent evidence is still required. |
| Workflow and ledger | PARTIAL | Dynamic requirements are frozen before project command execution. Immutable approved exceptions and complete tool/environment receipts remain open. |
| Adapter and release evidence | PARTIAL | YAML, viewport and Python package identity are tested. Dependency/security scanning, EXE installation and private-domain oracle coverage remain open. |
| Evidence authentication | PARTIAL | Manifest validates digests. Storage with a separate signing or writer identity is required against a co-privileged writer. |

These gaps keep the full 2.0.0 release at NO-GO. RC2 candidate evidence applies to the narrower trusted-project workflow.
