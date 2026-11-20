# Open release risks

| Item | Status | Required evidence |
|---|---|---|
| OS-level and network containment | OPEN | Untrusted execution kept disabled. Need verified sandbox and an independent evidence writer. |
| Cancellation of detached descendants | OPEN | Tracked commands and restart retrieval tested. Detached processes require operating-system job containment. |
| Repository trial runs | NOT_RUN | Obtain explicit per-repository authorization and isolated environments. |
| Client matrix | PARTIAL | Official Python SDK and independent TypeScript SDK 1.27.1 exercised. Desktop Agent evidence is still required. |
| Workflow and ledger | PARTIAL | Freeze applicability before adapters execute, add immutable approved exceptions and complete tool/environment receipts. |
| Adapter and release evidence | PARTIAL | Dependency/security scanning, EXE installation, mobile viewport, performance and private-domain oracle coverage remain open. |
| Evidence authentication | PARTIAL | Manifest validates digests. Storage with a separate signing or writer identity is required against a co-privileged writer. |

The current release decision is NO-GO pending these requirements and Owner review.
