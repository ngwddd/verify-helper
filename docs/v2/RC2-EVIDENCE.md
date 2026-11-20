# Verify Helper 2.0.0 RC2

RC2 is a prerelease for the trusted-project workflow. Its release evidence covers the pinned candidate on Windows and Linux, Python 3.11–3.14, and real Chromium, TypeScript, C/C++ and installation smoke tests where configured.

## Changes

- YAML syntax is checked. Missing Node leaves JavaScript syntax applicable and incomplete, while known source failures retain FAIL.
- The required dynamic check plan is frozen before project commands run and bound to the evidence manifest. Mutation sampling keeps unexecuted candidates visible.
- Windows uses a Job Object for the verifier worker and its descendants. Chromium previews block access outside the preview origin, and flows can assert behavior at a chosen viewport.
- Delivery checks compare Python package metadata with filenames. CI binds package hashes to the exact clean source commit and archived evidence.

## Scope still under audit

Untrusted project execution remains disabled. Host-level filesystem and network containment, detached POSIX process cleanup, an independently permissioned evidence writer, and private cross-project trial runs remain open. The desktop Agent and optional application-specific toolchains require separate evidence. See [the open risks](OPEN-RISKS.md).
