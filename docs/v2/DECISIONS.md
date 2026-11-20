# v2 implementation decisions

- Use SDK v2 negotiation for both transports. Start, retrieve, list and cancel are distinct operations, with one verification mode.
- Apply the formal environment variable and command names. The development-only historical command syntax remains a full-run alias.
- Bind manifests to the snapshot and operator policy digest. Report retrieval validates archived file digests before returning a final result.
- A discovered skipped test remains a coverage gap until a separately authorized policy can distinguish optional coverage. This follows the strict ledger rule in section 9. Section 11's mixed-skip PASS example needs an Owner decision on optionality.
- Runtime fixtures can use a declared toolchain and a working copy. Separate OS identity, filesystem policy and network containment are open.
