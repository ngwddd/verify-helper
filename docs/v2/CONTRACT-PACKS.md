# Project verification contracts

Configure project-owned assertions in `verify.toml`. The fixtures in `tests/test_full_verify.py` model source and product boundaries with synthetic data.

| Contract family | Project-owned oracle |
|---|---|
| Build and runtime | Expected output from an assertion program, run against compiled output. |
| Business state | Expected outputs for a migration, persistence operation or transaction. Use independent fixtures for expected values. |
| Browser | Assertions for URL, element visibility, text, input state and console errors. Conditions in a step are evaluated together. |
| Delivery | SHA-256 and required members for each release file. |
| Operator policy | JSON `required_checks` list can add checks to the full gate. An unavailable added check blocks PASS. |

See `examples/verify.toml` and `examples/verify-flows.toml`.
