# Beacon test migration

The earlier JavaScript reference tests were not kept as stale tests against removed modules. Their security-relevant assertions were migrated to colocated Rust unit tests against the production implementation:

- deterministic position selection and context separation: `src/randomness/extractor/unit-tests/`
- finalized/bounded Kaspa block evidence: `src/randomness/source/kaspa/unit-tests/`
- CURBy response parsing, cache reuse, and one-request-per-minute reservation: `src/randomness/source/curby/unit-tests/`
- beacon reconstruction and tamper rejection: `src/randomness/beacon/unit-tests/`

Bitcoin-specific fixtures and tests were intentionally removed because Bitcoin is not a Kaspa Portal randomness source.
