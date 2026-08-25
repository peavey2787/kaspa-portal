# Security Policy

## Supported release

`kaspa-portal` 1.0.x is the supported API/security line.

## Security model

`kaspa-portal` separates consensus/protocol logic from platform adapters. Native and browser entry points call the same Rust implementations; browser code is not a second consensus implementation.

Security-sensitive parsers are bounded, exact consensus-sized JSON integers are canonical unsigned decimal strings, monetary arithmetic uses checked integer operations, and protocol-specific secret material is zeroized where supported by its owning type.

## Keys and secret material

Kaspa wallet/spending keys and RFC 9381 VRF keys are different cryptographic domains. Do not reuse a Kaspa spending key as a VRF key. Raw VRF secret export is disabled unless the `secret-export` feature is explicitly enabled.

Public randomness from Kaspa block hashes or CURBy is **not secret entropy**. Do not use the beacon output as the sole source for wallet seeds, encryption keys, authentication secrets, password salts that require unpredictability from observers, or similar secret-generation tasks.

Applications remain responsible for protecting mnemonic/private-key material at rest. The lightweight indexer and its IndexedDB backend are designed for public/index data and must not be used as a secret-key vault.

## Randomness

The beacon/extractor accepts only explicitly finalized Kaspa evidence and deterministically binds network, context and source evidence into its output. Verification reconstructs the result rather than trusting a supplied success flag.

CURBy is an optional public source. Client refresh attempts are reserved before I/O and rate-limited to no more than once per 60 seconds. A successful raw HTTPS API fetch is recorded as `RawApiUnverified`; it is not upgraded to independently source-verified evidence without external verification.

The separate VRF implements RFC 9381 `ECVRF-EDWARDS25519-SHA512-ELL2`. Conformance vectors belong in `qa/tests/conformance/rfc9381/`.

NIST SP 800-22-style statistical checks are health diagnostics only. Passing them does not prove unpredictability or cryptographic security. [NIST audit notes](randomness/NIST_AUDIT.md) records deviations found in the retained statistical reference code that were intentionally not reproduced.

## Browser/WASM

Use `wss://` endpoints in production. If an application deliberately allows plaintext `ws://` for local development, restrict it to loopback and never ship that configuration as production policy.

Keep a restrictive Content Security Policy. Limit `connect-src` to the intended Kaspa node(s) and, when CURBy is enabled, the explicitly required CURBy origin. Treat all node/indexer data as untrusted input.

Consensus amounts/DAA scores must stay `BigInt` or canonical decimal strings in JavaScript. Never convert sompi or DAA values through JavaScript `Number`.

IndexedDB state is schema-versioned and validated before restoration. It contains public indexer state/checkpoints/matchers, not live WASM object pointers. An application should still treat IndexedDB as attacker-modifiable local storage and rely on validation/reconciliation before trusting restored state.

## Network and node trust

A node can lie, omit data, delay data or disconnect. Retry/reconnect logic improves availability; it does not make an untrusted node authoritative. Applications requiring stronger guarantees should use independent nodes and validate the evidence required by their threat model.

## Required production gates

Before release, run:

Linux:

```bash
./run-all-linux.sh
```

Windows:

```cmd
run-all-windows.cmd
```

A production release should not be declared green unless the Rust test suite, Clippy, fuzz harness build and WASM target check actually execute successfully in an environment with the pinned Rust toolchain.

## Reporting vulnerabilities

Report suspected vulnerabilities privately to the project maintainers. Include the affected version, reproduction steps, security impact and any relevant test vector or minimal reproduction. Avoid public disclosure until a fix or coordinated disclosure date is available.
