# kaspa-portal architecture

`kaspa-portal` is organized by Kaspa capability with a thin orchestration facade over focused domains.

## Public domains

```text
portal
network
chain
wallet
transaction
contract
privacy
indexer
randomness
crypto
primitives
platform
```

`KaspaPortal` is orchestration only. Complex domains expose a facade; narrow algorithms and value types remain directly usable.

## Dependency direction

The enforced production dependency graph is:

```text
primitives -> (leaf)
crypto     -> primitives
network    -> primitives
chain      -> network, primitives
wallet     -> chain, crypto, primitives
contract   -> crypto, primitives
privacy    -> wallet, crypto, primitives
indexer    -> primitives
randomness -> crypto, primitives
transaction -> chain, contract, crypto, network, primitives, wallet
platform   -> target adapters over core domains
portal     -> composes domains and platform adapters
```

Core domains do not import `platform`. Network transports, time and CURBy I/O are injected/constructed at the platform/portal boundary. IndexedDB implements the indexer persistence contract; it does not own indexing logic.

`qa/scripts/check_architecture.py` enforces these edges and rejects obsolete namespaces.

## Native wRPC lifecycle

Native networking is connection-oriented. `NativeWebSocketTransport` owns a driver task and a single persistent WebSocket shared by cloned `NetworkClient`/`NetworkApi` handles for that Portal. The driver:

- serializes outgoing RPC calls and retains request identity until the matching response arrives;
- routes server notifications independently, so a BlockAdded frame can arrive between a request and its response;
- records successful subscription payloads and replays them with fresh request IDs after reconnect;
- bounds queued notifications and tears down a timed-out socket so a late response cannot be associated with a later request;
- never automatically retries `SubmitTransaction`, avoiding duplicate-broadcast ambiguity; and
- responds to explicit `disconnect()` through a separate shutdown channel even when the RPC command queue is full.

The public native BlockAdded decoder/API lives in `network`; transport/WebSocket details remain in `platform/native`. `KaspaPortal::start_live_indexer()` is orchestration at the portal boundary rather than an `indexer -> network` dependency. The live-indexer task is shared across Portal clones and is aborted when the final shared runtime is dropped.

## Transaction payload boundary

KSPT v1's payload length is a little-endian `u16`, so Portal's application-payload ceiling is exactly 65,535 bytes. The transaction model stores payloads in `Vec<u8>` and KSPT encode/decode paths reject values beyond that format limit. Standard PSKT parser offsets/decoded-JSON lengths are wider than `u16`, because a maximum-size binary payload represented as JSON/hex is itself larger than 65,535 bytes.

`plan_send_with_payload()` performs payload-aware mass/fee estimation before final UTXO selection and then validates the resulting plan's actual output-script lengths and payload size before encoding.

## Testing

```text
src/**/unit-tests/       focused module-level invariants
qa/tests/conformance/    standards/Kaspa test vectors
qa/tests/integration/    cross-domain behavior
qa/tests/security/       security invariants/attack cases
qa/tests/regression/     fixed-vulnerability/bug regressions
qa/tests/property/       generative/property checks
qa/tests/randomness/     beacon/VRF/statistical checks
qa/tests/browser/        WASM/IndexedDB/BigInt/browser lifecycle
qa/tests/fuzz/           cargo-fuzz harness and targets
qa/benches/              criterion benchmarks
```

The filesystem directory is literally `unit-tests`; Rust parents attach it using `#[path = "unit-tests/..."]`.

## Indexer consistency

The indexer is bounded by `IndexerConfig`. Multi-transaction block ingestion, sync application and virtual-chain reconciliation operate on a cloned staging engine and replace live state only after the complete operation succeeds. Persisted state is versioned and contains snapshot data, matcher configuration and a sync checkpoint. Reorg reconciliation removes orphaned retained blocks/transactions/matches before accepted-chain batches are applied.

## Randomness separation

The public beacon/extractor and RFC 9381 VRF are separate subsystems.

- Beacon: finalized Kaspa hashes + optional CURBy public evidence -> deterministic extractor -> proof containing the complete public evidence/configuration.
- VRF: independent Edwards25519 VRF secret/public key -> RFC 9381 proof and output.

Kaspa spending keys are not VRF keys. Public beacon output is not secret entropy.

## Browser boundary

`platform/browser` contains only adapters/bindings: WebSocket/fetch, IndexedDB, BigInt/decimal conversion, time/entropy adapters and WASM facade wrappers. Consensus and security algorithms remain in target-independent Rust domains.

## Exact integers

Consensus-sized JSON fields (amount, DAA score, sequence, lock time, gas and related optional exact fields) use canonical unsigned decimal strings. Browser APIs use BigInt-compatible conversion instead of JavaScript `Number` arithmetic.
