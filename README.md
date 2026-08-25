# kaspa-portal

`kaspa-portal` 1.0.0 is a capability-oriented Rust SDK for connecting to and interacting with Kaspa from native Rust and WebAssembly. It exposes one small `KaspaPortal` facade while keeping specialized protocol, cryptographic, transaction, contract, indexing, privacy, and randomness APIs directly accessible.

## Design

The public domains are:

- `network` — node transport, RPC/wRPC, retry and health.
- `chain` — block, DAG, UTXO and fee queries.
- `wallet` — addresses, KPUB/xpub import, derivation, balances and mnemonic utilities.
- `transaction` — planning, PSKT/PSKB/KSPT, review, signing, finalization and broadcast.
- `contract` — scripts, covenants, vaults, oracle/commit-reveal and related contract families.
- `privacy` — stealth-payment functionality.
- `indexer` — bounded lightweight local index/scanner with checkpoints and reorg reconciliation.
- `randomness` — a public Kaspa+CURBy beacon/extractor and a separate RFC 9381 ECVRF.
- `crypto` / `primitives` — reusable low-level functionality.
- `platform` — native and browser adapters only.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for dependency rules and internal layout.

For the developer-facing method reference, including parameters and return values for the Rust facades and browser/WASM classes, see [docs/PUBLIC_API.md](docs/PUBLIC_API.md) | [docs/E2E_CAPABILITIES.md](docs/E2E_CAPABILITIES.md).

## Rust quick start

```toml
[dependencies]
kaspa-portal = "1.0.0"
```

Build an offline portal when no node connection is needed:

```rust
use kaspa_portal::{KaspaPortal, primitives::NetworkId};

let portal = KaspaPortal::builder()
    .network(NetworkId::Mainnet)
    .build()?;

let mnemonic = portal.wallet().mnemonic_12_from_entropy(&[0x42; 16]);
let vrf = portal.randomness().vrf();
let (secret, public) = vrf.generate_keypair()?;
let result = vrf.prove(&secret, b"example-domain")?;
assert_eq!(vrf.verify(&public, b"example-domain", &result.proof)?, result.output);
# Ok::<(), kaspa_portal::Error>(())
```

Configure a node when using network-backed operations:

```rust
use kaspa_portal::{KaspaPortal, primitives::NetworkId};

# async fn example() -> kaspa_portal::Result<()> {
let portal = KaspaPortal::builder()
    .network(NetworkId::Mainnet)
    .endpoint("wss://node.example/ws")
    .connect()
    .await?;

let health = portal.network()?.health().await?;
let daa_score = portal.chain()?.virtual_daa_score().await?;
println!("{health:?} {daa_score}");
# Ok(())
# }
```

The facade is intentionally thin. Advanced callers can import focused APIs directly, for example `kaspa_portal::transaction::interchange::pskt`, `kaspa_portal::contract`, `kaspa_portal::crypto`, or `kaspa_portal::randomness`.

## Transaction safety

Consensus-sized integers such as sompi amounts, DAA scores, sequences, lock times and gas are represented canonically as unsigned decimal strings at JSON/WASM boundaries. JavaScript `Number` is not used for consensus monetary/DAA arithmetic. Browser callers should use `BigInt` locally and decimal strings when serializing JSON.

PSKT/PSKB/KSPT parsing is bounded and fuzz-targeted.

## Lightweight indexer

The indexer is independent of browser storage:

```rust
use kaspa_portal::KaspaPortal;
use kaspa_portal::indexer::event::IndexedTransaction;

let portal = KaspaPortal::builder().build()?;
let indexer = portal.indexer();
indexer.start()?;
indexer.watch_address("kaspa:example")?;

indexer.ingest_transaction(IndexedTransaction {
    txid: "abc".into(),
    block_hash: None,
    daa_score: Some(100),
    observed_at_ms: 1,
    addresses: vec!["kaspa:example".into()],
    payload: Vec::new(),
    raw: serde_json::Value::Null,
})?;

let events = indexer.drain_events()?;
# Ok::<(), kaspa_portal::Error>(())
```

Core persistence is defined through `IndexerPersistence`. Browser IndexedDB is one platform implementation. Persisted state is versioned and includes bounded indexed state, matcher configuration and sync checkpoints. Batch ingestion and virtual-chain reconciliation are staged atomically before replacing live state.

## Randomness: two different tools

### Public beacon/extractor

`portal.randomness().beacon()` combines **public finalized Kaspa block hashes** with optional CURBy evidence through a deterministic domain-separated extractor. CURBy refresh attempts are globally rate-limited per client to at most once per minute.

This is public randomness. It must **not** be treated as secret entropy for wallet keys or passwords. Raw CURBy HTTPS API responses are explicitly marked as not independently source-verified unless the application supplies externally verified evidence.

### Genuine VRF

`portal.randomness().vrf()` implements the RFC 9381 `ECVRF-EDWARDS25519-SHA512-ELL2` ciphersuite. VRF keys are separate from Kaspa spending keys. The QA conformance suite contains all three official RFC 9381 Appendix B.4 ELL2 vectors.

## Browser / WASM

The WASM build uses this crate's Rust implementation; it does not introduce another Kaspa SDK.

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli
cargo build --release --target wasm32-unknown-unknown --features wasm
wasm-bindgen --target web --out-dir pkg --out-name kaspa_portal target/wasm32-unknown-unknown/release/kaspa_portal.wasm
```

Browser construction accepts a JSON string so exact integer configuration stays under caller control:

```javascript
import init, { KaspaPortal } from "./pkg/kaspa_portal.js";

await init();

const portal = new KaspaPortal(JSON.stringify({
  network: "mainnet",
  endpoint: "wss://node.example/ws",
  timeoutMs: "15000",
  maxRetries: 3
}));

const wallet = portal.wallet();
const indexer = portal.indexer();
const randomness = portal.randomness();
```

IndexedDB persistence stores dehydrated/versioned plain data only, never Rust/WASM pointer objects. See `examples/browser/index.html` for a minimal loader.

## Features

- Default: native/core SDK without secret-export helpers.
- `wasm`: browser/WASM bindings and IndexedDB/WebSocket/fetch adapters.
- `secret-export`: explicitly enables raw VRF secret export helpers. Do not enable it unless an application genuinely needs them.

## QA

Unit tests live next to important modules in literal `unit-tests/` directories. Cross-domain QA is under `qa/tests/`; fuzzing is under `qa/tests/fuzz/`; benchmarks are under `qa/benches/`.

For a normal local release QA run, use the only two repository-root scripts:

Linux:

```bash
./run-all-linux.sh
```

Windows (double-click it, or run it from Command Prompt/Terminal):

```cmd
run-all-windows.cmd
```

All other user-facing launchers live under `scripts/`. Internal QA implementation scripts remain under `qa/scripts/`.

`run-all` is the authoritative full gate. It runs the static/project checks, Rust compile/tests/doc tests, Clippy with warnings denied, benchmark/fuzz compile checks, WASM compile check, **all Rust functional E2E scenarios**, **all real-browser/WASM E2E scenarios**, and the bounded **quick resource/leak/CPU/fault-injection E2E profile**. The separate soak launcher repeats the same resource scenarios for much longer; it is an extended stress run rather than a distinct functional-capability suite.

Late-stage failures can resume without repeating gates that already passed. Use the closest stage:

```cmd
run-all-windows.cmd --from-wasm
run-all-windows.cmd --from-formatting
run-all-windows.cmd --from-rust-e2e
run-all-windows.cmd --from-live-e2e
run-all-windows.cmd --from-browser-e2e
run-all-windows.cmd --from-resources-e2e
```

```sh
./run-all-linux.sh --from-wasm
./run-all-linux.sh --from-formatting
./run-all-linux.sh --from-rust-e2e
./run-all-linux.sh --from-live-e2e
./run-all-linux.sh --from-browser-e2e
./run-all-linux.sh --from-resources-e2e
```

`--from-wasm` starts at the WASM target compile, `--from-formatting` starts at rustfmt, `--from-rust-e2e` starts immediately before the Rust E2E suites, and `--from-live-e2e` skips the already-passed offline Rust E2E suite and resumes at the configured public standard-network workflows. `--from-browser-e2e` and `--from-resources-e2e` resume at the browser/WASM and resource/fault gates. Each resume continues through all later gates.

### E2E network selection

QA deliberately separates the network used for ordinary functionality from the network used for covenant functionality:

- **standard / non-covenant:** `testnet-10` by default;
- **covenant:** `testnet-12` by default, because covenant validation is kept on the covenant-capable test network independently of ordinary SDK coverage.

The single editable source of defaults, public resolver/fallback endpoints, REST endpoints, faucets, and genesis hashes is [`qa/e2e/networks.toml`](qa/e2e/networks.toml). Change `defaults.standard_network` or `defaults.covenant_network` there when Kaspa moves either validation role to another network. The SDK network parser accepts future names such as `testnet-14` (suffixes 1 through 127), so moving to a future testnet does not require adding another `NetworkId` enum variant.

At the first E2E stage of an interactive run, the ordinary network is selected with:

```text
Kaspa E2E ordinary/non-covenant network:
  1. testnet-10 (recommended/default)
  2. testnet-12
  3. mainnet (read-only unless mainnet spending is explicitly enabled)
  4. custom
Which would you like to use? [1]
```

`Custom` accepts values such as `testnet-14`; if that network is not already present in `qa/e2e/networks.toml`, the runner asks for its wRPC endpoint, genesis hash, and optional faucet. Pressing Enter chooses the configured `defaults.standard_network`, so changing that one config value also changes the interactive default. Covenant tests do not follow this ordinary-network choice: they use `defaults.covenant_network` (TN12 today), or `KASPA_PORTAL_E2E_COVENANT_NETWORK` when explicitly overridden.

For automation, set `KASPA_PORTAL_E2E_NO_NETWORK_PROMPT=1`. Role-specific overrides are `KASPA_PORTAL_E2E_STANDARD_NETWORK`, `KASPA_PORTAL_E2E_STANDARD_ENDPOINT`, `KASPA_PORTAL_E2E_STANDARD_REST_ENDPOINT`, `KASPA_PORTAL_E2E_STANDARD_GENESIS_HASH`, `KASPA_PORTAL_E2E_STANDARD_FAUCET` and the corresponding `KASPA_PORTAL_E2E_COVENANT_*` variables. The legacy `KASPA_PORTAL_E2E_ENDPOINT` remains a standard-network endpoint alias. Known profiles resolve a current public wRPC node at run start and retain a direct fallback; funded-wallet verification uses the selected network's REST balance API first, with wRPC as a fallback.

### Funded E2E wallets

Funded ordinary and covenant scenarios are checked independently. The same dedicated XPRV is reused across network roles, but it must have test KAS on each selected testnet whose spending tests are enabled. The local secret is stored only in the Git-ignored `.kaspa-portal-e2e/wallet.env`; the XPRV is never printed. A legacy `.kaspa-portal-e2e/testnet12-wallet.env` is migrated automatically.

For each funded network role the runner prints the derived address and configured faucet, then asks `Y/N`. `Y` checks that network immediately; if the balance is below 10 KAS, the current balance is reported and the same prompt repeats. `N` skips only that role's funded scenarios and continues the rest of QA. Thus, for the defaults, declining TN10 funded tests does not suppress TN12 covenant-funded tests, and vice versa. Mainnet spending is disabled by default even when mainnet is selected for ordinary read-only validation; enabling real-mainnet spending requires the explicit `KASPA_PORTAL_E2E_ALLOW_MAINNET_SPEND=1` safety override.

Advanced users may still provide `KASPA_PORTAL_E2E_XPRV` explicitly. An explicitly supplied secret is used in memory and is not written to the local state file.

Individual runners are available when diagnosing a particular layer:

```bash
scripts/run-e2e-rust-linux.sh
scripts/run-e2e-browser-linux.sh
scripts/run-e2e-resources-linux.sh
scripts/run-e2e-soak-linux.sh
```

```cmd
scripts\run-e2e-rust-windows.cmd
scripts\run-e2e-browser-windows.cmd
scripts\run-e2e-resources-windows.cmd
scripts\run-e2e-soak-windows.cmd
```

The Rust and browser runners support `--read-only` for diagnostics when funded transaction execution is intentionally unavailable. Read-only mode is not a complete release E2E pass. Browser E2E requires `wasm-pack`, Node.js/npm, and Playwright browser dependencies. Generated WASM/npm artifacts are kept outside the repository.

See [docs/E2E_CAPABILITIES.md](docs/E2E_CAPABILITIES.md) for the capability map and E2E policy.

## Security

Read [docs/SECURITY.md](docs/SECURITY.md) before using wallet secrets, signing, browser persistence, the randomness beacon, or the VRF in production.
