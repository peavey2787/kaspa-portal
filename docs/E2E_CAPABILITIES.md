# E2E Capability Inventory

Kaspa Portal keeps a machine-readable inventory of the public developer-facing SDK surface at [`../qa/e2e/capabilities.toml`](../qa/e2e/capabilities.toml). The inventory is the contract used by QA to prevent Rust/WebAssembly functionality drift and, in later E2E passes, to prove that every capability has an executed scenario.

## Live-network rule

Real-world E2E is role-based. Ordinary/non-covenant functionality uses the **standard network** (`testnet-10` by default), while covenant functionality uses the independently configured **covenant network** (`testnet-12` by default). The defaults and known network profiles live in [`../qa/e2e/networks.toml`](../qa/e2e/networks.toml). A simulated transport is reserved for conditions that cannot be requested safely or deterministically from a public node, such as malformed, duplicated, mismatched, or deliberately delayed RPC responses.

## Registry fields

Each `[[capability]]` entry records:

- `id`: stable capability identifier.
- `domain`: SDK domain such as `chain`, `transaction`, `contract`, or `indexer`.
- `rust_symbol`: the Rust developer-facing method that implements the capability.
- `wasm_symbols`: one or more browser/WASM methods that provide the same functionality. Multiple browser entry points are allowed where the browser adds a safe convenience wrapper.
- `execution`: the E2E environment: `offline`, `public_standard`, `funded_standard`, `funded_covenant`, `browser_storage`, or `simulated_fault`.
- `funds_required`: whether the selected standard/covenant network scenario must spend dedicated test funds.
- `resource_profile`: the memory/CPU/resource-monitoring profile that later E2E passes must apply.
- `rust_e2e`: the Rust E2E scenario that exercises the capability when it is Rust-testable.
- `wasm_e2e`: the real-browser Playwright scenario that exercises the capability.
- `e2e_status`: `covered` only when the capability is bound to the required Rust and browser scenarios for the completed E2E passes.

## Parity gate

`qa/scripts/check_capability_parity.py` scans the tracked public Rust facade methods and browser/WASM methods and fails when:

- a tracked Rust method is not registered;
- a tracked WASM method is not registered;
- a registry entry points at a method that no longer exists;
- a capability lacks a WASM mapping;
- a new API method is added without updating the inventory;
- the standard/covenant execution-role policy becomes inconsistent with the configured defaults; or
- required planning metadata is missing or invalid.

The only current Rust exclusions are low-level platform transport constructors that create `NetworkClient` from an injected Rust `Transport`. They are platform plumbing rather than high-level SDK facade operations; the callable low-level client operation itself is inventoried and has a WASM counterpart.

## Pass 1 baseline

The repository-root `run-all` launchers execute all functional E2E layers described below plus the quick Pass 4 resource/fault profile. The soak profile is an optional longer repetition of those same resource scenarios.

Pass 1 inventories the full high-level public capability surface and establishes the parity gate. The registry must remain complete during later passes, so a newly introduced public capability cannot silently escape E2E planning.

## Pass 2 Rust E2E

Pass 2 maps every Rust-testable capability to an actual Rust E2E test function. `qa/scripts/check_rust_e2e_coverage.py` fails if a non-browser capability is unmapped, maps to a test function that does not exist, or if an unregistered Rust E2E scenario appears in the E2E tree. The three IndexedDB-only persistence operations remain deliberately deferred to the real-browser pass.

The Rust suite has three layers:

- Offline facade workflows exercise deterministic wallet, transaction/PSKB, contract, privacy, indexer, randomness, portal, and configuration behavior through public APIs.
- Public standard-network read workflows (TN10 by default) connect to a real public node and exercise connection lifecycle, raw RPC, DAA/block/UTXO/fee queries, wallet discovery, HD45 branch scanning, and live beacon generation from chain evidence.
- Funded standard-network workflows use a dedicated XPRV and real UTXOs for ordinary planning, signing, exact mass/fee analysis, finalization/broadcast, consolidation, and HD45 multisig coverage. Funded covenant-network workflows are separate and exercise ordinary/bound covenant deposit planning on the covenant network (TN12 by default).

Run the complete Rust E2E suite with:

```bash
scripts/run-e2e-rust-linux.sh
```

On Windows Command Prompt:

```cmd
scripts\run-e2e-rust-windows.cmd
```

`--read-only` is available for diagnostics when funded wallets are unavailable, but it explicitly does not represent a complete Rust E2E pass. Interactive runs prompt for the ordinary network: `1. testnet-10`, `2. testnet-12`, `3. mainnet`, or `4. custom`. Pressing Enter uses `defaults.standard_network` from `qa/e2e/networks.toml`; custom accepts future values such as `testnet-14`. The covenant role remains independently pinned by `defaults.covenant_network` (TN12 today).

If no XPRV is supplied, the runner creates one dedicated local wallet and stores its secret only in the Git-ignored `.kaspa-portal-e2e/wallet.env`. The same XPRV is reused across network roles, while each role derives/checks its address and balance on its own network. Standard and covenant funding each get an independent `Y/N` loop: `Y` checks the selected network immediately and repeats if the balance is below 10 KAS; `N` skips only that role's funded scenarios. Mainnet spending is disabled unless `KASPA_PORTAL_E2E_ALLOW_MAINNET_SPEND=1` is explicitly set. Secrets are never written to fixtures or the capability registry.

Known resolver/fallback wRPC endpoints, REST endpoints, faucets, genesis hashes, and defaults are centralized in `qa/e2e/networks.toml`. Known public profiles resolve a current wRPC node at run start and retain a direct fallback; funded-wallet balance verification uses REST first and falls back to wRPC. Automation can set `KASPA_PORTAL_E2E_NO_NETWORK_PROMPT=1`; role-specific overrides use `KASPA_PORTAL_E2E_STANDARD_*` and `KASPA_PORTAL_E2E_COVENANT_*`. `KASPA_PORTAL_E2E_ENDPOINT` remains a compatibility alias for the standard endpoint.

Pass 2 establishes the Rust execution half of the capability contract.

## Pass 3 browser/WASM E2E and differential parity

Pass 3 builds the actual WebAssembly package with `wasm-pack --target web` and executes it in real browsers through Playwright. `qa/scripts/check_wasm_e2e_coverage.py` makes the browser side machine-enforceable: every one of the 155 registered public capabilities must map to an exported `wasm_*` scenario function, and that scenario must invoke the registered browser/WASM method.

The browser suite has the same real-network policy as Rust:

- Offline differential scenarios compare deterministic wallet, transaction/PSKB, contract, privacy, indexer, beacon, and VRF outputs against a canonical fixture generated by the Rust public API.
- Public standard-network scenarios exercise browser WebSocket behavior, connection lifecycle, chain queries, wallet discovery, HD45 branch scanning, and live beacon generation against the selected ordinary network.
- Funded browser scenarios are split just like Rust: ordinary spend/broadcast workflows use the funded standard network, while covenant planning uses the independently funded covenant network. Browser transaction planning, payload mutation, mass/fee analysis, finalization, compact-KSPT signing, and entropy-controlled signing are exercised independently through WASM and compared against Rust where deterministic.
- IndexedDB persistence is tested in an actual browser lifecycle: ingest state, save to IndexedDB, reload the page and WASM instance, restore and verify state, clear IndexedDB, reload again, and prove the persisted state is gone.

Chromium runs the full offline/live/funded suite. Firefox and WebKit additionally run cross-browser integer/byte semantics and IndexedDB reload/clear coverage. The QA WASM build enables `secret-export` only so the fixed VRF secret fixture can be differentially compared; this does not change the default production feature policy.

Run the complete browser suite on Linux with:

```bash
scripts/run-e2e-browser-linux.sh
```

On Windows Command Prompt:

```cmd
scripts\run-e2e-browser-windows.cmd
```

The runner requires Cargo/rustup, `wasm-pack`, Node.js/npm, and Playwright browser dependencies. It builds the WASM package and installs npm dependencies into an OS temporary directory, so a browser E2E run does not leave `node_modules`, package-lock files, or generated WASM artifacts in the repository. By default it installs the pinned Chromium, Firefox, and WebKit browser builds; set `KASPA_PORTAL_E2E_SKIP_BROWSER_INSTALL=1` only when those Playwright browsers are already installed.

`--read-only` remains a diagnostic mode: it executes offline, IndexedDB, and non-spending public standard-network browser scenarios but explicitly omits both funded network roles and cannot represent a complete browser E2E pass.

After Pass 3, all 155 registered capabilities have executable WASM E2E mappings. Resource/leak/CPU budgets and fault-injection profiles remain Pass 4 work; a green Pass 3 result therefore proves browser execution/parity coverage, not yet resource-soak readiness.

## Pass 4 resource, leak, CPU, and fault-injection E2E

Pass 4 assigns every registered capability to one of five machine-enforced lifecycle resource profiles: `standard`, `network`, `indexer`, `crypto`, or `browser_storage`, and adds a sixth supplemental `fault` profile for repeated failure/recovery paths. The budgets and iteration counts live in [`../qa/resource/profiles.toml`](../qa/resource/profiles.toml), and `qa/scripts/check_resource_coverage.py` fails if any public capability points at an unknown profile or a profile lacks its concrete native/browser scenario.

The native resource harness builds a dedicated `resource_probe` executable into an OS temporary Cargo target and monitors that process directly. It uses only Python's standard library and supports Windows and Linux. Measurements include resident working-set/RSS, retained-memory slope across post-warmup batches, thread growth, Windows handle or Linux file-descriptor growth, and CPU consumed during an explicit idle period after the workload has stopped. The quick gate uses short bounded batches; the soak gate repeats the same lifecycle for substantially longer and applies the same plateau/slope budgets.

The browser resource harness runs the real `wasm-pack --target web` package in Chromium under Playwright. Chrome DevTools Protocol is used to force test-only garbage collection between measurement batches and capture JS heap usage, backing-storage usage (including ArrayBuffer/WASM-associated backing storage reported by V8), DOM/document/listener counts, and `TaskDuration` during a three-second post-workload idle window. Browser resource scenarios repeatedly construct/use/free the facade graph, indexer, VRF/stealth cryptography, public standard-network lifecycle, and IndexedDB save/load/clear lifecycle.

Resource testing does not replace the functional coverage from Passes 2 and 3. The capability registry proves that every public method is functionally exercised; the resource profile proves that every capability belongs to a lifecycle class with bounded resource behavior. High-risk stateful classes are then stressed directly by their profile workload.

Pass 4 also adds actual-WebSocket fault injection. A QA-only local WebSocket server accepts normal Kaspa Portal wRPC requests and deliberately returns delayed valid responses, duplicate responses, malformed framing, mismatched request IDs, mismatched operations, remote errors, premature connection closes, and unexpected text frames. Native Rust tests exercise `NativeWebSocketTransport` against that server, and the Playwright browser suite launches the same QA server binary and exercises `BrowserWebSocketTransport`. The supplemental fault resource profile repeatedly executes those failures followed by successful recovery while native RSS/CPU/thread/handle-or-FD and Chromium heap/backing-store/DOM/idle-CPU budgets are measured. The selected public standard network is used for ordinary network lifecycle/resource testing; only faults that cannot be safely induced on a public node are simulated.

Native and browser transports now fail closed consistently on unexpected text application frames. Ping/pong control traffic remains transport-level WebSocket behavior rather than an application response.

Run the quick Pass 4 gate on Linux with:

```bash
scripts/run-e2e-resources-linux.sh
```

On Windows Command Prompt:

```cmd
scripts\run-e2e-resources-windows.cmd
```

Run the longer soak gate on Linux with:

```bash
scripts/run-e2e-soak-linux.sh
```

or on Windows:

```cmd
scripts\run-e2e-soak-windows.cmd
```

Set `KASPA_PORTAL_E2E_STANDARD_ENDPOINT` (or legacy `KASPA_PORTAL_E2E_ENDPOINT`) to override the dynamically resolved public standard-network wRPC endpoint. The Pass 4 network resource scenario is intentionally live and has no mock fallback. The local fault server is used only for malformed/delayed/duplicate/mismatched conditions that cannot be requested from the public endpoint.

A Pass 4 success therefore means the resource-profile registry is complete, native and WASM lifecycle probes stayed inside their configured memory/CPU/resource budgets, the selected public standard-network connection lifecycle remained healthy under repetition, and both WebSocket implementations survived the fault matrix and recovered afterward. It does not substitute for external sanitizer tooling; AddressSanitizer/LeakSanitizer and Miri remain useful additional release/nightly layers when available.
