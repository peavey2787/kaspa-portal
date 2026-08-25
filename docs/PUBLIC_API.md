# Public Developer API

This reference lists the high-level developer-facing API surface exposed by the Rust facades and the browser/WebAssembly bindings. Parameters are shown using their source-level types. `Result<T>` means `kaspa_portal::Result<T>` unless another result type is shown.

## Rust entry point

### `KaspaPortalBuilder`

| Method | Parameters | Returns |
| --- | --- | --- |
| `network` | `network: NetworkId` | `KaspaPortalBuilder` |
| `endpoint` | `endpoint: impl Into<String>` | `KaspaPortalBuilder` |
| `timeout_ms` | `value: u64` | `KaspaPortalBuilder` |
| `max_retries` | `value: u8` | `KaspaPortalBuilder` |
| `indexer` | `value: IndexerConfig` | `KaspaPortalBuilder` |
| `build` | none | `Result<KaspaPortal>` |
| `connect` | none | `async Result<KaspaPortal>` |

### `NetworkId`

`NetworkId` supports `Mainnet`, `Simnet`, `Devnet`, and `Testnet(u8)`. The compatibility constants `NetworkId::Testnet10`, `NetworkId::Testnet11`, and `NetworkId::Testnet12` remain available. `NetworkId::parse()` accepts `testnet-N`/`testnetN` suffixes 1 through 127, so a future network such as `testnet-14` can be selected without adding a new enum variant. `canonical_name()` returns the hyphenated user-facing name and `address_prefix()` returns the matching Kaspa address prefix.

### `KaspaPortal`

| Method | Parameters | Returns |
| --- | --- | --- |
| `builder` | none | `KaspaPortalBuilder` |
| `config` | none | `&PortalConfig` |
| `network` | none | `Result<&NetworkApi>` |
| `chain` | none | `Result<&ChainApi>` |
| `wallet` | none | `&WalletApi` |
| `transaction` | none | `&TransactionApi` |
| `contract` | none | `&ContractApi` |
| `privacy` | none | `&PrivacyApi` |
| `indexer` | none | `&IndexerApi` |
| `randomness` | none | `&RandomnessApi` |
| `connect` | none | `async Result<NetworkHealth>` |
| `disconnect` | none | `Result<()>` |

### `PortalConfig`

Public fields:

- `network: NetworkId`
- `endpoint: Option<String>`
- `timeout_ms: u64`
- `max_retries: u8`
- `indexer: IndexerConfig`

`validate(&self)` returns `Result<(), String>`.

## Network API

### `NetworkApi`

| Method | Parameters | Returns |
| --- | --- | --- |
| `network_id` | none | `NetworkId` |
| `endpoint` | none | `&str` |
| `client` | none | `NetworkClient` |
| `status` | none | `ConnectionStatus` |
| `connect` | none | `async Result<NetworkHealth>` |
| `disconnect` | none | `()` |
| `reconnect` | none | `async Result<NetworkHealth>` |
| `health` | none | `async Result<NetworkHealth>` |

## Chain API

### `ChainApi`

| Method | Parameters | Returns |
| --- | --- | --- |
| `virtual_daa_score` | none | `async Result<DaaScore>` |
| `block_raw` | `hash: &BlockHash` | `async Result<Vec<u8>>` |
| `utxos` | `address: &str` | `async Result<Vec<UtxoEntry>>` |
| `utxos_many` | `addresses: &[String]` | `async Result<Vec<UtxoEntry>>` |
| `transaction` | `txid: &str` | `Result<Option<ChainTransaction>>` |
| `transaction_raw` | `txid: &str` | `Result<Option<serde_json::Value>>` |
| `fee_estimate` | none | `async Result<FeeEstimate>` |

## Wallet API

### `WalletApi`

| Method | Parameters | Returns |
| --- | --- | --- |
| `import_kpub` | `kpub: &str` | `Result<WalletData>` |
| `import_kpub_raw` | `payload: &[u8]` | `Result<WalletData>` |
| `extend_addresses` | `wallet: &WalletData`, `receive: u32`, `change: u32` | `Result<WalletData>` |
| `utxos` | `wallet: &WalletData` | `async Result<Vec<UtxoEntry>>` |
| `balance` | `wallet: &WalletData` | `async Result<BalanceInfo>` |
| `mnemonic_12_from_entropy` | `entropy: &[u8; 16]` | `Mnemonic12` |
| `mnemonic_24_from_entropy` | `entropy: &[u8; 32]` | `Mnemonic24` |
| `prefix` | none | `&str` |

## Transaction API

### `TransactionApi`

| Method | Parameters | Returns |
| --- | --- | --- |
| `pskb` | none | `PskbApi` |
| `plan_send` | `wallet: &WalletData`, `destination: &str`, `amount: u64`, `fee: u64` | `async Result<String>` |
| `plan_send_with_payload` | `wallet: &WalletData`, `destination: &str`, `amount: u64`, `fee: u64`, `payload: &[u8]` | `async Result<String>` |
| `plan_selected_send` | `wallet: &WalletData`, `destination: &str`, `amount: u64`, `fee: u64`, `indices: &[usize]` | `async Result<String>` |
| `plan_consolidation` | `wallet: &WalletData`, `fee: u64` | `async Result<String>` |
| `scan_multisig_branch` | `descriptor_text: &str`, `cosigner: u32`, `depth: u32`, `prefix: &str` | `async Result<String>` |
| `plan_multisig_consolidation` | `request: MultisigConsolidationRequest<'_>` | `async Result<String>` |
| `plan_covenant` | `request: CovenantBuildRequest<'_>` | `async Result<String>` |
| `plan_covenant_with_binding` | `request: CovenantBuildRequest<'_>` | `async Result<(String, Option<[u8; 32]>)>` |
| `plan_from_utxos` | `wallet: &WalletData`, `destination: &str`, `amount: u64`, `fee: u64`, `utxos: Vec<UtxoEntry>` | `Result<String>` |
| `set_payload` | `wire_hex: &str`, `payload: &[u8]` | `Result<String>` |
| `set_tx_lane` | `wire_hex: &str`, `subnetwork_id_hex: &str`, `gas: u64`, `transaction_version: u16`, `payload: &[u8]` | `Result<String>` |
| `analyze` | `wire_hex: &str` | `async Result<TransactionAnalysis>` |
| `analyze_with_fee_rate` | `wire_hex: &str`, `recommended_fee_rate_sompi_per_gram: u64` | `Result<TransactionAnalysis>` |

`analyze` and `analyze_with_fee_rate` operate on a signed/finalizable PSKB because exact serialized mass depends on the completed input signature scripts. Use the planner fee estimates while a transaction is still unsigned.
| `review` | `wire_hex: &str`, `network_prefix: &str` | `Result<PsktSummary>` |
| `finalize` | `wire_hex: &str` | `Result<ConsensusTransaction>` |
| `sign_compact_kspt` | `wire: &[u8]`, `private_key: &[u8; 32]`, `sighash_type: SigHashType` | `Result<SignedResponse>` |
| `sign_compact_kspt_with_entropy` | `wire: &[u8]`, `private_key: &[u8; 32]`, `sighash_type: SigHashType`, `signing_entropy: &[u8; 32]` | `Result<SignedResponse>` |
| `apply_sequence_commit_proof` | `wire_hex: &str`, `proof: &SequenceCommitProof` | `Result<String>` |
| `broadcast` | `transaction: &ConsensusTransaction` | `async Result<String>` |

### Transaction request objects

`MultisigConsolidationRequest` fields:

- `descriptor_text: &str`
- `sources_json: &str`
- `destination_address: &str`
- `amount: u64`
- `fee: u64`
- `cosigner: u32`
- `change_index_hint: u32`

`CovenantBuildRequest` fields:

- `wallet: &WalletData`
- `covenant_address: &str`
- `send_amount: u64`
- `fee: u64`
- `change_address: &str`
- `utxo_indices_csv: &str`
- `encoding: CovenantEncoding`

`CovenantEncoding` variants:

- `Payload { payload_hex: &str, tag_genesis: bool }`
- `BoundGenesis`

### `PskbApi`

| Method | Parameters | Returns |
| --- | --- | --- |
| `encode` | `plan: &PskbPlan` | `Result<String>` |
| `encode_document` | `document: serde_json::Value` | `Result<String>` |
| `plan_sweep` | `utxos: &[UtxoEntry]`, `source_script_public_key: &[u8]`, `destination_script_public_key: &[u8]`, `send_amount: u64`, `global: PskbGlobalPlan`, `input_policy: &SweepInputPolicy` | `PskbPlan` |
| `plan_global_thread_withdrawal` | `request: GlobalThreadWithdrawalRequest<'_>` | `Result<GlobalThreadWithdrawalPlan>` |
| `plan_global_thread_topup` | `request: GlobalThreadTopupRequest<'_>` | `Result<GlobalThreadTopupPlan>` |

`PskbGlobalPlan` fields:

- `tx_version: u16`
- `fallback_lock_time: Option<u64>`
- `covenant_branch: Option<serde_json::Value>`
- `proprietaries: serde_json::Value`
- `transaction_payload: Option<Vec<u8>>`

`SweepInputPolicy` fields:

- `sequence: u64`
- `sig_op_count: u8`
- `minimum_signatures: u8`
- `redeem_script: Option<Vec<u8>>`
- `proprietaries: serde_json::Value`
- `min_time: Option<u64>`

`GlobalThreadWithdrawalRequest` fields:

- `thread_utxos: &[UtxoEntry]`
- `covenant_script_public_key: &[u8]`
- `destination_script_public_key: &[u8]`
- `redeem_script: &[u8]`
- `covenant_id: &[u8; 32]`
- `withdrawal: u64`
- `fee: u64`
- `csv_sequence: u64`
- `policy: &GlobalThreadPolicy`

`GlobalThreadTopupRequest` fields:

- `thread_utxo: UtxoEntry`
- `wallet_utxos: &[UtxoEntry]`
- `covenant_script_public_key: &[u8]`
- `redeem_script: &[u8]`
- `covenant_id: &[u8; 32]`
- `fee: u64`
- `policy: &GlobalThreadPolicy`

## Contract API

### `ContractApi`

| Method | Parameters | Returns |
| --- | --- | --- |
| `script` | none | `ScriptApi` |
| `covenant` | none | `CovenantApi` |
| `commit_reveal` | none | `CommitRevealApi` |
| `crowdfund` | none | `CrowdfundApi` |
| `merkle` | none | `MerkleApi` |
| `oracle` | none | `OracleApi` |
| `sequence_commit` | none | `SequenceCommitApi` |
| `shipping_escrow` | none | `ShippingEscrowApi` |
| `vault` | none | `VaultApi` |
| `zk` | none | `ZkApi` |

### `ScriptApi`

| Method | Parameters | Returns |
| --- | --- | --- |
| `p2sh_address` | `redeem_script: &[u8]`, `prefix: &str` | `Result<String>` |
| `cltv_locktime` | `script_bytes: &[u8]` | `Result<Option<u64>>` |
| `csv_sequence` | `script_bytes: &[u8]` | `Result<Option<u64>>` |

### `CovenantApi`

| Method | Parameters | Returns |
| --- | --- | --- |
| `dms` | `owner: &[u8; 32]`, `heir: &[u8; 32]`, `inactivity_daa: u64` | `Vec<u8>` |
| `private_swap` | `owner: &[u8; 32]`, `claimer: &[u8; 32]`, `claimer_spk: &[u8]`, `refund_daa: u64`, `salt: &[u8; 16]` | `Result<Vec<u8>>` |
| `piggy_bank` | `owner: &[u8; 32]`, `threshold_sompi: u64`, `deadline_daa: u64`, `salt: &[u8; 8]` | `Vec<u8>` |
| `timelocked_savings` | `first: &[u8; 32]`, `second: &[u8; 32]`, `locktime_daa: u64` | `Vec<u8>` |
| `payjoin` | `owner: &[u8; 32]`, `beneficiary: &[u8; 32]`, `locktime_daa: u64`, `min_inputs: u64`, `min_outputs: u64` | `Vec<u8>` |

### Other contract facades

| API / method | Parameters | Returns |
| --- | --- | --- |
| `CommitRevealApi::build` | `owner: &[u8; 32]`, `commitment: &[u8; 32]`, `locktime_daa: u64` | `Vec<u8>` |
| `CrowdfundApi::campaign_id` | `goal_sompi: u64`, `locktime_daa: u64`, `verifying_key_hash: &[u8; 32]`, `organizer_spk: &[u8]` | `[u8; 32]` |
| `CrowdfundApi::redeem_script` | `request: CrowdfundScript<'_>` | `Result<Vec<u8>>` |
| `MerkleApi::root` | `leaves: &[Vec<u8>]` | `[u8; 32]` |
| `MerkleApi::proof` | `leaves: &[Vec<u8>]`, `leaf_index: usize` | `Vec<([u8; 32], u8)>` |
| `OracleApi::heartbeat_script` | none | `Vec<u8>` |
| `OracleApi::heartbeat_sig_script` | `redeem: &[u8]` | `Vec<u8>` |
| `OracleApi::consumer_sig_script` | `redeem: &[u8]` | `Vec<u8>` |
| `SequenceCommitApi::stealth_proof` | `ephemeral_public_key: &[u8; 32]`, `view_tag: u8` | `SequenceCommitProof` |
| `ShippingEscrowApi::build` | `request: ShippingEscrowScriptRequest<'_>` | `Result<Vec<u8>>` |
| `VaultApi::tagged` | `owner: &[u8; 32]` | `Vec<u8>` |
| `VaultApi::split` | `owner: &[u8; 32]` | `Vec<u8>` |
| `VaultApi::covenant_id` | `prev_txid: &[u8; 32]`, `prev_index: u32`, `outputs: &[(u32, u64, u16, &[u8])]` | `[u8; 32]` |
| `ZkApi::trusted_setup` | none | `Result<(Vec<u8>, Vec<u8>)>` |
| `ZkApi::prove_crowdfund` | `proving_key: &[u8]`, `amounts_sompi: &[u64]` | `Result<(Vec<u8>, Vec<u8>, u64)>` |
| `ZkApi::verify` | `verifying_key: &[u8]`, `proof: &[u8]`, `public_input: &[u8]` | `Result<bool>` |

`CrowdfundScript` fields:

- `contributor_pubkey: &[u8; 32]`
- `goal_sompi: u64`
- `locktime_daa: u64`
- `verifying_key_hash: &[u8; 32]`
- `organizer_output_spk: &[u8]`
- `salt: &[u8; 8]`

`ShippingEscrowScriptRequest` fields:

- `seller_pubkey: &[u8; 32]`
- `deliverer_pubkey: &[u8; 32]`
- `buyer_pubkey: &[u8; 32]`
- `arbiter_pubkey: &[u8; 32]`
- `product_sompi: u64`
- `fee_sompi: u64`
- `cltv1_deadline: u64`
- `cltv2_deadline: u64`
- `salt: &[u8; 8]`

## Privacy API

### `PrivacyApi`

| Method | Parameters | Returns |
| --- | --- | --- |
| `stealth` | none | `StealthApi` |

### `StealthApi`

| Method | Parameters | Returns |
| --- | --- | --- |
| `generate_payment` | `metadata: &StealthMeta`, `entropy: &[u8; 32]` | `Result<StealthPayment>` |
| `announcement_address` | `prefix: &str` | `String` |
| `decode_metadata` | `value: &str` | `Result<StealthMeta>` |
| `derive_metadata` | `kpub: &str` | `Result<StealthMeta>` |
| `encode_metadata` | `value: &StealthMeta` | `String` |
| `scan_raw_for_preimage` | `raw: &[u8]`, `transaction_id: &[u8]` | `Option<Vec<u8>>` |

## Indexer API

### `IndexerApi`

| Method | Parameters | Returns |
| --- | --- | --- |
| `with_clock` | `config: IndexerConfig`, `now_ms: fn() -> Result<u64, String>` | `Result<IndexerApi>` |
| `start` | none | `Result<()>` |
| `stop` | none | `Result<()>` |
| `watch_address` | `address: impl Into<String>` | `Result<u64>` matcher ID |
| `watch_payload_prefix` | `value: Vec<u8>` | `Result<u64>` matcher ID |
| `watch_payload_contains` | `value: Vec<u8>` | `Result<u64>` matcher ID |
| `watch_payload_exact` | `value: Vec<u8>` | `Result<u64>` matcher ID |
| `watch_payload_suffix` | `value: Vec<u8>` | `Result<u64>` matcher ID |
| `add_matcher` | `rule: MatchRule` | `Result<u64>` matcher ID |
| `remove_matcher` | `id: u64` | `Result<bool>` |
| `ingest_transaction` | `tx: IndexedTransaction` | `Result<Vec<IndexedMatch>>` |
| `ingest_block` | `block: IndexedBlock` | `Result<()>` |
| `ingest_block_batch` | `batch: BlockBatch` | `Result<BlockScanReport>` |
| `transaction` | `txid: &str` | `Result<Option<IndexedTransaction>>` |
| `transactions` | `query_value: TransactionQuery` | `Result<Page<IndexedTransaction>>` |
| `blocks` | `page: PageRequest` | `Result<Page<IndexedBlock>>` |
| `matches` | `page: PageRequest` | `Result<Page<IndexedMatch>>` |
| `metrics` | none | `Result<IndexerMetrics>` |
| `health` | none | `Result<IndexerHealth>` |
| `snapshot` | none | `Result<IndexerSnapshot>` |
| `restore_snapshot` | `snapshot: IndexerSnapshot` | `Result<()>` |
| `checkpoint` | none | `Result<SyncCheckpoint>` |
| `set_checkpoint` | `checkpoint: SyncCheckpoint` | `Result<()>` |
| `persisted_state` | none | `Result<PersistedIndexerState>` |
| `restore_state` | `state: PersistedIndexerState` | `Result<()>` |
| `save_to` | `persistence: &impl IndexerPersistence` | `async Result<()>` |
| `restore_from` | `persistence: &impl IndexerPersistence` | `async Result<bool>` |
| `clear_persisted` | `persistence: &impl IndexerPersistence` | `async Result<()>` |
| `apply_sync_batches` | `batches: Vec<BlockBatch>`, `checkpoint: SyncCheckpoint` | `Result<SyncReport>` |
| `reconcile_virtual_chain` | `delta: VirtualChainDelta` | `Result<ReconciliationReport>` |
| `drain_events` | none | `Result<Vec<IndexerEvent>>` |
| `clear` | none | `Result<()>` |

Common indexer request objects:

- `PageRequest { offset: usize, limit: usize }`
- `TransactionQuery { address: Option<String>, after_daa_score: Option<u64>, page: PageRequest }`
- `SyncCheckpoint { virtual_daa_score: Option<u64>, block_hash: Option<String> }`
- `VirtualChainDelta { removed_block_hashes: Vec<String>, accepted: Vec<BlockBatch>, checkpoint: SyncCheckpoint }`
- `BlockBatch { block: IndexedBlock, transactions: Vec<IndexedTransaction> }`

`IndexerConfig` fields:

- `mode: IndexingMode`
- `max_transactions: usize`
- `max_blocks: usize`
- `max_matches: usize`
- `dedupe_window: usize`
- `scanner_stale_after_ms: u64`
- `transaction_ttl_ms: u64`
- `max_payload_bytes: usize`
- `max_addresses_per_transaction: usize`
- `max_query_page: usize`

## Randomness API

### `RandomnessApi`

| Method | Parameters | Returns |
| --- | --- | --- |
| `beacon` | none | `&BeaconApi` |
| `vrf` | none | `&VrfApi` |

### `BeaconApi`

| Method | Parameters | Returns |
| --- | --- | --- |
| `observe_kaspa_block` | `evidence: KaspaEntropyEvidence` | `Result<()>` |
| `generate` | `request: BeaconRequest` | `Result<BeaconResult>` |
| `verify` | `result: &BeaconResult` | `Result<BeaconVerification>` |
| `generate_live` | `network: NetworkId`, `kaspa_blocks: usize`, `use_curby: bool`, `context: Vec<u8>` | `async Result<BeaconResult>` |

`BeaconRequest` fields:

- `network: NetworkId`
- `context: Vec<u8>`
- `kaspa: Vec<KaspaEntropyEvidence>`
- `curby: Option<CurbyEvidence>`
- `extractor: ExtractorConfig`

### `VrfApi` and `VrfSecretKey`

| Method | Parameters | Returns |
| --- | --- | --- |
| `VrfApi::generate_keypair` | none | `Result<(VrfSecretKey, VrfPublicKey)>` |
| `VrfApi::prove` | `secret: &VrfSecretKey`, `input: &[u8]` | `Result<VrfResult>` |
| `VrfApi::verify` | `public: &VrfPublicKey`, `input: &[u8]`, `proof: &VrfProof` | `Result<VrfOutput>` |
| `VrfSecretKey::from_bytes` | `bytes: [u8; 32]` | `VrfSecretKey` |
| `VrfSecretKey::public_key` | none | `VrfPublicKey` |
| `VrfSecretKey::expose_secret` | none | `[u8; 32]`; available only with `secret-export` |

## Browser / WebAssembly API

The browser classes are exported by `wasm-bindgen`. JavaScript method names below are the actual exported names. JSON-returning methods return a JSON string unless stated otherwise. Consensus-sized integer inputs are canonical unsigned decimal strings unless the signature is explicitly a small `number`. The parity contract for these methods is machine-enforced by [`../qa/e2e/capabilities.toml`](../qa/e2e/capabilities.toml).

### `new KaspaPortal(configJson?)`

`configJson` is optional JSON with `network`, `endpoint`, `timeoutMs`, `maxRetries`, and `indexer`. Supported network names are `mainnet`, `simnet`, `devnet`, and `testnet-N` (or compact `testnetN`) for numeric testnet suffixes 1 through 127. Existing names such as `testnet10`, `testnet11`, and `testnet12` remain compatible; future names such as `testnet-14` do not require an SDK enum change.

| Method | Parameters | Returns |
| --- | --- | --- |
| `config()` | none | portal configuration JSON |
| `connect()` | none | `Promise<string>` health JSON |
| `disconnect()` | none | `void` |
| `network()` | none | `KaspaNetwork`; throws if no endpoint is configured |
| `chain()` | none | `KaspaChain`; throws if no endpoint is configured |
| `wallet()` | none | `KaspaWallet` |
| `transaction()` | none | `KaspaTransaction` |
| `contract()` | none | `KaspaContract` |
| `privacy()` | none | `KaspaPrivacy` |
| `indexer()` | none | `KaspaIndexer` |
| `randomness()` | none | `KaspaRandomness` |

### `KaspaNetwork`

| Method | Parameters | Returns |
| --- | --- | --- |
| `networkId()` | none | `string` |
| `endpoint()` | none | `string` |
| `status()` | none | `string` |
| `client()` | none | `KaspaNetworkClient` |
| `connect()` | none | `Promise<string>` health JSON |
| `health()` | none | `Promise<string>` health JSON |
| `reconnect()` | none | `Promise<string>` health JSON |
| `disconnect()` | none | `void` |

`KaspaNetworkClient.call(operationCode, payload)` exposes the same low-level platform-neutral wRPC call capability as Rust `NetworkClient::call` and returns `Promise<Uint8Array>`.

### `KaspaChain`

| Method | Parameters | Returns |
| --- | --- | --- |
| `virtualDaaScore()` | none | `Promise<BigInt>` |
| `blockRaw(hashHex)` | 32-byte block hash hex | `Promise<Uint8Array>` |
| `utxos(address)` | address string | `Promise<string>` UTXO JSON |
| `utxosMany(addressesJson)` | JSON array of address strings | `Promise<string>` UTXO JSON |
| `transaction(txid)` | transaction ID string | optional decoded transaction JSON |
| `transactionRaw(txid)` | transaction ID string | optional raw indexed transaction JSON |
| `feeEstimate()` | none | `Promise<string>` fee-estimate JSON |

Decoded transaction lookup includes the transaction payload together with transaction ID, version, inputs, outputs, locktime, subnetwork ID, gas, and the raw indexed representation.

### `KaspaWallet`

| Method | Parameters | Returns |
| --- | --- | --- |
| `importKpub(kpub)` | canonical kpub string | wallet JSON |
| `importKpubRaw(payload)` | raw kpub bytes | wallet JSON |
| `extendAddresses(walletJson, receive, change)` | wallet JSON and two `u32` counts | wallet JSON |
| `utxos(walletJson)` | wallet JSON | `Promise<string>` UTXO JSON |
| `balance(walletJson)` | wallet JSON | `Promise<string>` balance JSON |
| `mnemonic12FromEntropy(entropy)` | 16-byte `Uint8Array` | mnemonic JSON containing indices, words, and phrase |
| `mnemonic24FromEntropy(entropy)` | 32-byte `Uint8Array` | mnemonic JSON containing indices, words, and phrase |
| `prefix()` | none | address-prefix string |

### `KaspaTransaction`

| Method | Parameters | Returns |
| --- | --- | --- |
| `pskb()` | none | `KaspaPskb` |
| `planSend(walletJson, destination, amountSompi, feeSompi)` | wallet JSON, address, amount decimal, fee decimal | `Promise<string>` wire |
| `planSendWithPayload(walletJson, destination, amountSompi, feeSompi, payload)` | same plus payload bytes | `Promise<string>` wire |
| `planSelectedSend(walletJson, destination, amountSompi, feeSompi, indicesJson)` | selected UTXO indices JSON | `Promise<string>` wire |
| `planConsolidation(walletJson, feeSompi)` | wallet JSON, fee decimal | `Promise<string>` wire |
| `scanMultisigBranch(descriptor, cosigner, depth, prefix)` | descriptor, two `u32` values, prefix | `Promise<string>` scan result |
| `planMultisigConsolidation(...)` | descriptor, sources JSON, destination, amount/fee decimals, cosigner, change-index hint | `Promise<string>` wire |
| `planCovenant(...)` | wallet JSON, covenant/change addresses, amount/fee decimals, UTXO index CSV, encoding kind, payload hex, genesis-tag flag | `Promise<string>` wire |
| `planCovenantWithBinding(...)` | same as `planCovenant` | `Promise<string>` JSON with wire and optional covenant ID |
| `planFromUtxos(walletJson, destination, amountSompi, feeSompi, utxosJson)` | explicit UTXO JSON | wire string |
| `setPayload(wireHex, payload)` | wire hex and payload bytes | updated wire string |
| `setTxLane(wireHex, subnetworkIdHex, gas, txVersion, payload)` | gas is decimal string | updated wire string |
| `analyze(wireHex)` | wire hex | `Promise<string>` `TransactionAnalysis` JSON using live fee estimate when available |
| `analyzeWithFeeRate(wireHex, feeRateSompiPerGram)` | wire hex, fee-rate decimal | `TransactionAnalysis` JSON |
| `review(wireHex, networkPrefix)` | wire hex, prefix | review-summary JSON |
| `finalize(wireHex)` | wire hex | finalized consensus-transaction JSON |
| `signCompactKspt(wire, privateKeyHex, sighashByte)` | wire bytes, 32-byte key hex, sighash byte | serialized KSSN hex |
| `signCompactKsptWithEntropy(wire, privateKeyHex, sighashByte, signingEntropyHex)` | same plus 32-byte signing entropy | serialized KSSN hex |
| `applySequenceCommitProof(wireHex, subnetworkIdHex, gas, transactionVersion, payload)` | sequence-commit lane fields | updated wire string |
| `broadcast(wireHex)` | finalized/reviewable wire hex | `Promise<string>` transaction identifier/response |
| `broadcastWire(wireHex)` | browser convenience alias | `Promise<string>` transaction identifier/response |

### `KaspaPskb`

| Method | Parameters | Returns |
| --- | --- | --- |
| `encode(planJson)` | `PskbPlan` JSON | encoded wire string |
| `encodeDocument(documentJson)` | PSKB document JSON | encoded wire string |
| `planSweep(...)` | UTXO JSON, source/destination script hex, send amount decimal, global plan JSON, input-policy JSON | `PskbPlan` JSON |
| `planGlobalThreadWithdrawal(...)` | thread UTXOs, scripts, covenant ID, withdrawal/fee/CSV decimals, policy JSON | withdrawal-plan JSON |
| `planGlobalThreadTopup(...)` | thread UTXO, wallet UTXOs, scripts, covenant ID, fee decimal, policy JSON | top-up-plan JSON |

### `KaspaContract`

All Rust contract sub-facades are flattened into this browser class.

| Method | Parameters | Returns |
| --- | --- | --- |
| `p2shAddress(redeemScript, prefix)` | script bytes, address prefix | address string |
| `cltvLocktime(script)` | script bytes | decimal locktime string or `null` |
| `csvSequence(script)` | script bytes | decimal sequence string or `null` |
| `dms(ownerHex, heirHex, inactivityDaa)` | two 32-byte keys, DAA decimal | script bytes |
| `privateSwap(ownerHex, claimerHex, claimerSpkHex, refundDaa, saltHex)` | keys/script hex, DAA decimal, 16-byte salt | script bytes |
| `piggyBank(ownerHex, thresholdSompi, deadlineDaa, saltHex)` | 32-byte key, amount/DAA decimals, 8-byte salt | script bytes |
| `timelockedSavings(firstHex, secondHex, locktimeDaa)` | two 32-byte keys, DAA decimal | script bytes |
| `payjoin(ownerHex, beneficiaryHex, locktimeDaa, minInputs, minOutputs)` | keys and decimal constraints | script bytes |
| `commitReveal(ownerHex, commitmentHex, locktimeDaa)` | two 32-byte values, DAA decimal | script bytes |
| `crowdfundCampaignId(goalSompi, locktimeDaa, verifyingKeyHashHex, organizerSpkHex)` | decimals and hex values | campaign-ID hex |
| `crowdfundRedeemScript(...)` | contributor key, goal/locktime decimals, verifying-key hash, organizer script, 8-byte salt | redeem-script bytes |
| `merkleRoot(leavesJson)` | JSON array of hex leaves | root hex |
| `merkleProof(leavesJson, leafIndex)` | JSON array of hex leaves, `u32` index | proof JSON |
| `oracleHeartbeatScript()` | none | script bytes |
| `oracleHeartbeatSigScript(redeem)` | redeem bytes | signature-script bytes |
| `oracleConsumerSigScript(redeem)` | redeem bytes | signature-script bytes |
| `sequenceCommitStealthProof(ephemeralPublicKeyHex, viewTag)` | 32-byte key, `u8` tag | proof/lane JSON |
| `shippingEscrow(requestJson)` | JSON containing seller/deliverer/buyer/arbiter keys, amount/fee/deadline decimal strings, and 8-byte salt | script bytes |
| `taggedVault(ownerHex)` | 32-byte key | script bytes |
| `splitVault(ownerHex)` | 32-byte key | script bytes |
| `covenantId(prevTxidHex, prevIndex, outputsJson)` | genesis outpoint and output descriptors | covenant-ID hex |
| `zkTrustedSetup()` | none | JSON with proving/verifying key hex |
| `zkProveCrowdfund(provingKeyHex, amountsJson)` | proving-key hex, JSON array of decimal amount strings | proof/public-input/total JSON |
| `zkVerify(verifyingKeyHex, proofHex, publicInputHex)` | three hex values | `boolean` |

### `KaspaPrivacy`

| Method | Parameters | Returns |
| --- | --- | --- |
| `announcementAddress(prefix)` | address prefix | string |
| `decodeMetadata(value)` | encoded stealth metadata | JSON with scan/spend x-only public keys |
| `deriveMetadata(kpub)` | canonical kpub | encoded stealth metadata |
| `encodeMetadata(metadataJson)` | JSON with `scanPubkey` and `spendPubkey` hex | encoded stealth metadata |
| `generateStealthPayment(metadataHex, entropyHex)` | metadata and 32-byte entropy | payment JSON |
| `scanRawForPreimage(raw, transactionIdHex)` | raw transaction bytes, transaction ID hex | preimage hex or `null` |

### `new KaspaIndexer(configJson?)`

`configJson` is optional and may be a partial object. Browser-facing fields use camelCase (`maxTransactions`, `maxBlocks`, `maxMatches`, `dedupeWindow`, `scannerStaleAfterMs`, `transactionTtlMs`, `maxPayloadBytes`, `maxAddressesPerTransaction`, `maxQueryPage`); omitted fields retain safe core defaults. The two millisecond `u64` fields are canonical decimal strings. Snake-case fields emitted by `config()` are also accepted for round-trip compatibility.

| Method | Parameters | Returns |
| --- | --- | --- |
| `start()` / `stop()` | none | `void` |
| `watchAddress(address)` | address | `BigInt` matcher ID |
| `watchPayloadPrefix(value)` | bytes | `BigInt` matcher ID |
| `watchPayloadContains(value)` | bytes | `BigInt` matcher ID |
| `watchPayloadExact(value)` | bytes | `BigInt` matcher ID |
| `watchPayloadSuffix(value)` | bytes | `BigInt` matcher ID |
| `addMatcher(ruleJson)` | `MatchRule` JSON | `BigInt` matcher ID |
| `removeMatcher(id)` | canonical decimal matcher ID | `boolean` |
| `ingestTransaction(json)` | indexed-transaction JSON | matches JSON |
| `ingestBlock(json)` | indexed-block JSON | `void` |
| `ingestBlockBatch(json)` | block-batch JSON | scan-report JSON |
| `transaction(txid)` | transaction ID | optional transaction JSON |
| `transactions(queryJson)` | transaction-query JSON | page JSON |
| `blocks(pageJson)` | page request JSON | page JSON |
| `matches(pageJson)` | page request JSON | page JSON |
| `snapshot()` / `restoreSnapshot(json)` | snapshot JSON on restore | snapshot JSON / `void` |
| `metrics()` / `health()` | none | JSON; `u64` metric counters are canonical decimal strings |
| `drainEvents()` | none | events JSON |
| `saveIndexedDb(namespace)` | namespace | `Promise<void>` |
| `loadIndexedDb(namespace)` | namespace | `Promise<boolean>` |
| `clearIndexedDb(namespace)` | namespace | `Promise<void>` |
| `persistedState()` / `restoreState(json)` | persisted-state JSON on restore | state JSON / `void` |
| `checkpoint()` / `setCheckpoint(json)` | checkpoint JSON on set | checkpoint JSON / `void` |
| `applySyncBatches(batchesJson, checkpointJson)` | block-batch array and checkpoint JSON | sync-report JSON |
| `reconcileVirtualChain(json)` | virtual-chain delta JSON | reconciliation-report JSON |
| `clear()` | none | `void` |

### `new KaspaRandomness()`

| Method | Parameters | Returns |
| --- | --- | --- |
| `observeKaspaBlock(evidenceJson)` | finalized Kaspa entropy evidence JSON | `void` |
| `generateBeacon(requestJson)` | beacon-request JSON | beacon-result JSON |
| `verifyBeacon(resultJson)` | beacon-result JSON | verification JSON |
| `generateLive(network, kaspaBlocks, useCurby, context)` | network string, `u32` count, boolean, context bytes | `Promise<string>` beacon-result JSON |
| `generateVrfKeypair()` | none | zeroizing `KaspaVrfSecretKey` handle |
| `vrfPublicKey(secretHex)` | 32-byte secret hex | public-key hex |
| `vrfProve(secretHex, input)` | secret hex, input bytes | VRF-result JSON |
| `vrfVerify(publicHex, input, proofHex)` | public-key hex, input bytes, proof hex | output hex |

### `KaspaVrfSecretKey`

`new KaspaVrfSecretKey(secretHex)` creates a zeroizing handle from a caller-supplied 32-byte secret. `generateVrfKeypair()` creates the handle from the platform CSPRNG. Dropping/freeing the WASM handle drops the Rust `VrfSecretKey`, whose storage is zeroized on drop.

| Method | Parameters | Returns |
| --- | --- | --- |
| `publicKey()` | none | public-key hex |
| `prove(input)` | input bytes | VRF-result JSON |
| `exposeSecret()` | none | secret hex; present only with the `secret-export` feature |

## Error behavior

Rust facade methods use `kaspa_portal::Error` through `Result<T>`. Browser methods surface failures as JavaScript exceptions/rejected promises through `JsValue`. Network-backed operations require a portal configured with a node endpoint. Offline-only wallet, contract, privacy, indexer, signing and randomness operations do not require a node unless the specific method performs network I/O.
