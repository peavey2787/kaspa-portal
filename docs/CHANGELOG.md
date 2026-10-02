# Changelog

## 1.2.1

- Payload sends (`create_send_with_payload`) no longer fail with "payload-aware
  storage-mass fee calculation did not converge". KIP-9 storage mass grows as
  the change output shrinks, so the fee fixed point approaches the
  storage-dust boundary in ever smaller steps; the 16-pass bound gave up just
  short of it for many ordinary wallets (e.g. 0.2 KAS out of a 0.43 KAS UTXO).
- Payload sends now evaluate every largest-first input prefix within the
  input limit and keep the cheapest complete plan, instead of the smallest
  covering one: an extra input that grows the change is far cheaper than a
  tiny change's storage-mass fee (or a storage-dust change burned as fee).

## 1.2.0

- Added `ChainApi::blocks_since` / `KaspaChain.blocksSince`: wRPC `GetBlocks`
  (with transactions) past a low hash, so a consumer can backfill blocks it
  missed while its BlockAdded stream was disconnected. The response decoder is
  bounded, rejects trailing bytes and requires the success payload marker;
  covered by unit tests and the Rust and browser live-network scenarios.

## 1.1.1

### Added

- `network::resolver`: public node discovery through the community wRPC resolvers (TLS `wss://` endpoints only, bounded HTTPS answers). `KaspaPortal::builder().connect()` with no endpoint resolves and connects to the first healthy public node, on native and browser targets.

### Fixed

- PSKB/PSKT encoders now emit the standard PSKT format version `"version": 0` (rusty-kaspa `Version::Zero`). The transaction builder previously omitted it and the interchange encoder wrote `1`, so strict signers such as KasKold 2.0 rejected Portal PSKBs. The parser accepts only version 0.
- The transaction builder's PSKB now uses the standard PSKT shape its interchange encoder already produced: explicit `sighashType` (SIGHASH_ALL) per input, `inputsModifiable`/`outputsModifiable`, `xpubs`, and JSON objects for `proprietaries`/`bip32Derivations` (previously the KasKold 1.x Companion envelope with `*ModifiableFlag` and empty arrays). KasKold 2.0 accepts Portal PSKBs directly.

## 1.1.0

### Added

- Cross-target Kaspa notification subscriptions on `NetworkApi`: `subscribe_block_added`, `subscribe_utxos_changed`, `subscribe_virtual_daa_score_changed`, `next_notification`, and `next_block_added` now work on native and browser/WASM hosts.
- Decoded `Notification` enum (`BlockAdded`, `UtxosChanged`, `VirtualDaaScoreChanged`) in `network::wrpc::notification`.
- Browser transport keeps a dedicated persistent notification WebSocket behind the `Transport` trait (`Transport::subscribe`), so apps no longer need a separate Kaspa RPC client for live events.

## 1.0.1

### Fixed

- Replaced the SDK's 768-byte transaction-payload model ceiling with the KSPT v1 format ceiling of 65,535 bytes and moved transaction payload storage to `Vec<u8>`.
- Widened standard PSKT decoded-JSON/unknown-field bookkeeping so large transaction interchange data is not constrained by 16-bit parser offsets.
- Made native transport futures `Send` while retaining non-`Send` WASM futures.
- Reworked native wRPC around one persistent WebSocket driver per Portal transport, with RPC/notification multiplexing, explicit shutdown, reconnect, and subscription replay.
- Added native first-class BlockAdded subscription and decoded-notification APIs.
- Made `plan_send_with_payload()` account for payload mass/fees before final UTXO selection and revalidate the planned transaction before PSKB encoding.
- Made storage-mass fee solving stable at the dust-change boundary: once change is omitted as dust, the full input-minus-payment remainder is treated as the actual fee instead of oscillating between one-output and two-output estimates.
- Preserved fail-closed monetary-range validation in the payload-aware fee solver so `amount + minimum_fee` overflow (including `u64::MAX` boundary inputs) is rejected instead of being mistaken for an underfunded selection.
- Aligned the indexer's default payload bound with the 65,535-byte KSPT v1 ceiling and added optional Portal-level live BlockAdded ingestion.

### Compatibility

- KSPT remains version 1. No new KSPT wire version is introduced; payloads larger than 65,535 bytes are rejected.
- Browser/WASM request transport remains target-specific and does not acquire native threading requirements.
