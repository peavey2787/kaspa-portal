# Changelog

## 1.4.0

Hardened signer core merged from KasKold, so the hardware signer can depend on
Portal instead of carrying its own copy.

- Transaction model: runtime `TransactionLimits` (inputs, payload bytes) with
  `Transaction::try_new_with`; payload is a fallibly allocated `Vec`; input
  storage grows only as wire records are consumed and never past the limit.
- KSPT signature status is cryptographic: `is_fully_signed` and
  `signature_status` verify every BIP340 signature over the exact SIGHASH_ALL
  digest instead of counting occupied slots.
- KSPT enforces SIGHASH_ALL for every signature slot, honours the
  transaction's device limits while decoding, and rejects hardened
  derivation indexes.
- KSPT trailers are canonical: fixed kind order, strictly increasing
  positions, network binding first. New input-derivation (`A`) and
  covenant-execution (`E`) trailers.
- Covenant signing binds candidate keys to the supplied execution branch
  selectors (`contract::covenant::branch`) instead of scanning every pushed key.
- Watchdog-friendly `*_with_checkpoint` variants of address lookup, account
  signing and anti-klepto finalization for constrained hardware.
- Password KDF v1 profile strengthened to Argon2id 8 MiB / t=3 / p=1, with a
  `DeviceBoundBackup` purpose; known answers come from the reference C
  implementation. The Argon2 frame keeps a single-pointer ABI to avoid an
  Xtensa LLVM stack-realignment bug (LLVM #208946).
- ECIES allocates fallibly and never panics on malformed points; Schnorr
  verification is split into out-of-line stages to bound embedded stack use.
- BIP39 seed stretching has a precomputed loop bound and zeroizes on drop.
- Covenant `KeyPresent` binding requires the key as an actual pushed script
  value, and `FixedCheckSigFromStack` requires the whole script to equal the
  fixed grammar; previously a matching byte window anywhere in the script
  was accepted.
- Private Swap claim validation allocates fallibly and treats an unsigned
  input's zero sighash byte as the SIGHASH_ALL protocol default.
- Totality tests feed every externally reachable parser truncated input and
  noise of every length up to 600 bytes, including the anti-klepto,
  covenant-sign and Private Swap wire protocols.
- `wallet::derivation::hmac` and `wallet::mnemonic::wordlist` are public so
  embedded signers reuse them instead of keeping copies.
- New `self-test` feature: `kaspa_portal::self_test` exposes the power-on
  known-answer runners (BIP39, BIP32, BIP85, xpub, address, Schnorr, sighash,
  KSPT)
  that hardware signers run at boot. They return `(passed, total)`, never
  panic (allocation failure counts as a failed check), and the unit tests
  assert each one passes. CI builds the feature on the bare-metal target.
- The `no_std` core no longer enables `k256/alloc`, which pulled `spki` and
  `pkcs8` into embedded dependency graphs that never use them.
- The library is an `rlib` only. Listing `cdylib` made every dependent,
  including `no_std` firmware, build a C dynamic library that needs an
  allocator and panic handler. The browser QA bundle now comes from the
  `qa/e2e/wasm` wrapper crate, which exports the same JavaScript API.
- `transaction::interchange::qr::security` (multi-frame session binding) is
  part of the `no_std` core, and `kspt::KSPT_VERSION` / `kspt::KSSN_VERSION`
  are exported so signers and hosts share one version byte.
- `crypto::adaptor::extract_adaptor_secret` recovers the Private Swap secret
  from a completed signature, so hosts share the signer's adaptor math.
- Ported the hardware signer's test suites for bytes, covenant branch
  resolution, QR frames and sessions, anti-klepto wire, PSKT state, account
  keys and BIP32 xpub import.
- Standard PSKT parser/serializer replaced by the hardened implementation with
  a split schema module, u32 offsets, and fallible storage.

## 1.3.0

- New default `std` feature. With `default-features = false` Kaspa Portal is a
  `no_std` + `alloc` signing core (keys, BIP32/BIP39/BIP85 derivation,
  addresses, transaction model, sighash, Schnorr signing, PSKT/KSPT
  interchange, crypto) for embedded and air-gapped signers, so hardware
  wallets share the audited host implementation instead of carrying a copy.
- Every dependency is declared `default-features = false`; operating-system
  dependencies (network, randomness, arkworks, VRF, QR rendering, tokio) are
  optional and enabled by `std`. `wasm` implies `std`. Default builds are
  unchanged.
- CI builds the core for `thumbv7em-none-eabihf` with warnings denied.

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
