# Changelog

## Unreleased

One implementation per primitive.

- `ThreadWithdrawFee::maximum_withdraw` fixes its answer bit by bit in a
  bounded 64-step search instead of an open `while` loop.
- `element_integer` drops any trailing zero sign byte (value-preserving).
- Tests pin the KRC-20 envelope payload rule, `Elements::is_complete`, the
  storage-mass limit boundary and the Private Swap destination length bounds.

- Fuzz harness bodies live in the `kaspa-portal-fuzz` library. A stable
  smoke test drives every harness with seeds and deterministic mutations in
  run-all and CI; KSPT, PSKT/PSKB and QR frames must round-trip and a QR
  session must reassemble in any frame order. New `qr_session` target; a
  nightly `fuzz` workflow runs each libFuzzer target for five minutes.

- KSPT decoding is canonical: a script length below 255 written in the
  three-byte long form is refused (`WireError::NonCanonicalEncoding`,
  `PsktError::NonCanonicalEncoding`). Signature records keep the order they
  were added, because anti-klepto proofs bind each signature to its slot. The
  `kspt` fuzz oracle requires every accepted envelope to re-encode to exactly
  its input bytes.

- wRPC response decoders share one strict success envelope: the `1` payload
  marker, the length-prefixed body and nothing after it. A short reply to
  `GetUtxosByAddresses` is an error instead of an empty UTXO set, and a short
  fee reply is an error instead of a 1 sompi/gram guess (callers already
  choose their own fallback rate); `FeeEstimate::conservative_fallback` is
  removed. UTXO outpoints must be exactly 37 bytes, and an entry whose script
  version is not 0 is refused rather than relabelled as version 0.

- Base58 and Base58Check encoding return `Result`: input over 128 bytes and
  an output buffer too small for the whole text are refused instead of
  truncated, and a full 128-byte value now encodes (175 characters) rather
  than failing. The power-on self-test pins Base58Check(`00`) = `1Wh4bh`.

- The animated-QR decoder ends its session on every rejected frame (mixed
  session, conflicting duplicate, digest mismatch), so the next transfer
  starts clean without a `reset_decoder` call; text that is not a frame
  leaves a transfer in progress untouched.

- E2E covenant workflows default to testnet-10 (covenants are live there
  since Toccata). The funding helpers check the wallet balance first and
  only prompt when it holds less than 10 KAS.

- `primitives::script::{read_element, elements}` is the only script-push
  reader; the covenant branch resolver, execution tracer, script-integer
  walker, key scanner and stealth scanner use it.
- Template recognizers live beside their builders and rebuild to compare:
  `covenant::private_swap_script_fields`, `commit_reveal::commit_reveal_script_fields`,
  `merkle::merkle_whitelist_script_fields` (Oracle-v1 already did). The PSKT
  pipeline's hand-written template parsers and the signer's own Private Swap
  parser are removed.
- `contract::krc20::krc20_operation` decodes a Kasplex reveal envelope.
- `MultisigConfig::{address, cosigner_parts, write_descriptor, from_descriptor}`.
- `primitives::address::{p2pk_script, p2sh_script}` build the standard locks
  and `{p2pk_xonly, p2sh_hash}` recognize them (moved from
  `contract::script`); `script_address` maps a standard lock to its address.
- `transaction::mass::ThreadWithdrawFee` prices a covenant-thread withdrawal at its
  KIP-9 storage mass and refuses remainders the storage-mass limit rejects.
- `transaction::interchange::pskt::append_output` appends a plain output to a
  PSKB wire and keeps `global.outputCount` exact; `pskb::plain_output_value` is
  the canonical output JSON it uses.
- `contract::shipping_escrow::ship_escrow_terms` reads a shipment-escrow redeem
  script back into its terms; `ShippingEscrowTranches` is the one place the
  pickup/delivery split is computed, with checked arithmetic throughout.
- `MultisigConfig::DESCRIPTOR_MAX_LEN` is the exact longest descriptor
  `write_descriptor` emits, so callers size its buffer from the owner.
- The browser funded fixture shares the Rust E2E funded support module and
  prices the multisig consolidation with the multisig fee, not the
  single-key broadcast fee.
- `contract::covenant::spend_path::{spend_path, is_single_path}` read which
  path a two-branch covenant spend took from its signature script.
- `contract::commit_reveal::read_commit_reveal_reveal` reads a reveal spend's
  preimage and opened script; `CommitRevealReveal::matches` checks the commitment.
- `transaction::interchange::pskt::pskb::encode_pskt_document` wraps a PSKT JSON
  document in the canonical PSKB wire; `ThreadWithdrawFee::maximum_withdraw`
  finds the largest withdrawal that still prices.
- `primitives::hash::{blake2b_256, Blake2b256}` is Portal's only BLAKE2b
  (unkeyed and keyed). The hand-written keyed compression in
  `transaction::sighash`, `sighash::{blake2b_hash, KaspaBlake2b}` and the
  `blake2` dependency are removed.
- `primitives::multisig_script` is the only `OP_CHECKMULTISIG` redeem codec;
  the transaction model, PSKT pipeline and `wallet::multisig::build_redeem_script`
  use it.
- `primitives::opcode` is the only opcode table (`contract::script::opcode`
  re-exports it; the model's duplicate constants are gone).
- `primitives::bytes::decode_hex` joins `decode_lower_hex`; the PSKT and
  descriptor parsers use them instead of their own loops.

Toccata-sized payloads and covenant genesis proofs.

- `contract::covenant::identity` is the one KIP-20 covenant-ID hash
  (known-answer tested against rusty-kaspa) and proves what a covenant was
  created as: `verify_genesis` recomputes the ID from the genesis outpoint and
  authorized outputs, `verify_redeem_script` proves an output locks a published
  redeem script, and `ConsensusTransaction::covenant_genesis` extracts and
  verifies the group from the genesis transaction. Exposed as
  `CovenantApi::{id, verify_genesis, verify_redeem_script}` and wasm
  `verifyCovenantGenesis`. `VaultApi::covenant_id` and
  `vault::compute_covenant_id` are removed (use `CovenantApi::id`).
- `MAX_PAYLOAD_SIZE` is now 250,000 bytes (`MAX_SERIALIZED_TRANSACTION_BYTES`):
  the 1,000,000-gram Toccata transient block limit at 4 grams per byte. The
  former 65,535-byte ceiling came from the KSPT `u16` payload length; mass
  analysis still decides whether the whole transaction fits.
- KSPT v1's global payload length is a little-endian `u32` (was `u16`); the
  global section is 47 bytes. Signer and Companion builds must pin the same
  Portal revision. The indexer's default `max_payload_bytes` follows
  `MAX_PAYLOAD_SIZE`.

Finalization runs only through the verify-once PSKT pipeline.

- `TransactionApi::finalize`, `analyze` and `analyze_with_fee_rate` verify
  every signature and build witnesses from the authorized typed plan; the
  unverified finalizer that chose branches from `covenantBranch`,
  `escrowBranch` and `shipBranch` metadata is removed.
- Covenant witnesses follow `contract::covenant::execution::trace_witness`,
  which models stack effects: IF/NOTIF conditions the script computes (the
  global-thread continuation check) are not witness selectors, and any path
  needing other witness data, unmodelled opcodes or non-canonical signature
  checks is refused rather than guessed.
- Removed: `pskt::relay_pskb_as_kspt_hex_for_network`,
  `pskt::merge_signed_kspt_into_pskb` and `consensus::decode_signed_kspt`.
  Use `pskt::pipeline::{encode_pskt, merge_signed_kspt, sign_pskt,
  verify_complete_kspt}` and `VerifiedTransaction::to_consensus`.
- Removed proprietary routes no producer emits (`commitPreimage`, oracle-MB,
  ZK/RISC0/Groth16/bridge claims, rollup and deposit-holding transitions);
  those fields are rejected as having no typed verified witness plan.
- PSKB plans carry an explicit per-input `CovenantExecution`;
  `PskbGlobalPlan::covenant_branch`/`with_branch` are removed and
  `SweepInputPolicy::covenant` takes the execution instead of branch metadata.
- `pskt::parse_summary` reports cryptographically verified signature counts
  and completion (from the pipeline) instead of counting signature entries,
  and includes output change-derivation hints. Review, mutation and the PSKB
  envelope share the pipeline's strict JSON grammar, lowercase outer hex and
  resource ceiling; multisig and key-position parsing exist once.

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
- The xpub power-on self-test also checks the original hardware-signer
  account-export vectors (kpub payload, XPrv text and recovered keys), and a
  unit test pins the BIP340 known-answer constant to the published vector 0.
- Account-key import accepts the Base58Check `kpub…` that rusty-kaspa wallets
  export (decode-only, alongside `kpub1:` text and account-level `xpub`).
  Portal now has a single strict Base58 decoder; the old one silently
  truncated oversized input.
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
