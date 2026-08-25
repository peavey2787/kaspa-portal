#!/usr/bin/env python3
"""Enforce the public Rust/WASM capability inventory and parity contract."""

from __future__ import annotations

import re
import sys
from collections import Counter
from typing import Dict, List, Optional, Set
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "qa" / "e2e" / "capabilities.toml"

RUST_FILES = [
    "src/portal/builder.rs",
    "src/portal/facade.rs",
    "src/portal/config.rs",
    "src/network/facade.rs",
    "src/network/client.rs",
    "src/chain/facade.rs",
    "src/wallet/facade.rs",
    "src/transaction/facade.rs",
    "src/transaction/builder/pskb/facade.rs",
    "src/contract/facade.rs",
    "src/privacy/facade.rs",
    "src/indexer/facade.rs",
    "src/randomness/facade.rs",
    "src/randomness/beacon/mod.rs",
    "src/randomness/vrf/mod.rs",
]

RUST_TYPES = {
    "KaspaPortalBuilder",
    "KaspaPortal",
    "PortalConfig",
    "NetworkApi",
    "NetworkClient",
    "ChainApi",
    "WalletApi",
    "TransactionApi",
    "PskbApi",
    "ContractApi",
    "ScriptApi",
    "CovenantApi",
    "CommitRevealApi",
    "CrowdfundApi",
    "MerkleApi",
    "OracleApi",
    "SequenceCommitApi",
    "ShippingEscrowApi",
    "VaultApi",
    "ZkApi",
    "PrivacyApi",
    "StealthApi",
    "IndexerApi",
    "RandomnessApi",
    "BeaconApi",
    "VrfApi",
    "VrfSecretKey",
}

WASM_FILES = [
    "src/platform/browser/bindings/portal.rs",
    "src/platform/browser/bindings/core/network.rs",
    "src/platform/browser/bindings/core/chain.rs",
    "src/platform/browser/bindings/core/wallet.rs",
    "src/platform/browser/bindings/core/transaction.rs",
    "src/platform/browser/bindings/core/transaction/pskb.rs",
    "src/platform/browser/bindings/core/contract.rs",
    "src/platform/browser/bindings/core/privacy.rs",
    "src/platform/browser/bindings/indexer.rs",
    "src/platform/browser/bindings/randomness.rs",
]

WASM_TYPES = {
    "WasmKaspaPortal",
    "WasmNetwork",
    "WasmNetworkClient",
    "WasmChain",
    "WasmWallet",
    "WasmTransaction",
    "WasmPskb",
    "WasmContract",
    "WasmPrivacy",
    "WasmIndexer",
    "WasmRandomness",
    "WasmVrfSecretKey",
}

ALLOWED_EXECUTION = {
    "offline",
    "public_standard",
    "funded_standard",
    "funded_covenant",
    "browser_storage",
    "simulated_fault",
}
ALLOWED_RESOURCE_PROFILES = {
    "standard",
    "network",
    "crypto",
    "indexer",
    "browser_storage",
    "lifecycle",
}
ALLOWED_E2E_STATUS = {"pending", "covered"}

IMPL_RE = re.compile(r"^\s*impl(?:<[^>]*>)?\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{")
PUB_FN_RE = re.compile(r"^\s*pub\s+(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)")



def parse_value(raw: str):
    raw = raw.strip()
    if raw == "true":
        return True
    if raw == "false":
        return False
    if raw.startswith('"') and raw.endswith('"'):
        return bytes(raw[1:-1], "utf-8").decode("unicode_escape")
    if raw.startswith("[") and raw.endswith("]"):
        body = raw[1:-1].strip()
        if not body:
            return []
        values = []
        current = []
        quoted = False
        escaped = False
        for char in body:
            if escaped:
                current.append(char)
                escaped = False
                continue
            if char == "\\" and quoted:
                current.append(char)
                escaped = True
                continue
            if char == '"':
                quoted = not quoted
                current.append(char)
                continue
            if char == "," and not quoted:
                values.append(parse_value("".join(current).strip()))
                current = []
            else:
                current.append(char)
        values.append(parse_value("".join(current).strip()))
        return values
    try:
        return int(raw)
    except ValueError as error:
        raise ValueError(f"unsupported registry value: {raw}") from error


def load_registry(path: Path) -> Dict:
    data = {}
    current = data
    for number, source in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = source.strip()
        if not line or line.startswith("#"):
            continue
        if line == "[[capability]]":
            item = {}
            data.setdefault("capability", []).append(item)
            current = item
            continue
        if line == "[[rust_exclusion]]":
            item = {}
            data.setdefault("rust_exclusion", []).append(item)
            current = item
            continue
        if "=" not in line:
            raise ValueError(f"invalid capability registry line {number}: {source}")
        key, raw = line.split("=", 1)
        current[key.strip()] = parse_value(raw)
    return data

def public_impl_methods(paths: List[str], tracked_types: Set[str]) -> Set[str]:
    methods = set()
    for relative in paths:
        path = ROOT / relative
        if not path.is_file():
            raise RuntimeError(f"tracked source file is missing: {relative}")
        current = None  # type: Optional[str]
        depth = 0
        for line in path.read_text(encoding="utf-8").splitlines():
            match = IMPL_RE.match(line)
            if current is None and match and match.group(1) in tracked_types:
                current = match.group(1)
                depth = line.count("{") - line.count("}")
                continue
            if current is None:
                continue
            method = PUB_FN_RE.match(line)
            if method:
                methods.add(f"{current}::{method.group(1)}")
            depth += line.count("{") - line.count("}")
            if depth <= 0:
                current = None
                depth = 0
    return methods


def fail(errors: List[str]) -> int:
    print("CAPABILITY/PARITY CHECK: FAIL")
    for error in errors:
        print(f"ERROR: {error}")
    return 1


def main() -> int:
    if not REGISTRY.is_file():
        return fail(["qa/e2e/capabilities.toml is missing"])

    data = load_registry(REGISTRY)

    errors = []  # type: List[str]
    if data.get("schema") != 1:
        errors.append("capability registry schema must be 1")
    if data.get("surface") != "public-developer-api":
        errors.append("capability registry surface must be public-developer-api")
    if data.get("standard_network") != "testnet-10":
        errors.append("default standard E2E network must be testnet-10")
    if data.get("covenant_network") != "testnet-12":
        errors.append("default covenant E2E network must be testnet-12")

    capabilities = data.get("capability", [])
    exclusions = data.get("rust_exclusion", [])
    if not capabilities:
        errors.append("capability registry has no capabilities")

    ids = [item.get("id") for item in capabilities]
    duplicate_ids = sorted(key for key, count in Counter(ids).items() if count > 1)
    if duplicate_ids:
        errors.append(f"duplicate capability id(s): {', '.join(duplicate_ids)}")

    rust_registry = set()  # type: Set[str]
    wasm_registry = set()  # type: Set[str]
    domain_counts: Counter[str] = Counter()
    execution_counts: Counter[str] = Counter()

    for item in capabilities:
        cid = item.get("id", "<missing-id>")
        domain = item.get("domain")
        rust_symbol = item.get("rust_symbol")
        wasm_symbols = item.get("wasm_symbols")
        execution = item.get("execution")
        resource = item.get("resource_profile")
        status = item.get("e2e_status")
        funds_required = item.get("funds_required")

        if not isinstance(domain, str) or not domain:
            errors.append(f"{cid}: domain is required")
        else:
            domain_counts[domain] += 1
        if not isinstance(rust_symbol, str) or "::" not in rust_symbol:
            errors.append(f"{cid}: rust_symbol must be Type::method")
        else:
            rust_registry.add(rust_symbol)
        if not isinstance(wasm_symbols, list) or not wasm_symbols:
            errors.append(f"{cid}: at least one WASM mapping is required")
        else:
            for symbol in wasm_symbols:
                if not isinstance(symbol, str) or "::" not in symbol:
                    errors.append(f"{cid}: invalid WASM symbol {symbol!r}")
                else:
                    wasm_registry.add(symbol)
        if execution not in ALLOWED_EXECUTION:
            errors.append(f"{cid}: unsupported execution class {execution!r}")
        else:
            execution_counts[execution] += 1
        if resource not in ALLOWED_RESOURCE_PROFILES:
            errors.append(f"{cid}: unsupported resource profile {resource!r}")
        if status not in ALLOWED_E2E_STATUS:
            errors.append(f"{cid}: e2e_status must be pending or covered")
        if not isinstance(funds_required, bool):
            errors.append(f"{cid}: funds_required must be boolean")
        if funds_required and execution not in {"funded_standard", "funded_covenant"}:
            errors.append(f"{cid}: funds_required capabilities must use a funded execution class")
        if execution == "funded_covenant" and not str(cid).startswith("transaction.plan_covenant"):
            errors.append(f"{cid}: only covenant transaction planners may use funded_covenant")

    excluded = set()  # type: Set[str]
    for item in exclusions:
        symbol = item.get("symbol")
        reason = item.get("reason")
        if not isinstance(symbol, str) or "::" not in symbol:
            errors.append(f"invalid rust_exclusion symbol: {symbol!r}")
            continue
        if not isinstance(reason, str) or not reason.strip():
            errors.append(f"{symbol}: rust_exclusion requires a reason")
        excluded.add(symbol)

    try:
        rust_actual = public_impl_methods(RUST_FILES, RUST_TYPES)
        wasm_actual = public_impl_methods(WASM_FILES, WASM_TYPES)
    except RuntimeError as error:
        errors.append(str(error))
        rust_actual = set()
        wasm_actual = set()

    overlap = rust_registry & excluded
    if overlap:
        errors.append(
            "symbols cannot be both registered and excluded: " + ", ".join(sorted(overlap))
        )

    missing_rust = sorted(rust_actual - rust_registry - excluded)
    stale_rust = sorted(rust_registry - rust_actual)
    stale_exclusions = sorted(excluded - rust_actual)
    missing_wasm = sorted(wasm_actual - wasm_registry)
    stale_wasm = sorted(wasm_registry - wasm_actual)

    if missing_rust:
        errors.append("unregistered public Rust capability(s): " + ", ".join(missing_rust))
    if stale_rust:
        errors.append("registry references missing Rust symbol(s): " + ", ".join(stale_rust))
    if stale_exclusions:
        errors.append("stale Rust exclusion(s): " + ", ".join(stale_exclusions))
    if missing_wasm:
        errors.append("unregistered WASM export(s): " + ", ".join(missing_wasm))
    if stale_wasm:
        errors.append("registry references missing WASM symbol(s): " + ", ".join(stale_wasm))

    if errors:
        return fail(errors)

    pending = sum(1 for item in capabilities if item["e2e_status"] == "pending")
    print("CAPABILITY/PARITY CHECK: PASS")
    print(f"Public capabilities registered: {len(capabilities)}")
    print(f"Rust methods covered: {len(rust_actual) - len(excluded)}/{len(rust_actual) - len(excluded)}")
    print(f"WASM methods covered: {len(wasm_actual)}/{len(wasm_actual)}")
    print(f"Explicit non-facade Rust exclusions: {len(excluded)}")
    print(f"E2E scenarios pending future passes: {pending}")
    print("Domains: " + ", ".join(f"{key}={domain_counts[key]}" for key in sorted(domain_counts)))
    print(
        "Execution classes: "
        + ", ".join(f"{key}={execution_counts[key]}" for key in sorted(execution_counts))
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
