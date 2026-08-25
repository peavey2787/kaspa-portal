#!/usr/bin/env python3
"""Enforce executable browser/WASM E2E mapping for every public capability."""
from __future__ import annotations

import pathlib
import re
import sys
from collections import Counter

sys.dont_write_bytecode = True
from check_capability_parity import load_registry

ROOT = pathlib.Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "qa" / "e2e" / "capabilities.toml"
SCENARIOS = ROOT / "qa" / "e2e" / "browser" / "scenarios"

WASM_CLASS = {
    "WasmKaspaPortal": "KaspaPortal",
    "WasmNetwork": "KaspaNetwork",
    "WasmNetworkClient": "KaspaNetworkClient",
    "WasmChain": "KaspaChain",
    "WasmWallet": "KaspaWallet",
    "WasmTransaction": "KaspaTransaction",
    "WasmPskb": "KaspaPskb",
    "WasmContract": "KaspaContract",
    "WasmPrivacy": "KaspaPrivacy",
    "WasmIndexer": "KaspaIndexer",
    "WasmRandomness": "KaspaRandomness",
    "WasmVrfSecretKey": "KaspaVrfSecretKey",
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

IMPL_RE = re.compile(r"^\s*impl\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{")
PUB_FN_RE = re.compile(r"^\s*pub\s+(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)")
JS_NAME_RE = re.compile(r"#\s*\[\s*wasm_bindgen\s*\(\s*js_name\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*\]")
CONSTRUCTOR_RE = re.compile(r"#\s*\[\s*wasm_bindgen\s*\(\s*constructor\s*\)\s*\]")
SCENARIO_RE = re.compile(r"\bexport\s+async\s+function\s+(wasm_[a-z0-9_]+)\s*\(")


def fail(message: str) -> None:
    print(f"WASM E2E COVERAGE CHECK: FAIL\nERROR: {message}")
    raise SystemExit(1)


def wasm_js_calls() -> dict[str, tuple[str, bool]]:
    calls: dict[str, tuple[str, bool]] = {}
    for relative in WASM_FILES:
        path = ROOT / relative
        current = None
        depth = 0
        pending_name = None
        pending_constructor = False
        for line in path.read_text(encoding="utf-8").splitlines():
            if current is None:
                match = IMPL_RE.match(line)
                if match and match.group(1) in WASM_CLASS:
                    current = match.group(1)
                    depth = line.count("{") - line.count("}")
                continue
            name_match = JS_NAME_RE.search(line)
            if name_match:
                pending_name = name_match.group(1)
            if CONSTRUCTOR_RE.search(line):
                pending_constructor = True
            fn_match = PUB_FN_RE.match(line)
            if fn_match:
                rust_name = fn_match.group(1)
                symbol = f"{current}::{rust_name}"
                calls[symbol] = (pending_name or rust_name, pending_constructor)
                pending_name = None
                pending_constructor = False
            depth += line.count("{") - line.count("}")
            if depth <= 0:
                current = None
                depth = 0
                pending_name = None
                pending_constructor = False
    return calls


def main() -> None:
    data = load_registry(REGISTRY)
    capabilities = data.get("capability", [])
    if not capabilities:
        fail("capability registry is empty")

    scenario_files: dict[str, tuple[pathlib.Path, str]] = {}
    for path in sorted(SCENARIOS.glob("*.mjs")):
        source = path.read_text(encoding="utf-8")
        for match in SCENARIO_RE.finditer(source):
            scenario = match.group(1)
            if scenario in scenario_files:
                fail(f"duplicate WASM E2E scenario function {scenario}")
            scenario_files[scenario] = (path, source)

    calls = wasm_js_calls()
    scenario_counts: Counter[str] = Counter()
    for capability in capabilities:
        ident = capability.get("id", "<missing-id>")
        scenario = capability.get("wasm_e2e")
        if not isinstance(scenario, str) or not scenario:
            fail(f"capability {ident} has no wasm_e2e mapping")
        if scenario not in scenario_files:
            fail(f"capability {ident} maps to missing WASM E2E scenario {scenario}")
        path, source = scenario_files[scenario]
        for symbol in capability.get("wasm_symbols", []):
            if symbol not in calls:
                fail(f"capability {ident} references unrecognized WASM symbol {symbol}")
            js_name, constructor = calls[symbol]
            cls = symbol.split("::", 1)[0]
            if constructor:
                probe = re.compile(rf"\bnew\s+sdk\.{re.escape(WASM_CLASS[cls])}\s*\(")
            else:
                probe = re.compile(rf"\.{re.escape(js_name)}\s*\(")
            if not probe.search(source):
                fail(
                    f"capability {ident} maps to {scenario}, but {path.name} does not "
                    f"exercise JS export {WASM_CLASS[cls]}.{js_name}()"
                )
        scenario_counts[scenario] += 1

    unused = sorted(set(scenario_files) - set(scenario_counts))
    if unused:
        fail("unregistered WASM E2E scenario(s): " + ", ".join(unused))

    execution = Counter(item.get("execution") for item in capabilities)
    print("WASM E2E COVERAGE CHECK: PASS")
    print(f"  Browser-testable capabilities mapped: {len(capabilities)}/{len(capabilities)}")
    print(f"  Offline capabilities: {execution['offline']}")
    print(f"  Public standard-network capabilities: {execution['public_standard']}")
    print(f"  Funded standard-network capabilities: {execution['funded_standard']}")
    print(f"  Funded covenant-network capabilities: {execution['funded_covenant']}")
    print(f"  IndexedDB/browser-storage capabilities: {execution['browser_storage']}")
    print(f"  WASM E2E scenario functions: {len(scenario_files)}")


if __name__ == "__main__":
    main()
