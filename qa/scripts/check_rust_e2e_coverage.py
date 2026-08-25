#!/usr/bin/env python3
"""Enforce complete Rust E2E scenario mapping for the public capability registry."""
from __future__ import annotations

import pathlib
import re
import sys
from collections import Counter

sys.dont_write_bytecode = True

from check_capability_parity import load_registry

ROOT = pathlib.Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "qa" / "e2e" / "capabilities.toml"
E2E_ROOT = ROOT / "qa" / "tests" / "e2e"


def fail(message: str) -> None:
    print(f"RUST E2E COVERAGE CHECK: FAIL\nERROR: {message}")
    raise SystemExit(1)


def main() -> None:
    data = load_registry(REGISTRY)
    capabilities = data.get("capability", [])
    if not capabilities:
        fail("capability registry is empty")

    scenario_files = {}
    for path in sorted(E2E_ROOT.rglob("*.rs")) if E2E_ROOT.exists() else []:
        source = path.read_text(encoding="utf-8")
        for match in re.finditer(r"\b(?:async\s+)?fn\s+(rust_[a-z0-9_]+)\s*\(", source):
            scenario = match.group(1)
            if scenario in scenario_files:
                fail(f"duplicate Rust E2E scenario function {scenario}")
            scenario_files[scenario] = (path, source)
    functions = set(scenario_files)

    mapped = 0
    deferred = 0
    scenario_counts: Counter[str] = Counter()
    for capability in capabilities:
        execution = capability.get("execution")
        scenario = capability.get("rust_e2e")
        ident = capability.get("id", "<missing-id>")
        if execution == "browser_storage":
            if scenario:
                fail(f"browser-storage capability {ident} must be deferred to Pass 3")
            deferred += 1
            continue
        if not isinstance(scenario, str) or not scenario.strip():
            fail(f"Rust-testable capability {ident} has no rust_e2e mapping")
        if scenario not in functions:
            fail(f"capability {ident} maps to missing Rust E2E function {scenario}")
        rust_symbol = capability.get("rust_symbol")
        if isinstance(rust_symbol, str) and "::" in rust_symbol:
            method = rust_symbol.rsplit("::", 1)[1]
            path, scenario_source = scenario_files[scenario]
            probe = re.compile(rf"(?:\.|::){re.escape(method)}\s*\(")
            if not probe.search(scenario_source):
                fail(
                    f"capability {ident} maps to {scenario}, but {path.name} does not "
                    f"exercise method {method}()"
                )
        mapped += 1
        scenario_counts[scenario] += 1

    unused = sorted(functions - set(scenario_counts))
    if unused:
        fail("unregistered Rust E2E scenario(s): " + ", ".join(unused))

    live = sum(1 for item in capabilities if item.get("execution") == "public_standard")
    funded_standard = sum(1 for item in capabilities if item.get("execution") == "funded_standard")
    funded_covenant = sum(1 for item in capabilities if item.get("execution") == "funded_covenant")
    offline = sum(1 for item in capabilities if item.get("execution") == "offline")
    print("RUST E2E COVERAGE CHECK: PASS")
    print(f"  Rust-testable capabilities mapped: {mapped}/{len(capabilities) - deferred}")
    print(f"  Offline capabilities: {offline}")
    print(f"  Public standard-network capabilities: {live}")
    print(f"  Funded standard-network capabilities: {funded_standard}")
    print(f"  Funded covenant-network capabilities: {funded_covenant}")
    print(f"  Browser-storage capabilities deferred to Pass 3: {deferred}")
    print(f"  Rust E2E scenario functions: {len(functions)}")


if __name__ == "__main__":
    main()
