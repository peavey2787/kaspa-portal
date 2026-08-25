#!/usr/bin/env python3
"""Enforce kaspa-portal's capability-oriented dependency direction."""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
DOMAINS = {
    "primitives", "crypto", "network", "chain", "wallet", "transaction",
    "contract", "privacy", "indexer", "randomness", "platform", "portal",
}
ALLOWED = {
    "primitives": set(),
    "crypto": {"primitives"},
    "network": {"primitives"},
    "chain": {"network", "primitives"},
    "wallet": {"chain", "crypto", "primitives"},
    "contract": {"crypto", "primitives"},
    "privacy": {"wallet", "crypto", "primitives"},
    "indexer": {"primitives"},
    "randomness": {"crypto", "primitives"},
    "transaction": {"chain", "contract", "crypto", "network", "primitives", "wallet"},
    "platform": DOMAINS - {"platform", "portal"},
    "portal": DOMAINS - {"portal"},
}
LEGACY = re.compile(r"\b(?:offline[_-]signer|online[_-]watcher|shared[_-]signer|WatchWallet|watcher\(\)|signer\(\))\b", re.I)
USE_GROUP = re.compile(r"use\s+crate::\{(.*?)\};", re.S)
DIRECT = re.compile(r"crate::([A-Za-z_][A-Za-z0-9_]*)")
errors = []

def dependencies(text: str):
    deps = {m.group(1) for m in DIRECT.finditer(text) if m.group(1) in DOMAINS}
    for match in USE_GROUP.finditer(text):
        group = match.group(1)
        for domain in DOMAINS:
            if re.search(rf"(?<![A-Za-z0-9_]){re.escape(domain)}(?=\s*(?:::|,|\}}))", group):
                deps.add(domain)
    return deps

for domain in sorted(DOMAINS):
    path = SRC / domain
    if not path.is_dir():
        errors.append(f"missing domain directory src/{domain}")
        continue
    observed = set()
    for source in path.rglob("*.rs"):
        if "unit-tests" in source.parts:
            continue
        text = source.read_text(errors="replace")
        observed |= dependencies(text) - {domain}
        if LEGACY.search(text):
            errors.append(f"obsolete role terminology in {source.relative_to(ROOT)}")
        if domain != "platform" and ("web_sys::" in text or "js_sys::" in text or "wasm_bindgen::" in text):
            errors.append(f"browser implementation leaked into {source.relative_to(ROOT)}")
    disallowed = observed - ALLOWED[domain]
    if disallowed:
        errors.append(
            f"src/{domain} has disallowed domain dependencies: {', '.join(sorted(disallowed))}; "
            f"allowed: {', '.join(sorted(ALLOWED[domain])) or '(none)'}"
        )

# Platform-specific implementation must not be imported by core domains.
for source in SRC.rglob("*.rs"):
    if source.parts[len(SRC.parts)] in {"platform", "portal"}:
        continue
    text = source.read_text(errors="replace")
    if re.search(r"crate::platform(?:::|\b)", text):
        errors.append(f"core domain imports platform adapter: {source.relative_to(ROOT)}")

if errors:
    print("ARCHITECTURE CHECK: FAIL")
    for error in errors:
        print("ERROR:", error)
    sys.exit(1)
print("ARCHITECTURE CHECK: PASS")
for domain in sorted(DOMAINS):
    print(f"  {domain} -> {', '.join(sorted(ALLOWED[domain])) or '(leaf)'}")
