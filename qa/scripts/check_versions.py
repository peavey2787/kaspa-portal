#!/usr/bin/env python3
"""Enforce package and Kaspa Portal-owned format versions."""
from pathlib import Path
import sys
sys.dont_write_bytecode = True
from manifest import read_package

ROOT = Path(__file__).resolve().parents[2]
errors = []


def fail(message: str) -> None:
    errors.append(message)


for path in [ROOT / "Cargo.toml", ROOT / "qa/Cargo.toml", ROOT / "qa/benches/Cargo.toml", ROOT / "qa/tests/fuzz/Cargo.toml"]:
    package = read_package(path)
    if package.get("version") != "1.0.1":
        fail(f"package must be 1.0.1: {path.relative_to(ROOT)}")

required_markers = {
    "src/transaction/interchange/kspt/format.rs": [
        "KSPT_VERSION_CURRENT: u8 = 0x01",
        "KSSN_VERSION_CURRENT: u8 = 0x01",
    ],
    "src/transaction/interchange/pskt/standard/parser/mod.rs": ["PSKT_VERSION: u64 = 1"],
    "src/transaction/interchange/qr/frame.rs": ["FRAME_VERSION: u8 = 1"],
    "src/transaction/signing/anti_klepto/protocol.rs": ["pub const VERSION: u8 = 1"],
    "src/transaction/signing/covenant/protocol/mod.rs": ["pub const VERSION: u8 = 1"],
    "src/transaction/signing/covenant/protocol/private_swap.rs": ["pub const VERSION: u8 = 1"],
    "src/randomness/beacon/mod.rs": ["BEACON_PROOF_VERSION: u16 = 1"],
    "src/indexer/storage/mod.rs": ["INDEXER_STATE_SCHEMA: u32 = 1"],
    "src/platform/browser/indexed_db.rs": ["INDEX_DB_VERSION: u32 = 1"],
}
for rel, markers in required_markers.items():
    path = ROOT / rel
    if not path.is_file():
        fail(f"missing versioned source: {rel}")
        continue
    text = path.read_text(errors="replace")
    for marker in markers:
        if marker not in text:
            fail(f"owned format must be v1 in {rel}: missing `{marker}`")

forbidden_markers = (
    "KSPT_GENERATION_CURRENT",
    "KSPT_V4",
    "COMPACT_KSPT_V4",
    "generation-4",
    "generation 4",
    "Private Swap v2",
    "CrowdfundV2",
    "anti-klepto v2",
    "canonical public wire version 2",
)
for root in (ROOT / "src", ROOT / "qa/tests", ROOT / "qa/benches", ROOT / "examples"):
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix not in {".rs", ".py", ".sh", ".toml", ".js", ".mjs", ".md"}:
            continue
        text = path.read_text(errors="replace")
        for marker in forbidden_markers:
            if marker in text:
                fail(f"disallowed version marker `{marker}` remains in {path.relative_to(ROOT)}")


if errors:
    print("VERSION CHECK: FAIL")
    for error in errors:
        print("ERROR:", error)
    sys.exit(1)
print("VERSION CHECK: PASS")
print("Kaspa Portal packages and project-owned public formats are v1")
