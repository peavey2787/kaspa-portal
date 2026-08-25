#!/usr/bin/env python3
"""Remove only extensionless root files produced by the old CMD progress-arrow bug."""

from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]

KNOWN_ARTIFACTS = {
    "Kaspa": "== Portal static QA",
    "Windows": "== low-memory Cargo settings: 1 job, debug info off, incremental off",
    "Rust": "== compile/test QA",
    "WASM": "== compile QA",
    "Formatting": "== QA",
}

removed = []
for name, expected in KNOWN_ARTIFACTS.items():
    path = ROOT / name
    if not path.is_file():
        continue
    try:
        contents = path.read_text(errors="strict").strip()
    except (OSError, UnicodeError):
        continue
    if contents == expected:
        path.unlink()
        removed.append(name)

if removed:
    print("Removed legacy Windows progress artifact(s): " + ", ".join(removed))
