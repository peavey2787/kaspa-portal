#!/usr/bin/env python3
"""Source-shape guardrails for SRP and navigability."""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
MAX_PRODUCTION_LINES = 500
MAX_DIRECT_RUST_FILES = 12
MAX_FACADE_LINES = 360
errors = []

for path in SRC.rglob("*.rs"):
    if "unit-tests" in path.parts or path.name == "wordlist.rs":
        continue
    lines = path.read_text(errors="replace").splitlines()
    if len(lines) > MAX_PRODUCTION_LINES:
        errors.append(f"production file exceeds {MAX_PRODUCTION_LINES} lines: {path.relative_to(ROOT)} ({len(lines)})")
    if path.name == "facade.rs" and len(lines) > MAX_FACADE_LINES:
        errors.append(f"facade exceeds {MAX_FACADE_LINES} lines: {path.relative_to(ROOT)} ({len(lines)})")

for directory in SRC.rglob("*"):
    if not directory.is_dir() or "unit-tests" in directory.parts:
        continue
    files = [p for p in directory.iterdir() if p.is_file() and p.suffix == ".rs"]
    if len(files) > MAX_DIRECT_RUST_FILES:
        errors.append(f"folder has {len(files)} direct Rust files (> {MAX_DIRECT_RUST_FILES}): {directory.relative_to(ROOT)}")

# Any colocated unit-test directory uses the agreed literal spelling and has
# at least one real #[path] target pointing into it. A directory can serve
# several sibling modules (for example indexer/config.rs and engine.rs).
path_attr = re.compile(r'#\s*\[\s*path\s*=\s*"([^"]+)"\s*\]')
wired_test_dirs = set()
for source in SRC.rglob("*.rs"):
    text = source.read_text(errors="replace")
    for target in path_attr.findall(text):
        resolved = (source.parent / target).resolve()
        for parent in resolved.parents:
            if parent.name == "unit-tests":
                wired_test_dirs.add(parent)
                break

for directory in SRC.rglob("*"):
    if not directory.is_dir():
        continue
    if directory.name == "unit_tests":
        errors.append(f"unit test directory must be named unit-tests: {directory.relative_to(ROOT)}")
    if directory.name == "unit-tests" and directory.resolve() not in wired_test_dirs:
        errors.append(f"unit-tests directory is not wired by #[path]: {directory.relative_to(ROOT)}")

# Production source must not suppress dead/unused/deprecated warnings locally.
SUPPRESS = re.compile(r"#\s*!?\[\s*allow\s*\([^)]*\b(?:dead_code|unused|deprecated)\b", re.S)
for path in SRC.rglob("*.rs"):
    if "unit-tests" in path.parts:
        continue
    if SUPPRESS.search(path.read_text(errors="replace")):
        errors.append(f"production lint suppression hides dead/unused/deprecated code: {path.relative_to(ROOT)}")

if errors:
    print("SRP CHECK: FAIL")
    for error in errors:
        print("ERROR:", error)
    sys.exit(1)
print("SRP CHECK: PASS")
