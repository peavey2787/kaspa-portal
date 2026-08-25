#!/usr/bin/env python3
"""Detect exact or substantial copy/paste duplication in production Rust."""
from pathlib import Path
import hashlib
import re
import sys
from collections import defaultdict

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
BLOCK_LINES = 14
MIN_BLOCK_CHARS = 320
errors = []

sources = []
for path in SRC.rglob("*.rs"):
    if "unit-tests" in path.parts or path.name == "wordlist.rs":
        continue
    text = path.read_text(errors="replace")
    # Remove comments and collapse whitespace for whole-file duplicate checks.
    logical = re.sub(r"//.*?$|/\*.*?\*/", "", text, flags=re.M | re.S)
    logical = re.sub(r"\s+", " ", logical).strip()
    sources.append((path, text, logical))

whole = defaultdict(list)
for path, _text, logical in sources:
    if len(logical) >= MIN_BLOCK_CHARS:
        whole[hashlib.sha256(logical.encode()).hexdigest()].append(path)
for paths in whole.values():
    if len(paths) > 1:
        errors.append("exact duplicated production files: " + ", ".join(str(p.relative_to(ROOT)) for p in paths))

# Sliding nonblank source windows catch large copy/paste regions while ignoring
# tiny wrappers, declarations, and repeated error idioms.
blocks = defaultdict(list)
for path, text, _logical in sources:
    lines = [re.sub(r"//.*$", "", line).strip() for line in text.splitlines()]
    lines = [line for line in lines if line]
    seen_here = set()
    for i in range(0, max(0, len(lines) - BLOCK_LINES + 1)):
        block = " ".join(lines[i:i + BLOCK_LINES])
        normalized = re.sub(r"\s+", " ", block)
        if len(normalized) < MIN_BLOCK_CHARS:
            continue
        digest = hashlib.sha256(normalized.encode()).hexdigest()
        if digest in seen_here:
            continue
        seen_here.add(digest)
        blocks[digest].append((path, i + 1))
for occurrences in blocks.values():
    unique_files = {path for path, _line in occurrences}
    if len(unique_files) > 1:
        sample = occurrences[:4]
        errors.append("duplicated 14-line production region: " + ", ".join(f"{p.relative_to(ROOT)}~{line}" for p, line in sample))

if errors:
    print("DUPLICATION CHECK: FAIL")
    for error in errors[:50]:
        print("ERROR:", error)
    if len(errors) > 50:
        print(f"ERROR: ... {len(errors)-50} additional duplicate regions")
    sys.exit(1)
print(f"DUPLICATION CHECK: PASS ({len(sources)} production Rust files scanned)")
