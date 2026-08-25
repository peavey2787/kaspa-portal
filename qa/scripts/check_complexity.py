#!/usr/bin/env python3
"""Conservative source-level cyclomatic-complexity estimator.

This is a toolchain-independent guard used when Cargo coverage tooling is not
available. It intentionally checks every production Rust function; unit tests
are excluded because CRAP/coverage quality is enforced separately when Cargo
is present.
"""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
LIMIT = 12
FUNCTION = re.compile(r'\b(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z0-9_]+)[^{]*\{')
DECISIONS = re.compile(r'\bif\b|\bwhile\b|\bfor\b|\bmatch\b|&&|\|\|')
COMMENTS_AND_STRINGS = re.compile(r'//.*|/\*.*?\*/|"(?:\\.|[^"\\])*"', re.S)
violations = []
checked = 0

for path in (ROOT / 'src').rglob('*.rs'):
    if 'unit-tests' in path.parts or path.name == 'wordlist.rs':
        continue
    text = path.read_text(errors='replace')
    for match in FUNCTION.finditer(text):
        depth = 0
        end = None
        for index in range(match.end() - 1, len(text)):
            if text[index] == '{':
                depth += 1
            elif text[index] == '}':
                depth -= 1
                if depth == 0:
                    end = index + 1
                    break
        if end is None:
            continue
        body = COMMENTS_AND_STRINGS.sub('', text[match.end():end])
        complexity = 1 + len(DECISIONS.findall(body))
        checked += 1
        if complexity > LIMIT:
            violations.append((complexity, path.relative_to(ROOT), match.group(1)))

if violations:
    print('COMPLEXITY CHECK: FAIL')
    for complexity, path, name in sorted(violations, reverse=True):
        print(f'CC~{complexity}: {path}::{name}')
    sys.exit(1)

print(f'COMPLEXITY CHECK: PASS ({checked} production functions <= {LIMIT} estimated CC)')
