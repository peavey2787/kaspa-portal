#!/usr/bin/env python3
"""Mutation gate for Kaspa Portal's security-critical code.

  run   [--shard K/N]       run cargo-mutants over `.cargo/mutants.toml`
  check OUTCOMES.json ...   aggregate shard outcomes and enforce the gate

The gate: every viable mutant must be caught (100%), none may time out, and an
uncaught mutant is accepted only through a reviewed entry in
`qa/mutation/equivalent_mutants.json` whose `source_sha256` still matches the
mutated file, so an approval lapses as soon as that code changes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EQUIVALENTS = ROOT / "qa/mutation/equivalent_mutants.json"
CARGO_MUTANTS_VERSION = "27.1.0"


def run(shard: str | None, output: Path) -> int:
    version = subprocess.run(
        ["cargo", "mutants", "--version"], capture_output=True, text=True, check=False
    ).stdout.split()
    if CARGO_MUTANTS_VERSION not in version:
        print(f"ERROR: cargo-mutants {CARGO_MUTANTS_VERSION} is required, found {version}")
        return 2
    output.mkdir(parents=True, exist_ok=True)
    command = ["cargo", "mutants", "--no-shuffle", "--output", str(output), "--", "--lib"]
    if shard:
        command[3:3] = ["--shard", shard]
    # cargo-mutants exits non-zero when mutants survive; the gate below decides.
    subprocess.run(command, cwd=ROOT, check=False)
    return 0


def sha256(relative: str) -> str:
    return hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()


def mutant_key(mutant: dict) -> tuple[str, str, str]:
    function = (mutant.get("function") or {}).get("function_name", "")
    return mutant["file"].replace("\\", "/"), function, mutant.get("replacement", "")


def load_equivalents() -> dict[tuple[str, str, str], dict]:
    if not EQUIVALENTS.is_file():
        return {}
    entries = json.loads(EQUIVALENTS.read_text(encoding="utf-8"))["equivalent_mutants"]
    return {(e["file"], e["function"], e["replacement"]): e for e in entries}


def check(paths: list[Path]) -> int:
    equivalents = load_equivalents()
    counts = {"caught": 0, "missed": 0, "timeout": 0, "unviable": 0, "equivalent": 0}
    errors: list[str] = []
    used: set[tuple[str, str, str]] = set()
    for path in paths:
        document = json.loads(path.read_text(encoding="utf-8"))
        for outcome in document.get("outcomes", []):
            scenario = outcome.get("scenario")
            if not isinstance(scenario, dict) or "Mutant" not in scenario:
                if outcome.get("summary") not in ("Success", None):
                    errors.append(f"baseline did not pass in {path}: {outcome.get('summary')}")
                continue
            mutant = scenario["Mutant"]
            summary = outcome.get("summary")
            if summary == "CaughtMutant":
                counts["caught"] += 1
            elif summary == "Unviable":
                counts["unviable"] += 1
            elif summary == "Timeout":
                counts["timeout"] += 1
                errors.append(f"timeout: {describe(mutant)}")
            else:
                key = mutant_key(mutant)
                entry = equivalents.get(key)
                if entry and entry.get("source_sha256") == sha256(key[0]):
                    counts["equivalent"] += 1
                    used.add(key)
                else:
                    counts["missed"] += 1
                    errors.append(f"missed: {describe(mutant)}")
    for key, entry in equivalents.items():
        if key not in used:
            errors.append(f"stale equivalent-mutant approval: {key}")
        for field in ("justification", "refactor_attempted"):
            if not str(entry.get(field, "")).strip():
                errors.append(f"equivalent-mutant approval lacks {field}: {key}")
    viable = counts["caught"] + counts["missed"] + counts["timeout"]
    score = 100.0 if viable == 0 else 100.0 * counts["caught"] / viable
    print(json.dumps({**counts, "score_percent": round(score, 4)}, sort_keys=True))
    if viable == 0:
        errors.append("mutation run produced no viable mutants")
    for error in errors:
        print(f"ERROR: {error}")
    if errors:
        return 1
    print(f"PASS: mutation gate caught {counts['caught']}/{viable} viable mutants")
    return 0


def describe(mutant: dict) -> str:
    file, function, replacement = mutant_key(mutant)
    span = mutant.get("span", {}).get("start", {}).get("line", "?")
    return f"{file}:{span} {function} -> {replacement}"


def main() -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    run_parser = commands.add_parser("run")
    run_parser.add_argument("--shard")
    run_parser.add_argument("--output", type=Path, default=ROOT / "target/qa/mutation")
    check_parser = commands.add_parser("check")
    check_parser.add_argument("outcomes", type=Path, nargs="+")
    args = parser.parse_args()
    if args.command == "run":
        return run(args.shard, args.output)
    return check(args.outcomes)


if __name__ == "__main__":
    sys.exit(main())
