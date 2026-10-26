#!/usr/bin/env python3
"""Fail on any RustSec advisory, including warnings, in every committed lockfile."""
from pathlib import Path
import shutil
import subprocess
import sys
sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[2]
CARGO_AUDIT_VERSION = "0.22.2"

# Every accepted advisory names why it cannot reach a shipped binary.
ACCEPTED_ADVISORIES = {
    # derivative is unmaintained; it is a proc-macro that arkworks 0.6 runs
    # at compile time and contributes no runtime code.
    "RUSTSEC-2024-0388",
}


def lockfiles() -> list[Path]:
    listed = subprocess.run(
        ["git", "ls-files", "*Cargo.lock"],
        cwd=ROOT, check=True, capture_output=True, text=True,
    ).stdout.split()
    return [ROOT / path for path in listed]


def installed_version() -> str:
    if shutil.which("cargo-audit") is None:
        return ""
    output = subprocess.run(
        ["cargo", "audit", "--version"], check=True, capture_output=True, text=True,
    ).stdout
    return output.split()[-1]


def audit(lockfile: Path) -> bool:
    command = ["cargo", "audit", "--deny", "warnings", "--file", str(lockfile)]
    for advisory in sorted(ACCEPTED_ADVISORIES):
        command += ["--ignore", advisory]
    print(f"==> cargo audit {lockfile.relative_to(ROOT)}", flush=True)
    return subprocess.run(command, cwd=ROOT).returncode == 0


def main() -> int:
    version = installed_version()
    if version != CARGO_AUDIT_VERSION:
        print(f"cargo-audit {CARGO_AUDIT_VERSION} is required (found {version or 'none'}): "
              f"cargo install cargo-audit --version {CARGO_AUDIT_VERSION} --locked")
        return 1
    failed = [lock for lock in lockfiles() if not audit(lock)]
    for lock in failed:
        print(f"dependency advisory gate failed: {lock.relative_to(ROOT)}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
