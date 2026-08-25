#!/usr/bin/env python3
"""Verify every public capability has an executable resource/lifecycle profile."""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
CAPABILITIES = ROOT / "qa/e2e/capabilities.toml"
PROFILES = ROOT / "qa/resource/profiles.toml"
NATIVE = ROOT / "qa/src/resource_probe/mod.rs"
BROWSER = ROOT / "qa/e2e/browser/resource/scenarios.mjs"

errors = []

def fail(message: str) -> None:
    errors.append(message)

from check_capability_parity import load_registry

def load_profiles(path: Path):
    profiles = []
    current = None
    for source in path.read_text(encoding="utf-8").splitlines():
        line = source.strip()
        if not line or line.startswith("#"):
            continue
        if line == "[[profile]]":
            current = {}
            profiles.append(current)
            continue
        if current is None or "=" not in line:
            continue
        key, raw = (part.strip() for part in line.split("=", 1))
        if raw.startswith(chr(34)) and raw.endswith(chr(34)):
            value = raw[1:-1]
        else:
            if raw in ("true", "false"):
                value = raw == "true"
            else:
                try:
                    value = int(raw)
                except ValueError:
                    value = float(raw)
        current[key] = value
    return profiles

capabilities = load_registry(CAPABILITIES).get("capability", [])
profiles = load_profiles(PROFILES)
by_name = {}
for profile in profiles:
    name = profile.get("name")
    if not isinstance(name, str) or not name:
        fail("resource profile is missing a non-empty name")
        continue
    if name in by_name:
        fail(f"duplicate resource profile: {name}")
    by_name[name] = profile

native_text = NATIVE.read_text(errors="replace") if NATIVE.is_file() else ""
browser_text = BROWSER.read_text(errors="replace") if BROWSER.is_file() else ""

for capability in capabilities:
    capability_id = capability.get("id", "<missing-id>")
    profile_name = capability.get("resource_profile")
    if profile_name not in by_name:
        fail(f"{capability_id}: unknown resource_profile {profile_name!r}")
        continue
    profile = by_name[profile_name]
    browser_scenario = profile.get("browser_scenario")
    if not browser_scenario:
        fail(f"{capability_id}: profile {profile_name} has no browser_scenario")
    elif not re.search(rf"\bexport\s+async\s+function\s+{re.escape(browser_scenario)}\b", browser_text):
        fail(f"{capability_id}: browser resource scenario does not exist: {browser_scenario}")

    native_scenario = profile.get("native_scenario")
    if capability.get("execution") != "browser_storage":
        if not native_scenario:
            fail(f"{capability_id}: profile {profile_name} has no native_scenario")
        elif not re.search(rf'"{re.escape(native_scenario)}"\s*=>', native_text):
            fail(f"{capability_id}: native resource scenario does not exist: {native_scenario}")

for name, profile in by_name.items():
    browser_scenario = profile.get("browser_scenario")
    if not browser_scenario:
        fail(f"profile {name}: browser_scenario is required")
    elif not re.search(
        rf"\bexport\s+async\s+function\s+{re.escape(browser_scenario)}\b",
        browser_text,
    ):
        fail(f"profile {name}: browser resource scenario does not exist: {browser_scenario}")
    native_scenario = profile.get("native_scenario")
    if native_scenario and not re.search(rf'"{re.escape(native_scenario)}"\s*=>', native_text):
        fail(f"profile {name}: native resource scenario does not exist: {native_scenario}")

    for field in ("quick_warmup", "quick_batches", "quick_iterations_per_batch", "soak_warmup", "soak_batches", "soak_iterations_per_batch"):
        value = profile.get(field)
        if not isinstance(value, int) or value < 1:
            fail(f"profile {name}: {field} must be a positive integer")
    for field in ("max_browser_heap_growth_bytes", "max_browser_heap_slope_bytes_per_batch", "max_browser_backing_growth_bytes", "max_browser_backing_slope_bytes_per_batch", "max_browser_dom_growth"):
        value = profile.get(field)
        if not isinstance(value, int) or value < 0:
            fail(f"profile {name}: {field} must be a non-negative integer")
    if profile.get("native_scenario"):
        for field in ("max_rss_growth_bytes", "max_rss_slope_bytes_per_batch", "max_thread_growth", "max_handle_or_fd_growth"):
            value = profile.get(field)
            if not isinstance(value, int) or value < 0:
                fail(f"profile {name}: {field} must be a non-negative integer")
        idle = profile.get("max_idle_cpu_ratio")
        if not isinstance(idle, (int, float)) or not 0 <= idle <= 1:
            fail(f"profile {name}: max_idle_cpu_ratio must be in 0..=1")

used = {capability.get("resource_profile") for capability in capabilities}
for name in sorted(set(by_name) - used):
    if not by_name[name].get("supplemental", False):
        fail(f"resource profile is not assigned to any capability: {name}")

if errors:
    print("RESOURCE COVERAGE CHECK: FAIL")
    for error in errors:
        print("ERROR:", error)
    sys.exit(1)

print("RESOURCE COVERAGE CHECK: PASS")
print(f"Capabilities with resource profiles: {len(capabilities)}/{len(capabilities)}")
print(f"Resource profiles: {len(by_name)}")
print("Profiles:", ", ".join(sorted(by_name)))
