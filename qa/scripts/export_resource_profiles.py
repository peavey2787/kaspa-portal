#!/usr/bin/env python3
"""Export TOML resource budgets as JSON for the browser runner."""
from pathlib import Path
import argparse
import json

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser()
parser.add_argument("--mode", choices=("quick", "soak"), required=True)
parser.add_argument("--output", required=True)
args = parser.parse_args()
profile_path = ROOT / "qa/resource/profiles.toml"
items = []
current = None
for source in profile_path.read_text(encoding="utf-8").splitlines():
    line = source.strip()
    if not line or line.startswith("#"):
        continue
    if line == "[[profile]]":
        current = {}
        items.append(current)
        continue
    if current is None or "=" not in line:
        continue
    key, raw = (part.strip() for part in line.split("=", 1))
    if raw.startswith(chr(34)) and raw.endswith(chr(34)):
        value = raw[1:-1]
    elif raw in ("true", "false"):
        value = raw == "true"
    else:
        try:
            value = int(raw)
        except ValueError:
            try:
                value = float(raw)
            except ValueError as error:
                raise ValueError(
                    f"unsupported resource profile scalar for {key}: {raw!r}"
                ) from error
    current[key] = value
profiles = {}
for item in items:
    prefix = "quick" if args.mode == "quick" else "soak"
    profiles[item["name"]] = {
        "name": item["name"],
        "warmup": item[f"{prefix}_warmup"],
        "batches": item[f"{prefix}_batches"],
        "iterationsPerBatch": item[f"{prefix}_iterations_per_batch"],
        "maxIdleCpuRatio": item.get("max_idle_cpu_ratio", 0.10),
        "maxHeapGrowthBytes": item["max_browser_heap_growth_bytes"],
        "maxHeapSlopeBytesPerBatch": item["max_browser_heap_slope_bytes_per_batch"],
        "maxBackingGrowthBytes": item["max_browser_backing_growth_bytes"],
        "maxBackingSlopeBytesPerBatch": item["max_browser_backing_slope_bytes_per_batch"],
        "maxDomGrowth": item["max_browser_dom_growth"],
    }
Path(args.output).write_text(json.dumps({"mode": args.mode, "profiles": profiles}, indent=2) + "\n")
