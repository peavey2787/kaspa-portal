#!/usr/bin/env python3
"""Resolve/prompt the E2E network split and emit environment assignments.

Ordinary/non-covenant live workflows use the selected standard network.
Covenant workflows use the independently configured covenant network.
The parser is dependency-free so it works on the repository's Python 3.8 floor.
"""
from pathlib import Path
import argparse
import json
import os
import random
import re
import sys
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "qa/e2e/networks.toml"
NETWORK_RE = re.compile(r"^testnet-([1-9][0-9]{0,2})$")
HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")

# Mirrors the public resolver groups shipped by rusty-kaspa. The resolver
# returns a current wRPC node for the requested network and provides the
# load-balancing/failover layer that a single hard-coded public node cannot.
PUBLIC_RESOLVERS = [
    "https://eric.kaspa.stream",
    "https://maxim.kaspa.stream",
    "https://john.kaspa.red",
    "https://mike.kaspa.red",
    "https://jake.kaspa.green",
    "https://mark.kaspa.green",
    "https://noah.kaspa.blue",
    "https://ryan.kaspa.blue",
]
RESOLVER_VERSION = 2
RESOLVER_TIMEOUT_SECONDS = 3.0


def parse_scalar(raw):
    raw = raw.strip()
    if len(raw) >= 2 and raw[0] == raw[-1] == '"':
        return raw[1:-1]
    if raw == "true":
        return True
    if raw == "false":
        return False
    try:
        return int(raw)
    except ValueError:
        raise ValueError(f"unsupported networks.toml scalar: {raw!r}")


def read_config(path):
    root = {}
    sections = {"": root}
    current = root
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            name = line[1:-1].strip()
            current = sections.setdefault(name, {})
            continue
        if "=" not in line:
            raise ValueError(f"invalid networks.toml line: {raw_line}")
        key, value = (part.strip() for part in line.split("=", 1))
        current[key] = parse_scalar(value)
    defaults = sections.get("defaults", {})
    profiles = {
        name[len("network."):]: values
        for name, values in sections.items()
        if name.startswith("network.")
    }
    return root, defaults, profiles


def normalize_network(value):
    value = value.strip().lower()
    if value.startswith("kaspa:"):
        value = value[6:]
    if value in ("mainnet", "simnet", "devnet"):
        return value
    compact = re.fullmatch(r"testnet-?(\d+)", value)
    if not compact:
        raise ValueError("network must be mainnet, simnet, devnet, or testnet-N")
    suffix = int(compact.group(1))
    if not 1 <= suffix <= 127:
        raise ValueError("testnet suffix must be 1..=127")
    return f"testnet-{suffix}"


def stderr(message=""):
    print(message, file=sys.stderr, flush=True)


def ask(message):
    sys.stderr.write(message)
    sys.stderr.flush()
    value = sys.stdin.readline()
    if value == "":
        raise EOFError("input closed while selecting E2E network")
    return value.strip()


def ask_network(default_network):
    stderr("")
    stderr("Kaspa E2E ordinary/non-covenant network:")
    stderr("  1. testnet-10 (recommended/default)")
    stderr("  2. testnet-12")
    stderr("  3. mainnet (read-only unless mainnet spending is explicitly enabled)")
    stderr("  4. custom")
    while True:
        default_hint = "1" if default_network == "testnet-10" else default_network
        choice = ask(f"Which would you like to use? [{default_hint}] ")
        if not choice:
            return default_network
        if choice == "1":
            return "testnet-10"
        if choice == "2":
            return "testnet-12"
        if choice == "3":
            return "mainnet"
        if choice == "4":
            while True:
                try:
                    return normalize_network(ask("Custom network (for example testnet-14): "))
                except ValueError as error:
                    stderr(f"ERROR: {error}")
        stderr("Please enter 1, 2, 3, or 4.")


def env_name(role, field):
    return f"KASPA_PORTAL_E2E_{role.upper()}_{field.upper()}"


def resolve_public_wrpc(network):
    urls = list(PUBLIC_RESOLVERS)
    random.SystemRandom().shuffle(urls)
    errors = []
    for base in urls:
        url = f"{base}/v{RESOLVER_VERSION}/kaspa/{network}/tls/wrpc/borsh"
        request = urllib.request.Request(
            url,
            headers={"Accept": "application/json", "User-Agent": "kaspa-portal-e2e/1.0"},
        )
        try:
            with urllib.request.urlopen(request, timeout=RESOLVER_TIMEOUT_SECONDS) as response:
                payload = json.loads(response.read().decode("utf-8"))
            endpoint = str(payload.get("url", "")).strip() if isinstance(payload, dict) else ""
            if endpoint.startswith(("ws://", "wss://")):
                return endpoint, base
            errors.append(f"{base}: resolver response did not contain a WebSocket URL")
        except (OSError, ValueError, urllib.error.URLError) as error:
            errors.append(f"{base}: {error}")
    raise ValueError("Kaspa public resolver lookup failed: " + " | ".join(errors))


def resolve_profile(role, network, profiles, interactive):
    profile = dict(profiles.get(network, {}))
    legacy_endpoint = os.environ.get("KASPA_PORTAL_E2E_ENDPOINT") if role == "standard" else None
    overrides = {
        "wrpc_endpoint": os.environ.get(env_name(role, "endpoint")) or legacy_endpoint,
        "rest_endpoint": os.environ.get(env_name(role, "rest_endpoint")),
        "faucet": os.environ.get(env_name(role, "faucet")),
        "genesis_hash": os.environ.get(env_name(role, "genesis_hash")),
    }
    for key, value in overrides.items():
        if value is not None:
            profile[key] = value

    if not profile.get("wrpc_endpoint"):
        if not interactive:
            raise ValueError(
                f"{network} has no configured wRPC endpoint; set {env_name(role, 'endpoint')}"
            )
        profile["wrpc_endpoint"] = ask(
            f"wRPC endpoint for {network} (ws://, wss://, or resolver): "
        )

    endpoint = str(profile["wrpc_endpoint"]).strip()
    if endpoint == "resolver":
        try:
            endpoint, resolver = resolve_public_wrpc(network)
            stderr(f"Resolved {network} public wRPC through {resolver}: {endpoint}")
        except ValueError as error:
            fallback = str(profile.get("wrpc_fallback", "")).strip()
            if not fallback:
                raise
            stderr(f"WARNING: {error}")
            stderr(f"Falling back to configured {network} wRPC endpoint: {fallback}")
            endpoint = fallback
        profile["wrpc_endpoint"] = endpoint

    if not endpoint.startswith(("ws://", "wss://")):
        raise ValueError(f"{role} endpoint must use ws:// or wss://")

    if not profile.get("genesis_hash"):
        if not interactive:
            raise ValueError(
                f"{network} has no configured genesis hash; set {env_name(role, 'genesis_hash')}"
            )
        profile["genesis_hash"] = ask(f"64-hex genesis hash for {network}: ")
    genesis = str(profile["genesis_hash"]).strip()
    if not HEX64_RE.fullmatch(genesis):
        raise ValueError(f"{role} genesis hash must be exactly 64 hexadecimal characters")

    if "faucet" not in profile:
        if interactive and network.startswith("testnet-"):
            profile["faucet"] = ask(f"Faucet URL for {network} (optional): ")
        else:
            profile["faucet"] = ""
    if "rest_endpoint" not in profile:
        profile["rest_endpoint"] = ""
    if "funded_spending" not in profile:
        profile["funded_spending"] = network.startswith("testnet-")

    return profile


def assignment_text(assignments):
    lines = []
    for key, value in assignments.items():
        text = str(value)
        if "\n" in text or "\r" in text or "=" in key:
            raise ValueError(f"unsafe environment assignment for {key}")
        lines.append(f"{key}={text}")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--prompt", action="store_true", help="prompt for the ordinary network when not overridden")
    parser.add_argument("--no-prompt", action="store_true", help="use env/config only")
    parser.add_argument("--output", help="write environment assignments to this file instead of stdout")
    args = parser.parse_args()

    _, defaults, profiles = read_config(CONFIG)
    standard_default = normalize_network(str(defaults.get("standard_network", "testnet-10")))
    covenant_default = normalize_network(str(defaults.get("covenant_network", "testnet-12")))

    standard_env = os.environ.get("KASPA_PORTAL_E2E_STANDARD_NETWORK")
    covenant_env = os.environ.get("KASPA_PORTAL_E2E_COVENANT_NETWORK")
    no_prompt = args.no_prompt or os.environ.get("KASPA_PORTAL_E2E_NO_NETWORK_PROMPT") == "1"
    interactive = not no_prompt and (args.prompt or sys.stdin.isatty())

    if standard_env:
        standard = normalize_network(standard_env)
    elif args.prompt and interactive:
        standard = ask_network(standard_default)
    else:
        standard = standard_default
    covenant = normalize_network(covenant_env or covenant_default)

    standard_profile = resolve_profile("standard", standard, profiles, interactive)
    covenant_profile = resolve_profile("covenant", covenant, profiles, interactive)

    assignments = {"KASPA_PORTAL_E2E_NETWORKS_RESOLVED": "1"}
    for role, network, profile in (
        ("standard", standard, standard_profile),
        ("covenant", covenant, covenant_profile),
    ):
        prefix = f"KASPA_PORTAL_E2E_{role.upper()}"
        assignments[f"{prefix}_NETWORK"] = network
        assignments[f"{prefix}_ENDPOINT"] = profile["wrpc_endpoint"]
        assignments[f"{prefix}_REST_ENDPOINT"] = profile.get("rest_endpoint", "")
        assignments[f"{prefix}_FAUCET"] = profile.get("faucet", "")
        assignments[f"{prefix}_GENESIS_HASH"] = str(profile["genesis_hash"]).lower()
        assignments[f"{prefix}_FUNDED_SUPPORTED"] = "1" if profile.get("funded_spending") else "0"

    stderr("")
    stderr(f"Ordinary/non-covenant E2E network: {standard}")
    stderr(f"  wRPC: {standard_profile['wrpc_endpoint']}")
    stderr(f"Covenant E2E network: {covenant}")
    stderr(f"  wRPC: {covenant_profile['wrpc_endpoint']}")
    if standard == "mainnet" and os.environ.get("KASPA_PORTAL_E2E_ALLOW_MAINNET_SPEND") != "1":
        stderr("  Mainnet funded spending is disabled by default (read-only standard-network live tests only).")
    stderr("")
    output = assignment_text(assignments)
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
    else:
        sys.stdout.write(output)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, EOFError) as error:
        stderr(f"ERROR: {error}")
        raise SystemExit(2)
