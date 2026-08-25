#!/usr/bin/env python3
"""Build and monitor native Kaspa Portal resource probes without third-party Python packages."""
from __future__ import annotations

import argparse
import ctypes
import json
import math
import os
from pathlib import Path
import queue
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
PROFILES = ROOT / "qa/resource/profiles.toml"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("quick", "soak"), default="quick")
    parser.add_argument("--profiles", default="standard,indexer,crypto,network,fault")
    parser.add_argument("--idle-ms", type=int, default=3000)
    return parser.parse_args()


def load_profiles() -> dict:
    profiles = []
    current = None
    for source in PROFILES.read_text(encoding="utf-8").splitlines():
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
    return {item["name"]: item for item in profiles}


def reader_thread(stream, output: queue.Queue) -> None:
    for line in iter(stream.readline, ""):
        output.put(line.rstrip("\r\n"))
    output.put(None)


def linear_slope(values) -> float:
    if len(values) < 2:
        return 0.0
    xs = list(range(len(values)))
    x_mean = sum(xs) / len(xs)
    y_mean = sum(values) / len(values)
    denominator = sum((x - x_mean) ** 2 for x in xs)
    if denominator == 0:
        return 0.0
    return sum((x - x_mean) * (y - y_mean) for x, y in zip(xs, values)) / denominator


class LinuxStats:
    def __init__(self, pid: int):
        self.pid = pid
        self.ticks = os.sysconf(os.sysconf_names["SC_CLK_TCK"])

    def sample(self) -> dict:
        stat = (Path("/proc") / str(self.pid) / "stat").read_text().split()
        status = (Path("/proc") / str(self.pid) / "status").read_text().splitlines()
        fields = {}
        for line in status:
            if ":" in line:
                key, value = line.split(":", 1)
                fields[key] = value.strip()
        rss_kib = int(fields.get("VmRSS", "0 kB").split()[0])
        threads = int(fields.get("Threads", "0"))
        fd_dir = Path("/proc") / str(self.pid) / "fd"
        fds = len(list(fd_dir.iterdir())) if fd_dir.exists() else 0
        cpu_seconds = (int(stat[13]) + int(stat[14])) / self.ticks
        return {"rss": rss_kib * 1024, "cpu": cpu_seconds, "threads": threads, "handles": fds}


if os.name == "nt":
    from ctypes import wintypes

    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010
    TH32CS_SNAPTHREAD = 0x00000004
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    class FILETIME(ctypes.Structure):
        _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]

    class PROCESS_MEMORY_COUNTERS_EX(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("PageFaultCount", wintypes.DWORD),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
            ("PrivateUsage", ctypes.c_size_t),
        ]

    class THREADENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ThreadID", wintypes.DWORD),
            ("th32OwnerProcessID", wintypes.DWORD),
            ("tpBasePri", wintypes.LONG),
            ("tpDeltaPri", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.GetProcessTimes.argtypes = [wintypes.HANDLE, ctypes.POINTER(FILETIME), ctypes.POINTER(FILETIME), ctypes.POINTER(FILETIME), ctypes.POINTER(FILETIME)]
    kernel32.GetProcessTimes.restype = wintypes.BOOL
    kernel32.GetProcessHandleCount.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetProcessHandleCount.restype = wintypes.BOOL
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(THREADENTRY32)]
    kernel32.Thread32First.restype = wintypes.BOOL
    kernel32.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(THREADENTRY32)]
    kernel32.Thread32Next.restype = wintypes.BOOL
    psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESS_MEMORY_COUNTERS_EX), wintypes.DWORD]
    psapi.GetProcessMemoryInfo.restype = wintypes.BOOL

    class WindowsStats:
        def __init__(self, pid: int):
            self.pid = pid
            self.handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
            if not self.handle:
                raise OSError(ctypes.get_last_error(), "OpenProcess failed")

        def close(self) -> None:
            if self.handle:
                kernel32.CloseHandle(self.handle)
                self.handle = None

        def thread_count(self) -> int:
            snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
            if snapshot == INVALID_HANDLE_VALUE:
                return 0
            entry = THREADENTRY32()
            entry.dwSize = ctypes.sizeof(entry)
            count = 0
            if kernel32.Thread32First(snapshot, ctypes.byref(entry)):
                while True:
                    if entry.th32OwnerProcessID == self.pid:
                        count += 1
                    if not kernel32.Thread32Next(snapshot, ctypes.byref(entry)):
                        break
            kernel32.CloseHandle(snapshot)
            return count

        def sample(self) -> dict:
            counters = PROCESS_MEMORY_COUNTERS_EX()
            counters.cb = ctypes.sizeof(counters)
            if not psapi.GetProcessMemoryInfo(self.handle, ctypes.byref(counters), counters.cb):
                raise OSError(ctypes.get_last_error(), "GetProcessMemoryInfo failed")
            creation, exit_time, kernel, user = FILETIME(), FILETIME(), FILETIME(), FILETIME()
            if not kernel32.GetProcessTimes(self.handle, ctypes.byref(creation), ctypes.byref(exit_time), ctypes.byref(kernel), ctypes.byref(user)):
                raise OSError(ctypes.get_last_error(), "GetProcessTimes failed")
            to_seconds = lambda value: ((value.dwHighDateTime << 32) | value.dwLowDateTime) / 10_000_000
            handles = wintypes.DWORD()
            if not kernel32.GetProcessHandleCount(self.handle, ctypes.byref(handles)):
                raise OSError(ctypes.get_last_error(), "GetProcessHandleCount failed")
            return {
                "rss": int(counters.WorkingSetSize),
                "cpu": to_seconds(kernel) + to_seconds(user),
                "threads": self.thread_count(),
                "handles": int(handles.value),
            }
else:
    WindowsStats = None


def stats_for(pid: int):
    if sys.platform.startswith("linux"):
        return LinuxStats(pid)
    if os.name == "nt":
        return WindowsStats(pid)
    raise RuntimeError("native resource monitoring currently supports Linux and Windows")


def build_probe(target_dir: Path) -> Path:
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(target_dir)
    env.setdefault("CARGO_BUILD_JOBS", "1")
    env.setdefault("CARGO_INCREMENTAL", "0")
    command = ["cargo", "build", "--manifest-path", "qa/Cargo.toml", "--release", "--bin", "resource_probe"]
    subprocess.run(command, cwd=ROOT, env=env, check=True)
    name = "resource_probe.exe" if os.name == "nt" else "resource_probe"
    binary = target_dir / "release" / name
    if not binary.is_file():
        raise RuntimeError(f"resource probe binary missing: {binary}")
    return binary


def run_profile(binary: Path, profile: dict, mode: str, idle_ms: int) -> dict:
    prefix = "quick" if mode == "quick" else "soak"
    command = [
        str(binary), profile["native_scenario"],
        "--warmup", str(profile[f"{prefix}_warmup"]),
        "--batches", str(profile[f"{prefix}_batches"]),
        "--iterations", str(profile[f"{prefix}_iterations_per_batch"]),
        "--idle-ms", str(idle_ms),
    ]
    endpoint = (
        os.environ.get("KASPA_PORTAL_E2E_STANDARD_ENDPOINT")
        or os.environ.get("KASPA_PORTAL_E2E_ENDPOINT")
    )
    if endpoint:
        command.extend(["--endpoint", endpoint])
    process = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
    stats = stats_for(process.pid)
    messages: queue.Queue = queue.Queue()
    errors: queue.Queue = queue.Queue()
    stdout_thread = threading.Thread(target=reader_thread, args=(process.stdout, messages), daemon=True)
    stderr_thread = threading.Thread(target=reader_thread, args=(process.stderr, errors), daemon=True)
    stdout_thread.start()
    stderr_thread.start()
    baseline = None
    batch_samples = []
    idle_start = None
    idle_wall = None
    idle_end = None
    idle_end_wall = None
    stderr_lines = []
    done = False
    while process.poll() is None or not done:
        try:
            line = messages.get(timeout=0.05)
        except queue.Empty:
            line = ""
        if line is None:
            done = True
        elif line:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                print(f"[{profile['name']}] {line}")
                event = None
            if event:
                name = event.get("event")
                if name == "baseline":
                    baseline = stats.sample()
                elif name == "batch":
                    batch_samples.append(stats.sample())
                elif name == "idle_begin":
                    idle_start = stats.sample()
                    idle_wall = time.monotonic()
                elif name == "idle_end":
                    idle_end = stats.sample()
                    idle_end_wall = time.monotonic()
        while True:
            try:
                error_line = errors.get_nowait()
            except queue.Empty:
                break
            if error_line:
                stderr_lines.append(error_line)
    return_code = process.wait()
    if hasattr(stats, "close"):
        stats.close()
    if return_code != 0:
        raise RuntimeError(f"{profile['name']} resource probe exited {return_code}: {' | '.join(stderr_lines[-20:])}")
    if baseline is None or not batch_samples or idle_start is None or idle_end is None or idle_wall is None or idle_end_wall is None:
        raise RuntimeError(f"{profile['name']} resource probe did not emit complete phase markers")

    rss_values = [int(sample["rss"]) for sample in batch_samples]
    rss_growth = max(rss_values) - int(baseline["rss"])
    rss_slope = max(0.0, linear_slope(rss_values))
    thread_growth = max(int(sample["threads"]) for sample in batch_samples) - int(baseline["threads"])
    handle_growth = max(int(sample["handles"]) for sample in batch_samples) - int(baseline["handles"])
    idle_seconds = max(0.001, idle_end_wall - idle_wall)
    idle_cpu_ratio = max(0.0, float(idle_end["cpu"]) - float(idle_start["cpu"])) / idle_seconds
    result = {
        "profile": profile["name"],
        "rss_growth_bytes": rss_growth,
        "rss_slope_bytes_per_batch": rss_slope,
        "thread_growth": thread_growth,
        "handle_or_fd_growth": handle_growth,
        "idle_cpu_ratio": idle_cpu_ratio,
    }
    violations = []
    checks = [
        (rss_growth, profile["max_rss_growth_bytes"], "RSS growth"),
        (rss_slope, profile["max_rss_slope_bytes_per_batch"], "RSS slope"),
        (thread_growth, profile["max_thread_growth"], "thread growth"),
        (handle_growth, profile["max_handle_or_fd_growth"], "handle/FD growth"),
        (idle_cpu_ratio, profile["max_idle_cpu_ratio"], "idle CPU ratio"),
    ]
    for actual, maximum, label in checks:
        if actual > maximum:
            violations.append(f"{label} {actual:.3f} > {maximum}")
    if violations:
        raise RuntimeError(f"{profile['name']} resource budget failed: " + "; ".join(violations))
    return result


def main() -> int:
    args = parse_args()
    profiles = load_profiles()
    requested = [item.strip() for item in args.profiles.split(",") if item.strip()]
    missing = [name for name in requested if name not in profiles]
    if missing:
        print("ERROR: unknown resource profile(s):", ", ".join(missing), file=sys.stderr)
        return 2
    for name in requested:
        if not profiles[name].get("native_scenario"):
            print(f"ERROR: profile {name} has no native resource scenario", file=sys.stderr)
            return 2
    with tempfile.TemporaryDirectory(prefix="kaspa-portal-resource-") as temp:
        binary = build_probe(Path(temp) / "target")
        results = []
        for name in requested:
            print(f"==> Native resource profile: {name} ({args.mode})")
            result = run_profile(binary, profiles[name], args.mode, args.idle_ms)
            results.append(result)
            print(json.dumps(result, sort_keys=True))
    print(f"NATIVE RESOURCE {args.mode.upper()} GATE: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
