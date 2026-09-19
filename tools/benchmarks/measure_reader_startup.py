#!/usr/bin/env python3
"""Compare prebuilt reader profiles in fresh macOS processes with warm files.

Usage: measure_reader_startup.py CONFIG_JSON OUTPUT_JSON
CONFIG_JSON contains `samples`, `profiles` (name/binary), and `cases`
(notes/threads/zkey/sha256/constraints). Binaries use whole_key_wtns's CLI.
"""

import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import tempfile
import time


def measure(command):
    # wait4 returns this child's own high-water RSS. Unlike RUSAGE_CHILDREN,
    # it does not accumulate the maximum from earlier benchmark processes.
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        started = time.perf_counter()
        process = subprocess.Popen(command, stdout=output, stderr=errors)
        _, status, usage = os.wait4(process.pid, 0)
        process.returncode = os.waitstatus_to_exitcode(status)
        elapsed_ms = (time.perf_counter() - started) * 1000
        output.seek(0)
        errors.seek(0)
        stdout = output.read().decode()
        stderr = errors.read().decode()
        if process.returncode:
            raise RuntimeError(f"{command[0]} exited {process.returncode}\n{stdout}\n{stderr}")
    values = {}
    for line in stdout.splitlines():
        key, separator, value = line.partition("=")
        if not separator:
            continue
        try:
            values[key] = float(value) if "." in value else int(value)
        except ValueError:
            values[key] = value
    values["peak_rss_bytes"] = usage.ru_maxrss
    values["process_wall_ms"] = elapsed_ms
    return values


def summarize(values):
    return {
        "min": min(values),
        "median": statistics.median(values),
        "max": max(values),
        "mean": statistics.mean(values),
        "standard_deviation": statistics.pstdev(values),
    }


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    if platform.system() != "Darwin":
        raise SystemExit("This runner records macOS wait4 RSS in bytes.")
    config = json.loads(Path(sys.argv[1]).read_text())
    samples = config["samples"]
    if not isinstance(samples, int) or samples < 1:
        raise ValueError("samples must be a positive integer")
    profiles = config["profiles"]
    if not profiles or len({profile["name"] for profile in profiles}) != len(profiles):
        raise ValueError("profile names must be nonempty and unique")
    output = {"config": config, "cases": []}
    destination = Path(sys.argv[2])
    for case in config["cases"]:
        commands = {
            profile["name"]: [
                profile["binary"], case["zkey"], case["sha256"],
                "unused-in-load-only-mode", str(case["threads"]), "--load-only",
            ] + (["--manifest", case["manifest"], case["manifest_sha256"]]
                 if profile.get("manifest") else [])
            for profile in profiles
        }
        raw = {profile["name"]: [] for profile in profiles}
        warmups = {}
        names = list(commands)
        print(f"Measuring notes={case['notes']}, threads={case['threads']}", flush=True)

        def execute(name):
            values = measure(commands[name])
            assert values["operation"] == "load-only"
            assert values["constraints"] == case["constraints"]
            assert values["threads"] == case["threads"]
            assert values["zkey_bytes"] == case["zkey_bytes"]
            assert values["public_inputs"] == 1
            assert values["peak_rss_bytes"] > 0
            return values

        for name in names:
            warmups[name] = execute(name)
        for sample in range(samples):
            offset = sample % len(names)
            order = names[offset:] + names[:offset]
            if sample % 2:
                order.reverse()
            for name in order:
                raw[name].append(execute(name))
        metrics = [
            "zkey_parse_and_auth_ms", "peak_rss_bytes", "process_wall_ms", "total_ms",
        ]
        summaries = {
            name: {metric: summarize([row[metric] for row in rows]) for metric in metrics}
            for name, rows in raw.items()
        }
        output["cases"].append({
            "case": case, "commands": commands, "warmups": warmups,
            "raw_samples": raw, "summary": summaries,
        })
        destination.write_text(json.dumps(output, indent=2) + "\n")
        for name in names:
            median_ms = summaries[name]["zkey_parse_and_auth_ms"]["median"]
            rss_mib = summaries[name]["peak_rss_bytes"]["median"] / 1024**2
            print(f"  {name}: {median_ms:.3f} ms, {rss_mib:.1f} MiB peak RSS", flush=True)


if __name__ == "__main__":
    main()
