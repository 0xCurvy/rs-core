#!/usr/bin/env python3
"""Measure fresh resident processes. Usage: SCRIPT BINARY ARTIFACTS_JSON OUTPUT_JSON"""
import json
import math
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import tempfile


def measure(binary, config):
    with tempfile.TemporaryDirectory(prefix="curvy-resident-bench-") as directory:
        config_path = Path(directory) / "config.json"
        config_path.write_text(json.dumps(config))
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            child = subprocess.Popen([binary, str(config_path)], stdout=stdout, stderr=stderr)
            _, status, usage = os.wait4(child.pid, 0)
            child.returncode = os.waitstatus_to_exitcode(status)
            stdout.seek(0)
            stderr.seek(0)
            if child.returncode:
                raise RuntimeError(stderr.read().decode())
            result = json.load(stdout)
            assert result["self_verified"]
            result["peak_rss_bytes"] = usage.ru_maxrss * (1 if platform.system() == "Darwin" else 1024)
            result["config"] = config
            return result


def main():
    if platform.system() not in ("Darwin", "Linux"):
        raise SystemExit("RSS measurement supports macOS and Linux")
    binary, artifacts, destination = sys.argv[1:]
    result = {"binary": binary, "runs": [], "summary": []}
    profiles = [("graph", None), ("sage", None), ("cached", None), ("cached", 128 * 1024**2)]
    for case in json.loads(Path(artifacts).read_text()):
        for round_index in range(2):
            for backend, scratch in profiles[::1 if round_index == 0 else -1]:
                config = case | dict(backend=backend, scratch_bytes=scratch, samples=11, threads=13)
                run = measure(binary, config)
                result["runs"].append(run)
                Path(destination).write_text(json.dumps(result, indent=2) + "\n")
                print(f"notes={case['notes']} {backend} scratch={scratch}: "
                      f"{statistics.median(run['proof_and_witness_ms']):.2f} ms, "
                      f"{run['peak_rss_bytes']/1024**2:.1f} MiB", flush=True)
        for backend, scratch in profiles:
            runs = [r for r in result["runs"] if r["notes"] == case["notes"] and
                    r["backend"] == backend and r["config"]["scratch_bytes"] == scratch]
            samples = sorted(v for r in runs for v in r["proof_and_witness_ms"])
            result["summary"].append(dict(notes=case["notes"], backend=backend, scratch_bytes=scratch,
                samples=len(samples), median_ms=statistics.median(samples),
                p95_ms=samples[math.ceil(len(samples) * .95) - 1],
                median_peak_rss_bytes=statistics.median(r["peak_rss_bytes"] for r in runs),
                witness_load_ms=statistics.median(r["witness_load_ms"] for r in runs),
                scratch_retained_bytes=runs[0]["scratch_retained_bytes"]))
        Path(destination).write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
