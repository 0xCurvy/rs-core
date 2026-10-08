#!/usr/bin/env python3
"""Usage: SCRIPT CONFIG_JSON OUTPUT_JSON. Compare explicit serial/parallel builds."""
import json
from pathlib import Path
import statistics
import sys
from measure_resident_repeated import measure

config = json.loads(Path(sys.argv[1]).read_text())
result = {"config": config, "runs": []}
for case in config["artifacts"]:
    for profile in config["profiles"]:
        run = measure(profile["binary"], case | dict(backend="graph", threads=profile["threads"], samples=5))
        run["profile"] = profile["name"]
        result["runs"].append(run)
        Path(sys.argv[2]).write_text(json.dumps(result, indent=2) + "\n")
        print(f"notes={case['notes']} {profile['name']}: "
              f"{statistics.median(run['proof_and_witness_ms']):.2f} ms, "
              f"{run['peak_rss_bytes']/1024**2:.1f} MiB", flush=True)
