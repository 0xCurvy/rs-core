#!/usr/bin/env python3
"""Summarize run-all.sh results as Markdown tables.

    python3 report.py [RESULTS_DIR]   (default ../../target/claude-scratch/wasm-field/results)
"""
import glob
import json
import os
import statistics
import sys

R = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "../../target/claude-scratch/wasm-field/results")


def load(name):
    path = os.path.join(R, name)
    if not os.path.exists(path):
        return None
    with open(path) as f:
        text = f.read().strip().splitlines()
    if not text:
        return None
    try:
        return json.loads(text[-1])
    except json.JSONDecodeError:
        return None


def fmt(v, digits=1):
    return "—" if v is None else f"{v:,.{digits}f}"


ENGINES = ["native", "node", "chromium"]
OPS = [("mul_lat", "mul lat"), ("mul_thr", "mul thr"), ("sqr_lat", "sqr lat"), ("sqr_thr", "sqr thr"),
       ("add_lat", "add lat"), ("add_thr", "add thr"), ("sub_lat", "sub lat"), ("sub_thr", "sub thr"),
       ("from_ark", "from ark"), ("to_ark", "to ark")]


def fields_table():
    data = {}
    for engine in ENGINES:
        rounds = [load(f"fields-{engine}-{r}.json") for r in (1, 2)]
        rounds = [r for r in rounds if r]
        for rnd in rounds:
            for f in rnd["fields"]:
                for key, val in f.items():
                    if key == "field":
                        continue
                    data.setdefault((engine, f["field"], key), []).append(val["ns"])
    # Mean of the two rounds' medians.
    get = lambda e, f, k: statistics.mean(data[(e, f, k)]) if (e, f, k) in data else None
    print("### A. Field arithmetic, ns per operation (per element for simd4)\n")
    for group, names in [("Fq", ["ark", "u32x8", "u29x9", "simd4"]),
                         ("Fq2", ["fq2-ark", "fq2-u29x9", "fq2-simd", "fq2x4"])]:
        print(f"**{group}**\n")
        cols = [("pack", "pack") if n == "simd4" else None for n in names]
        print("| Op | " + " | ".join(f"{n} {e}" for n in names for e in ("nat", "node", "chr")) + " |")
        print("|---|" + "---:|" * (3 * len(names)))
        ops = OPS + ([("inverse", "inverse")] if group == "Fq" else [("inverse", "inverse")])
        for key, label in ops:
            row = []
            for n in names:
                for e in ENGINES:
                    k = key
                    if n == "simd4" and key == "from_ark":
                        k = "pack"
                    if n == "simd4" and key == "to_ark":
                        k = "unpack"
                    row.append(fmt(get(e, n, k), 2))
            print(f"| {label} | " + " | ".join(row) + " |")
        print()
    # WASM / native ratios against native arkworks.
    print("**WASM / native ratio** (each representation vs native arkworks; mul and square throughput)\n")
    print("| Representation | mul node | mul chromium | sqr node | sqr chromium | mul vs WASM ark (node) |")
    print("|---|---:|---:|---:|---:|---:|")
    base = {k: get("native", "ark", k) for k in ("mul_thr", "sqr_thr")}
    for n in ["ark", "u32x8", "u29x9", "simd4"]:
        r = lambda e, k: (get(e, n, k) / base[k]) if get(e, n, k) and base[k] else None
        speed = get("node", "ark", "mul_thr") / get("node", n, "mul_thr") if get("node", n, "mul_thr") else None
        print(f"| {n} | {fmt(r('node', 'mul_thr'), 2)} | {fmt(r('chromium', 'mul_thr'), 2)} | "
              f"{fmt(r('node', 'sqr_thr'), 2)} | {fmt(r('chromium', 'sqr_thr'), 2)} | {fmt(speed, 2)}x |")
    print()
    noslp = load("fields-node-noslp.json")
    if noslp:
        f = {x["field"]: x for x in noslp["fields"]}
        print("No-SLP build (Node), u29x9: " + ", ".join(
            f"{k} {f['u29x9'][k]['ns']:.2f}" for k in ("mul_lat", "mul_thr", "sqr_lat", "sqr_thr", "add_lat", "sub_lat")))
        print()


def msm_rows(prefix, curve, sizes):
    print(f"### {'C' if curve == 'g1' else 'D'}. {curve.upper()} kernel, random inputs, ms (median of 3; every result == arkworks VariableBaseMSM)\n")
    print("| Points | w | ark nat | u29x9 nat | ark node | u29x9 node | simd node | ark chr | u29x9 chr | simd chr | speedup node | speedup chr |")
    print("|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    extra = []
    for log2 in sizes:
        res = {e: load(f"{prefix}-{curve}-{log2}-{e}.json") for e in ENGINES}
        widths = sorted({w["width"] for e in res if res[e] for f in res[e]["msm"]["fields"] for w in f["widths"]})
        for w in widths:
            def t(e, field):
                if not res[e]:
                    return None
                for f in res[e]["msm"]["fields"]:
                    name = f["field"].replace("fq2-", "")
                    if name == field or (field == "simd" and f["apply"] == "simd4"):
                        if field != "simd" and f["apply"] == "simd4":
                            continue
                        for row in f["widths"]:
                            if row["width"] == w:
                                return row
                return None
            ms = lambda e, fld: (t(e, fld) or {}).get("ms")
            sp = lambda e: ms(e, "ark") / ms(e, "simd") if ms(e, "ark") and ms(e, "simd") else None
            print(f"| 2^{log2} | {w} | {fmt(ms('native', 'ark'))} | {fmt(ms('native', 'u29x9'))} | "
                  f"{fmt(ms('node', 'ark'))} | {fmt(ms('node', 'u29x9'))} | {fmt(ms('node', 'simd'))} | "
                  f"{fmt(ms('chromium', 'ark'))} | {fmt(ms('chromium', 'u29x9'))} | {fmt(ms('chromium', 'simd'))} | "
                  f"{fmt(sp('node'), 2)}x | {fmt(sp('chromium'), 2)}x |")
            for e in ("node", "chromium"):
                for fld in ("ark", "simd"):
                    row = t(e, fld)
                    if row:
                        extra.append((log2, w, e, fld, row))
        if curve == "g1" and res["node"]:
            u32 = [f for f in res["node"]["msm"]["fields"] if f["field"] == "u32x8"]
            if u32:
                print(f"| 2^{log2} | | u32x8 node: " + ", ".join(
                    f"w{r['width']} {r['ms']:.1f}" for r in u32[0]["widths"]) + " | | | | | | | | | |")
    print()
    print("Phase split (node; accumulate / reduce ms, inversion share, base conversion ms):\n")
    print("| Points | w | kernel | accumulate | reduce | inversion share | convert bases |")
    print("|---:|---:|---|---:|---:|---:|---:|")
    for log2, w, e, fld, row in extra:
        if e != "node":
            continue
        res = load(f"{prefix}-{curve}-{log2}-{e}.json")
        conv = [f["convert_bases_ms"] for f in res["msm"]["fields"]
                if (f["apply"] == "simd4") == (fld == "simd") and (fld == "simd" or f["field"].endswith("ark"))]
        print(f"| 2^{log2} | {w} | {fld} | {row['accumulate_ms']:.1f} | {row['reduce_ms']:.1f} | "
              f"{100 * row['inversion_share']:.2f}% | {fmt(conv[0] if conv else None)} |")
    print()


def anchor_table():
    print("### C (iii). Anchor: production kernel vs the PoC on the same input (every base = generator), ms\n")
    print("| Points | w | production node | PoC ark node | PoC simd node | production chr | PoC ark chr | PoC simd chr |")
    print("|---:|---:|---:|---:|---:|---:|---:|---:|")
    prod = {e: load(f"anchor-prod-{e}.json") for e in ("node", "chromium")}
    for log2 in (14, 16, 18):
        poc = {e: load(f"anchor-poc-{log2}-{e}.json") for e in ("node", "chromium")}
        for w in (12, 13, 14):
            def p(e):
                if not prod[e]:
                    return None
                for r in prod[e]["rows"]:
                    if r["log"] == log2 and r["width"] == w:
                        return r["ms"]
            def q(e, apply):
                if not poc[e]:
                    return None
                for f in poc[e]["msm"]["fields"]:
                    if f["apply"] == apply:
                        for r in f["widths"]:
                            if r["width"] == w:
                                return r["ms"]
            print(f"| 2^{log2} | {w} | {fmt(p('node'))} | {fmt(q('node', 'scalar'))} | {fmt(q('node', 'simd4'))} | "
                  f"{fmt(p('chromium'))} | {fmt(q('chromium', 'scalar'))} | {fmt(q('chromium', 'simd4'))} |")
    print()


PROJECT = {
    2: [("h-2", "g1", 0), ("w-2", "g1", 1), ("w-2", "g1", 2), ("w-2", "g1", 3), ("w-2", "g2", 4)],
    5: [("h-2", "g1", 0), ("w-5", "g1", 1), ("w-5", "g1", 2), ("w-5", "g1", 3), ("w-5", "g2", 4)],
    10: [("h-10", "g1", 0), ("w-10", "g1", 1), ("w-10", "g1", 2), ("w-10", "g1", 3), ("w-10", "g2", 4)],
}


def speedups(engine):
    out = {}
    for name in ("h-2", "h-10", "w-2", "w-5", "w-10"):
        for curve in ("g1", "g2"):
            res = load(f"project-{name}-{curve}-{engine}.json")
            if not res:
                continue
            rows = {f["apply"]: f["widths"][0] for f in res["msm"]["fields"]}
            conv = {f["apply"]: f["convert_bases_ms"] for f in res["msm"]["fields"]}
            out[(name, curve)] = (rows["scalar"]["ms"], rows["simd4"]["ms"], conv["simd4"])
    return out


def phases_and_projection():
    print("### E. Portable proofs: measured phases and Amdahl projection\n")
    for engine in ("node", "chromium"):
        ph = load(f"phases-{engine}.json")
        sp = speedups(engine)
        if not ph:
            continue
        print(f"**{ph['engine']}** (instrumented portable build, median of {ph['samples']} proofs after a warm-up; "
              "proof = witness + Groth16 + self-verification, as `prove()`)\n")
        print("| Notes | proof ms | witness | witness map (FFT) | MSM G1 | MSM G2 | other | MSM share | G1 share | G2 share |")
        print("|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
        for r in ph["results"]:
            other = r["totalMs"] - r["witness"] - r["witnessMap"] - r["msmG1"] - r["msmG2"]
            print(f"| {r['notes']} | {r['totalMs']:,.0f} | {r['witness']:,.0f} | {r['witnessMap']:,.0f} | "
                  f"{r['msmG1']:,.0f} | {r['msmG2']:,.0f} | {other:,.0f} | {100 * r['msmShare']:.1f}% | "
                  f"{100 * r['msmG1Share']:.1f}% | {100 * r['msmG2Share']:.1f}% |")
        print()
        print("Per-call kernel ratio arkworks/SIMD from the projection runs (production sizes, `serial_window_bits` "
              "widths, witness-scalar mix measured in these proofs):\n")
        print("| Config | ark ms | simd ms | ratio | base conversion ms |")
        print("|---|---:|---:|---:|---:|")
        for (name, curve), (a, s, c) in sorted(sp.items()):
            print(f"| {name} {curve} | {a:,.1f} | {s:,.1f} | {a / s:.2f}x | {c:,.1f} |")
        print()
        print("Per-call: production time and the PoC arkworks kernel on the same configuration (ms):\n")
        print("| Notes | " + " | ".join(f"{n} prod / PoC ark" for n in ("H", "L", "A", "B1", "B2 (G2)")) + " |")
        print("|---:|---:|---:|---:|---:|---:|")
        for r in ph["results"]:
            calls = [c for c in zip(*[iter(statistics_median_calls(r))] * 6)]
            cells = []
            for (name, curve, idx) in PROJECT[r["notes"]]:
                a = sp.get((name, curve), (None,))[0]
                cells.append(f"{calls[idx][2]:,.0f} / {fmt(a, 0)}")
            print(f"| {r['notes']} | " + " | ".join(cells) + " |")
        print()
        print("Projection. *Ratio*: each production call divided by its arkworks/SIMD ratio. *Conservative*: each "
              "production call minus the smaller of the two savings: the ratio's, or the absolute ms the SIMD kernel "
              "saved on that configuration.\n")
        print("| Notes | proof ms | MSM ms | proof, G1 only | proof, G1+G2 | speedup G1 only | speedup G1+G2 | "
              "G1+G2 conservative | + per-proof base conversion | MSM-free bound |")
        print("|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
        for r in ph["results"]:
            calls = [c for c in zip(*[iter(statistics_median_calls(r))] * 6)]
            msm = sum(c[2] for c in calls)
            g1_only = g12 = conv = saved = 0.0
            for (name, curve, idx) in PROJECT[r["notes"]]:
                call_ms = calls[idx][2]
                a, s, c = sp.get((name, curve), (1, 1, 0))
                ratio = a / s
                g12 += call_ms / ratio
                g1_only += call_ms / ratio if curve == "g1" else call_ms
                saved += min(a - s, call_ms * (1 - 1 / ratio))
                conv += c
            total = r["totalMs"]
            p1 = total - msm + g1_only
            p12 = total - msm + g12
            pc = total - saved
            print(f"| {r['notes']} | {total:,.0f} | {msm:,.0f} | {p1:,.0f} | {p12:,.0f} | "
                  f"{total / p1:.2f}x | {total / p12:.2f}x | {pc:,.0f} ({total / pc:.2f}x) | "
                  f"{total / (p12 + conv):.2f}x | {total / (total - msm):.2f}x |")
        print()


def statistics_median_calls(r):
    runs = [run["msmCalls"] for run in r["runs"]]
    return [statistics.median(v) for v in zip(*runs)]


def tests_table():
    print("### B. Differential tests (all passed; a mismatch panics)\n")
    print("| Run | checks | ms |")
    print("|---|---:|---:|")
    for path in sorted(glob.glob(os.path.join(R, "test-*.json"))):
        d = load(os.path.basename(path))
        print(f"| {os.path.basename(path)[5:-5]} ({d.get('engine', d['target'])}) | {d['checks']:,} | {d['ms']:,} |")
    d = load("test-chromium.json") or load("test-node.json")
    if d:
        print("\nSections (" + d.get("engine", "") + "):\n")
        for s in d["sections"]:
            print(f"- {s['name']}: {s['checks']:,}")
    print()


if __name__ == "__main__":
    tests_table()
    fields_table()
    msm_rows("msm", "g1", (14, 16, 18))
    anchor_table()
    msm_rows("msm", "g2", (14, 16, 18))
    phases_and_projection()
    log = os.path.join(R, "run.log")
    if os.path.exists(log):
        loads = [float(line.split("load ")[1].split()[0]) for line in open(log) if "load " in line]
        print(f"Host 1-minute load during the run: {min(loads):.1f}–{max(loads):.1f} (14 cores).")
