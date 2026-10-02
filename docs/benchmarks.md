# Benchmarks

Consolidated measurement results for maintainers and future agents. Each area
records what was measured, where and when, the headline numbers, the conclusion,
and how to re-run it. Design decisions drawn from these numbers are in
[optimizations.md](optimizations.md); security-relevant results are summarized in
[security.md](security.md).

Raw runs are not tracked. Write new raw output under
`tools/benchmarks/results/<area>-<yyyy-mm-dd>/` (gitignored) and add only the
summary here. The re-run blocks assume
`OUT=tools/benchmarks/results/<area>-$(date +%F); mkdir -p "$OUT"` and are run
from the repository root. Unless stated otherwise, numbers are medians, latency
is in ms, and memory is peak RSS in MiB (1,048,576 bytes).

> **Staleness.** Every section lists later code changes that affect its numbers.
> Re-measure before quoting an old figure as current behavior.

## Reference host and conventions

| Item | Value |
|---|---|
| Host | Apple M4 Pro MacBook Pro (Mac16,7), 10 performance + 4 efficiency cores, 48 GB, macOS 26.5.1 arm64 |
| Toolchain | Rust 1.94.0 (LLVM 21.1.8), ordinary release profile, no `RUSTFLAGS`/LTO overrides; threaded WASM on `nightly-2026-07-03` |
| Node / browsers | Node 22.22.3; Playwright Chromium 143.0.7499.4 and Firefox 144.0.2 |
| Linux runs | Docker Desktop VM on the same host (linuxkit 6.10.14), `rust@sha256:a86cada8…` image, 6-CPU quota, 8 GiB limit. Not bare-metal evidence |
| Workers | "13 workers" = a 13-thread Rayon pool; "serial" = a `--no-default-features` build (no `parallel`) |
| Peak RSS | macOS: per-child `wait4` `ru_maxrss` or `/usr/bin/time -l`; Linux: `VmHWM`; browser: summed RSS of an isolated Chromium process tree sampled every 50 ms (shared pages counted per process; about 268 MiB before proving) |
| Correctness | Every timed proof self-verified and every artifact authenticated against its pin |

## Production artifacts

Pending-notes-commitment v2 circuits from the Curvy monorepo
(`packages/zk-keys/v2/pending-notes-commitment/verifyPendingNotesCommitment_<N>_30_0001.zkey`
and `..._<N>_30.<sha256>.graph.bin`). They are not in this repository. The
50-note key was unavailable for runs after 25 August.

| Notes | zkey bytes | Constraints | Witness fields | zkey SHA-256 |
|---:|---:|---:|---:|---|
| 2 | 91,785,620 | 150,769 | 149,452 | `dea6b15860701dee9c77ee2a6916ccda7735590012572d526a3714f8e429ed33` |
| 5 | 129,200,756 | 226,236 | 224,505 | `efb4c3d4d3350f931860faeb6319b6010303c5fbf06d8ef414d708e9cf907847` |
| 10 | 227,925,172 | 391,313 | 388,476 | `6986b1a778c87fe3cc29c31b74785e62e8e987b0ddc885fd9062265e6c037d22` |
| 50 | 925,400,177 | 1,594,033 | 1,583,596 | `cdb5cdff6bbb9a58d9cce8d811811d8244e6851ecdf6fabb2e90704416af62ee` |

| Notes | SIGNET v1 zstd SHA-256 | SIGNET v2 zstd SHA-256 | Manifest (1 MiB chunks) SHA-256 |
|---:|---|---|---|
| 2 | `73241359eec29d2f19516ca4daa04ad2c1a893782b692c598885c33c58415822` | `c2f8da1dd7f3ae23ffe64c754ba1e6d720229d459ae348f2a66319b8523bd27a` | `87df938aa2cd855392b3272b47e6d115198dd08f41497d2b7f409c5a24b5f02c` |
| 5 | `69fa449825732a0958ccd0689ad361d9e8df1223231d8b71932d0efc4a07d8f0` | `f1852372eb4e220fbc5c92f0cab0bbaa0b1fa80690ec1bc56f10367ea734aad6` | `843456931b21086b3e8386ed20b9e36eb148a668fa094b8fa4ac596960bb8a25` |
| 10 | `9ca2c4b05a54a23b90146175a8b6a03af68cd7da8c69ac32e8cffe60caaf7dc7` | `192c0bbe73d233ba92bc3c15b99269ef09154469c110c3898894a07a26638dae` | `0589836b7dda2a390a9e2586aaf6767ec70d26ffbfa51459d86f76b56c5640f7` |
| 50 | `6df82c04eeda1b3b506fc2c40755344c2bdeac677d72d001bace4867a4e81e1a` | `6d33b1e6a4d0edbaa991f3e8789758547bbf0c54814f7c6dc52791efaad52864` | `53f7c888cfd39b0d9f31fdbccc2ebb3b7b6f89c43c7130b2c2ba3b50e553dbc8` |

The resident and serial runs (5 and 6 September) used the SIGNET v1 graphs.
SAGE program digests depend on the compiler version, so regenerate them with
`derive_sage_cache` instead of reusing old pins.

The Python runners take an artifacts list of this shape:

```json
[{"notes": 10, "zkey": "/abs/path.zkey", "zkey_sha256": "…", "graph": "/abs/path.graph.bin",
  "graph_sha256": "…", "manifest": "/abs/10.manifest", "manifest_sha256": "…",
  "program": "/abs/10.sage", "program_sha256": "…"}]
```

## 1. MSM and whole proof (HAWK resident)

### 1.1 End-to-end profiles (25 Aug 2026)

Native, 13 workers, one warm-up then 7 alternating samples per profile and
circuit, RSS from a separate `/usr/bin/time -l` process. SPARROW used adaptive
windows, 524,288-point MSM chunks and 1 MiB manifest chunks. 112 timed proofs.

| Notes | Stock resident ms / MiB | HAWK resident | SPARROW cold | SPARROW warm |
|---:|---:|---:|---:|---:|
| 2 | 372.7 / 250.7 | 343.2 / 192.6 | 390.8 / 171.1 | 366.8 / 163.0 |
| 5 | 528.7 / 334.9 | 482.3 / 253.8 | 536.9 / 188.4 | 495.2 / 205.7 |
| 10 | 913.9 / 573.7 | 832.0 / 455.9 | 924.4 / 255.5 | 855.4 / 246.6 |
| 50 | 3,805.5 / 2,291.7 | 3,453.2 / 1,696.0 | 3,706.9 / 591.0 | 3,455.5 / 506.3 |

Profiles: stock = SIGNET v1, nested arkworks matrices; HAWK = SIGNET v2,
compact CSR matrices; SPARROW cold = SIGNET v2 compiled to SAGE in-process plus a
manifest-authenticated zkey stream; SPARROW warm = authenticated precompiled SAGE.
All start from a built circuit-input JSON, so Poseidon is not on this path.

Whole-key phases, stock -> HAWK:

| Notes | Bundle load | Witness | Proof + verify |
|---:|---:|---:|---:|
| 2 | 123.3 -> 91.6 | 18.0 -> 18.0 | 231.6 -> 234.1 |
| 5 | 179.7 -> 131.6 | 27.0 -> 26.2 | 321.1 -> 324.0 |
| 10 | 308.7 -> 224.4 | 45.0 -> 43.2 | 561.8 -> 558.5 |
| 50 | 1,283.2 -> 936.6 | 178.1 -> 176.8 | 2,333.7 -> 2,345.6 |

**Conclusion.** HAWK's 8–9% end-to-end gain is entirely load time (SIGNET v2 plus
compact parsing); the FFT/MSM proof phase is unchanged. With the key already
resident, witness + proof is about 252 / 350 / 602 / 2,522 ms for 2/5/10/50
notes, and warm SPARROW is 37–45% slower than that. In one-shot processes warm
SPARROW is within 0.1–6.9% of HAWK and uses up to 77.9% less memory.

Stale since: authenticated chunk recheck in the default zkey reader (4 Sep,
affects load), the serial window policy (6 Sep, serial builds only), and SPARROW
parallel bucket reduction (1 Oct).

### 1.2 Compact vs nested matrices in isolation (25 Aug 2026)

Same host, 13 workers, WTNS input (witness held constant), 7 alternating samples,
56 self-verified proofs.

| Notes | Auth + parse | Proof | Total | Load RSS | Proof RSS | Matrix payload |
|---:|---:|---:|---:|---:|---:|---:|
| 2 | 92.6 -> 78.7 | 237.5 -> 236.5 | 333.4 -> 318.8 | 161.0 -> 111.3 | 198.4 -> 143.1 | 35.6 -> 22.4 |
| 5 | 131.6 -> 112.6 | 325.3 -> 324.6 | 462.2 -> 440.8 | 217.4 -> 150.7 | 259.9 -> 180.7 | 47.2 -> 33.4 |
| 10 | 228.9 -> 192.5 | 571.7 -> 573.6 | 809.4 -> 775.3 | 377.9 -> 242.7 | 442.3 -> 315.4 | 84.7 -> 57.6 |
| 50 | 914.9 -> 768.9 | 2,360.4 -> 2,362.5 | 3,310.8 -> 3,164.2 | 1,412.7 -> 870.6 | 1,736.3 -> 1,191.7 | 342.6 -> 234.1 |

Synthetic kernel (`matrix_evaluation`, 1,048,576 rows, one coefficient per five
rows, 15 samples): 5.425 -> 4.384 ms with one worker and 1.424 -> 1.147 ms with
four; retained payload 33,554,464 -> 11,744,084 bytes (−65%).

**Conclusion.** Compact parsing is ~15% faster and cuts full-proof RSS 28–31%
with parallel proving; proof latency is unchanged.

### 1.3 Native matrix gates, parallel and serial (5 Sep 2026)

`resident_repeated`, compact or nested matrices, one warm-up plus five
self-verified proofs per fresh process. Parallel = 13 workers.

| Notes | Parallel nested | Parallel compact | Serial nested | Serial compact |
|---:|---:|---:|---:|---:|
| 2 | 244.7 / 253.6 | 243.5 / 197.0 | 1,592.4 / 483.8 | 1,832.2 / 184.3 |
| 5 | 336.0 / 339.2 | 337.2 / 259.2 | 2,228.0 / 846.5 | 2,612.4 / 244.4 |
| 10 | 584.4 / 587.5 | 584.0 / 457.1 | 4,200.9 / 1,366.7 | 4,860.1 / 440.5 |

Serial compact selects Curvy's MSM/proof assembly instead of stock serial
`ark-groth16`, so the serial columns compare complete feature choices.

**Conclusion.** Parallel compact matches nested latency with ~22% less memory,
which justified the Node default. Serial compact was 15–17% slower, so the
Rust, C and WASM defaults stayed nested. Section 1.4 later narrowed that gap.

### 1.4 Serial MSM window policy (6 Sep 2026)

Same harness, serial builds, one warm-up plus five proofs per fresh process.

| Notes | Stock serial | Previous compact | Final compact (ln(points)+2 windows) |
|---:|---:|---:|---:|
| 2 | 1,580.3 / 483.8 | 1,863.6 / 184.1 | 1,662.4 / 188.8 |
| 5 | 2,354.3 / 847.5 | 2,678.2 / 244.4 | 2,236.1 / 248.2 |
| 10 | 4,342.5 / 1,401.8 | 5,029.8 / 440.5 | 4,120.5 / 446.4 |

Rejected candidate, precomputed i16 digits on top of the wider windows:
1,701.8 / 198.4, 2,271.3 / 248.8 and 4,300.7 / 465.5, at most 2% faster than
the wide-window build measured alongside it (1,713.4 / 188.7, 2,312.5 / 248.3,
4,304.1 / 446.3) with up to 19 MiB more peak RSS.

Linux arm64 (Docker, 6 CPUs, 8 GiB, Linux `VmHWM`):

| Notes | Stock serial | Compact serial | Compact, 4 workers |
|---:|---:|---:|---:|
| 2 | 1,709.1 / 276.7 | 1,779.6 / 155.5 | 571.6 / 164.4 |
| 5 | 2,399.0 / 341.9 | 2,410.1 / 211.3 | 802.4 / 220.4 |
| 10 | 4,487.3 / 588.5 | 4,471.9 / 390.3 | 1,441.8 / 371.7 |

Emulated x86-64, 2 notes: 2,451.0 stock serial, 2,602.5 compact serial, 819.1
compact with 4 workers. Emulation timings are not x86-64 performance evidence.

**Conclusion.** Wider serial windows made serial compact 11–18% faster than the
previous compact path and faster than stock serial at 5 and 10 notes; the 2-note
circuit is still ~5% slower than stock serial. Compact remains Node-only.

### 1.5 Synthetic MSM scheduling (`proof_msm_schedule`)

Five equal-sized H, L, A, B1, B2 stand-ins; five-run medians at 131,072 points
per query (`LOG_SIZE=17`).

| Workers | Sequential | Concurrent queries | 16,384-point scalar chunks |
|---:|---:|---:|---:|
| 1 | 3,158.0 | 3,111.8 | 2,835.5 |
| 2 | 1,573.0 | 1,572.9 | 1,436.5 |
| 4 | 856.6 | 815.8 | 781.9 |
| 8 | 492.3 | 426.0 | 453.7 |

At 524,288 points and 8 workers: sequential 1,557.8, concurrent 1,586.7 (1.9%
slower), chunked 1,413.5 (9.3% faster); RSS 267,936 / 267,504 / 238,032 KiB.
These timings used a repeated-base fixture; the fixture now uses distinct bases
so its correctness test can catch base/scalar misalignment.

**Conclusion.** Outer concurrency does not generalize; chunking is a real but
small win at a boundary that already costs single-digit ms in production. Both
stay benchmark-only (see [optimizations.md](optimizations.md)).

### Re-run

```sh
# Whole-key load + proof from a WTNS (add --features compact-matrix for CSR):
cargo run --release --locked -p curvy-benchmarks --bin whole_key_wtns -- ZKEY ZKEY_SHA256 WTNS 13
# Alternating profile sweep; wrap each command in /usr/bin/time -l for RSS:
node tools/benchmarks/measure_profiles.mjs 7 \
  --profile hawk /usr/bin/time -l target/release/whole_key_signet ZKEY ZKEY_SHA256 SIGNET SIGNET_SHA256 INPUT.json 13 \
  --profile sparrow-warm /usr/bin/time -l target/release/sparrow_manifest_sage ZKEY ZKEY_SHA256 MANIFEST MANIFEST_SHA256 PROGRAM PROGRAM_SHA256 SIGNET_SHA256 INPUT.json 13 \
  > "$OUT/profiles.json"
# Serial/parallel matrix gates: build each variant, copy the binary aside, then
cargo build --release --locked -p curvy-benchmarks --no-default-features [--features compact-matrix] --bin resident_repeated
python3 tools/benchmarks/measure_resident_matrices.py MATRIX_CONFIG.json "$OUT/matrix.json"
# MATRIX_CONFIG.json: {"artifacts": [...], "profiles": [{"name", "binary", "threads"}]}
# Synthetic MSM schedule: MODE LOG_SIZE THREADS CHUNK_POINTS
cargo run --release --locked -p curvy-benchmarks --bin proof_msm_schedule -- chunked 17 8 16384
cargo run --release --locked -p curvy-benchmarks --features compact-matrix --bin matrix_evaluation
```

Linux: run `tools/benchmarks/run_linux.sh build` then `run_linux.sh measure` in a
Rust container with the repository mounted read-only at `/source`, a writable
`/work`, and `CARGO_TARGET_DIR` set. `measure` expects `/work/config-<profile>-<notes>.json`.

## 2. Witness evaluation, SIGNET and SAGE

### 2.1 SIGNET v1 vs v2 (25 Aug 2026)

Producer `curvy-signet-builder 0.1.0-rc.1`. Every v1 and v2 graph matched the
snarkjs WTNS field for field (2,346,029 fields in total).

| Notes | Upstream nodes | SIGNET nodes | v1 raw -> v2 raw | v1 zstd -9 -> v2 zstd -9 |
|---:|---:|---:|---:|---:|
| 2 | 2,931,941 | 729,816 | 7,912,521 -> 3,371,554 B (−57.4%) | 3,098,974 -> 1,178,187 B (−62.0%) |
| 5 | 4,186,959 | 1,106,576 | 11,978,841 -> 5,040,445 B (−57.9%) | 4,703,448 -> 1,697,063 B (−63.9%) |
| 10 | 7,099,221 | 1,848,663 | 20,055,807 -> 8,382,744 B (−58.2%) | 7,852,559 -> 2,759,980 B (−64.9%) |
| 50 | 27,935,601 | 7,442,816 | 80,771,417 -> 35,635,673 B (−55.9%) | 31,639,881 -> 9,886,519 B (−68.8%) |

The 50-note v1 graph exceeds the 64 MiB client ceiling and needs
`Limits::batch_prover()`; v2 fits the client profile.

### 2.2 SAGE compiled cache (25 Aug 2026)

`sage_cache`, CPU only (no file or Cache API I/O), 7 outer samples; each warm
validation is itself a median of 7 loads.

| Notes | SAGE program | Slots | Compile | Cold CPU total | Warm authenticated load |
|---:|---:|---:|---:|---:|---:|
| 2 | 12,896,156 B | 4,148 | 34.4 | 50.0 | 12.4 |
| 5 | 19,523,332 B | 4,916 | 51.3 | 75.6 | 18.8 |
| 10 | 32,709,900 B | 6,196 | 86.4 | 126.6 | 31.8 |
| 50 | 131,777,308 B | 16,436 | 353.4 | 514.3 | 127.2 |

**Conclusion.** The cache is ~11–13x larger than compressed SIGNET v2 but cuts
warm startup CPU ~4x. Cache only active circuits on quota-limited clients.

### 2.3 Resident SAGE and scratch (5 Sep 2026)

`resident_repeated` via `measure_resident_repeated.py`: compact matrices,
13 workers, 22 self-verified proofs over two fresh processes per row (one
warm-up each, backend order reversed in round two). Inputs: one note in an
empty depth-30 tree, rest padded.

| Notes | Backend | Witness load | Proof median / p95 | Peak |
|---:|---|---:|---:|---:|
| 2 | Graph | 35.5 | 243.5 / 250.9 | 197.2 |
| 2 | SAGE, compile source | 49.7 | 245.4 / 250.8 | 166.1 |
| 2 | SAGE, compiled cache | 9.5 | 246.8 / 254.8 | 160.2 |
| 2 | Cache + scratch | 9.5 | 257.0 / 266.7 | 172.1 |
| 5 | Graph | 53.6 | 343.0 / 354.2 | 260.8 |
| 5 | SAGE, compiled cache | 15.2 | 354.5 / 965.9* | 213.2 |
| 10 | Graph | 91.1 | 589.3 / 607.6 | 455.9 |
| 10 | SAGE, compile source | 125.4 | 589.6 / 603.3 | 360.5 |
| 10 | SAGE, compiled cache | 27.2 | 591.3 / 600.3 | 355.0 |
| 10 | Cache + scratch | 25.2 | 611.9 / 622.1 | 384.1 |

\* Tail outliers on a shared workstation; not a service-latency estimate.

Scratch retained 41.2 / 45.9 / 87.9 MiB (2/5/10 notes) under a 128 MiB cap.

**Conclusion.** Cached SAGE cuts 10-note peak RSS 22% (455.9 -> 355.0) with
unchanged proof time and loads in 27 ms instead of 125 ms. Scratch costs ~3.5%
latency and ~29 MiB, so it stays opt-in.

### 2.4 Input boundaries

| Measurement (date) | Result |
|---|---|
| Long decimal input through `WitnessGraph::calculate_json` (7 Sep, 5 runs) | 4.31 / 5.65 / 8.75 / 16.36 / 30.60 ms for 1 / 2 / 4 / 8 / 15 MiB: linear |
| Assignment output, 262,144 fields, 7 runs (25 Aug) | JSON 67.820 ms / 20,828,749 B vs packed 1.953 ms / 8,388,608 B |
| Node indexed tree, 4,096 leaves, depth 16, 7 runs (25 Aug) | JSON 45.138 ms vs packed 44.299 ms (Poseidon dominates) |

### Re-run

```sh
cargo run --release --locked -p curvy-benchmarks --bin sage_cache -- SIGNET SIGNET_SHA256 client 7
cargo run --release --locked -p curvy-benchmarks --bin witness_input
cargo run --release --locked -p curvy-benchmarks --bin witness_boundary
cargo build --release --locked -p curvy-benchmarks --features scratch --bin resident_repeated
python3 tools/benchmarks/measure_resident_repeated.py target/release/resident_repeated ARTIFACTS.json "$OUT/repeated.json"
cargo run --release -p curvy-signet --example v2_parity_matrix -- signet-v2-parity.json
```

## 3. SPARROW streaming

### 3.1 Phase attribution (25 Aug 2026)

Same run as 1.1. Manifest parsing was below 0.1 ms everywhere. The proof phase
includes one zkey pass, per-chunk authentication, bucket reduction, proof and
self-verification.

| Notes | Cold SIGNET -> SAGE | Warm SAGE load | Witness cold / warm | Proof + verify cold / warm |
|---:|---:|---:|---:|---:|
| 2 | 34.0 | 9.5 | 18.6 / 18.1 | 338.3 / 338.9 |
| 5 | 51.1 | 14.5 | 26.4 / 26.2 | 459.5 / 454.1 |
| 10 | 84.5 | 25.0 | 43.8 / 42.5 | 794.6 / 788.4 |
| 50 | 351.5 | 102.7 | 170.0 / 167.6 | 3,183.3 / 3,185.7 |

### 3.2 Tuning starting points

| Target | Window policy | MSM chunk points |
|---|---|---:|
| Native | `StreamingConfig::native_adaptive()` | 524,288 |
| Browser or mobile baseline | fixed 13-bit window | 65,536 |
| Browser or mobile with measured headroom | fixed 13-bit window | 262,144 |

In the large browser profile, chunks above 524,288 points gave no latency gain
and raised footprint.

**Conclusion and selection policy.**

1. Native service, few circuits, provisioned memory, repeated proofs: HAWK
   `ResidentProver` (about 193 MiB to 1.70 GiB per initialized profile).
2. Browser, mobile or untrusted device memory: SPARROW in a dedicated worker.
3. Many simultaneously active large circuits: benchmark both; default to SPARROW
   when the summed resident keys are not comfortably below the memory limit.
4. One-shot CLI: HAWK for small circuits, SPARROW for the 50-note class.

Stale since: parallel window reduction of SPARROW buckets (1 Oct, commit
`250116e`). Its code comment records 3–7x for that phase alone; no end-to-end
re-measurement exists.

### Re-run

```sh
cargo run --release --locked -p curvy-prover --features sparrow --example zkey_chunk_manifest -- ZKEY OUT.manifest 1048576
cargo run --release --locked -p curvy-benchmarks --bin sparrow_manifest_wtns -- ZKEY ZKEY_SHA256 MANIFEST MANIFEST_SHA256 WTNS 13 adaptive 524288
cargo run --release --locked -p curvy-benchmarks --bin native_window_sweep -- ZKEY ZKEY_SHA256 MANIFEST MANIFEST_SHA256 WTNS 13 524288 8,9,10,11,12,13 5
```

Browser and mobile SPARROW runs use the harness in
[crates/prover/MOBILE_HARNESS.md](../crates/prover/MOBILE_HARNESS.md).

## 4. Resident loading and Node concurrency

### 4.1 Key loading (5 Sep 2026)

`whole_key_wtns --load-only`, 13 workers, nine fresh processes per cell after one
warm-up. Includes authentication, parsing, point spot checks and verifying-key
preparation; the manifest column includes reading and authenticating the manifest.

| Notes | Nested | Compact | Manifest + compact |
|---:|---:|---:|---:|
| 2 | 157.8 / 160.5 | 162.7 / 110.5 | 57.7 / 128.0 |
| 5 | 223.4 / 218.1 | 231.4 / 151.7 | 79.3 / 167.8 |
| 10 | 389.9 / 374.3 | 403.3 / 241.9 | 134.9 / 263.3 |

**Conclusion.** The manifest path is the startup win (10 notes: −65% time,
−30% RSS vs nested). Compact alone saves 35% RSS for ~3% more load time with the
current authenticated reader.

### 4.2 Node proof queue (6 Sep 2026)

`measure_node_concurrency.mjs`, 10-note graph, one `ResidentProver` with
13 workers and `maxPendingProofs: 8`, 32 proofs per level.

| Concurrency | Service median | Response median | Response p95 | Proofs/s |
|---:|---:|---:|---:|---:|
| 1 | 607.9 | 608.1 | 629.7 | 1.64 |
| 2 | 601.3 | 942.7 | 1,276.0 | 1.63 |
| 4 | 608.2 | 1,576.4 | 2,553.3 | 1.62 |
| 8 | 599.6 | 2,700.1 | 4,819.9 | 1.66 |

**Conclusion.** A single prover serializes; queueing adds latency, not capacity.
The admission bound only keeps waiting work finite. Scale with instances and
budget their worker pools together.

### 4.3 Node startup (25 Aug 2026)

Authenticated 256 MiB padded zkey, five runs: event-loop first-timer delay
117.853 ms with the synchronous constructor vs 1.496 ms with
`ResidentProver.create()`; total initialization stayed ~117.5 ms.

### Re-run

```sh
python3 tools/benchmarks/measure_reader_startup.py LOAD_CONFIG.json "$OUT/load.json"   # macOS only
npm run build --prefix bindings/node -- -- --locked
CURVY_BENCH_THREADS=13 node tools/benchmarks/measure_node_concurrency.mjs ARTIFACTS.json "$OUT/node.json"
```

## 5. Zkey reader startup (4 Sep 2026)

`measure_reader_startup.py`, `whole_key_wtns --load-only`, 9 fresh processes
per cell, 324 measured loads.

**The "previous" vs "fixed" reader comparison is invalid**: the archived
binaries had identical executable hashes within each matrix layout, so the
sweep did not measure the authenticated-reader fix. No valid measurement of that
overhead exists. Current default-reader load times are in 4.1.

Opt-in `zkey-single-pass`, from the same sweep (ms / MiB):

| Notes | Matrices | 1 worker | 13 workers |
|---:|---|---:|---:|
| 2 | Nested | 77.6 / 173.7 | 74.5 / 180.1 |
| 10 | Nested | 184.0 / 387.5 | 179.7 / 395.8 |
| 2 | Compact | 60.4 / 125.1 | 59.2 / 127.9 |
| 10 | Compact | 147.1 / 263.0 | 142.2 / 262.5 |

Stale since: the single-pass parser was placed behind `AuthenticatedReader`
(7 Sep, audit L4), adding a full authentication pass before parsing. These
numbers no longer describe it.

### Re-run

`LOAD_CONFIG.json` holds `samples`, `profiles` (`name`, `binary`, optional
`manifest: true`) and `cases` (`notes`, `threads`, `zkey`, `sha256`,
`zkey_bytes`, `constraints`, optional `manifest`/`manifest_sha256`). Build each
variant, copy the binary aside, and record `shasum -a 256` of every binary:
the comparison is meaningless unless the hashes differ.

## 6. Browser and WASM

### 6.1 Production proofs in Chromium 143 (6 Sep 2026)

`tools/browser/measure.mjs`, fresh browser process tree per case, one warm-up
plus five proofs, expected public signals checked. Synchronous on the page, so
this measures throughput and memory, not responsiveness.

| Notes | Portable default | Portable compact | Threaded compact, 4 workers |
|---:|---:|---:|---:|
| 2 | 4,478.8 / 776.4 | 4,681.9 / 735.6 | 1,451.6 / 746.7 |
| 5 | 6,275.7 / 965.6 | 6,308.4 / 909.4 | 2,071.5 / 923.5 |
| 10 | 11,709.5 / 1,420.4 | 11,595.5 / 1,319.5 | 3,728.1 / 1,360.6 |

**Conclusion.** Portable compact saves 41–101 MiB aggregate RSS at −4.5% to +1%
time; desktop results do not justify changing mobile defaults.

### 6.2 WASM signing throughput (7 Sep 2026)

`signing-boundary.cjs`, portable WASM on Node 22.22.3, output parity checked,
five samples of 100 calls. Before = pre-fix variable-time arithmetic.

| Operation | Before | After |
|---|---:|---:|
| Seed signing | 6.62 | 1.21 |
| Scalar signing incl. public self-verification | 13.00 | 8.35 |
| Seed public key | 3.18 | 0.582 |
| Scalar public key | 1.56 | 0.570 |

Stale since: fixed-width Poseidon (8 Sep) slowed the signing hash stage (7.4).

### 6.3 Module size

Optimized Poseidon tables (25 Aug): portable WASM raw −301,986 B (−11.8%), but
gzip 942,085 -> 1,173,605 B (+24.6%). Accepted: ~1.12 MiB compressed versus
the ~5 MB Go artifact it replaces.

### 6.5 Serial build on Curvy's proof path (1 Oct 2026)

The default serial build (no `parallel`, no `compact-matrix`: default native
Rust, the C FFI, portable and Node WASM) switched from stock ark-groth16 to
Curvy's proof assembly with batch-affine MSMs and `serial_window_bits`. Before =
`07a4aff`, after = the change; every proof self-verified and matched
`expectedPublics`. Native: `curvy-native-prover` default features, 1 thread, 9
ABBA rounds. Browser: Chromium 143.0.7499.4, `scripts/build-wasm.sh web`, 7 ABBA
rounds × (1 warm-up + 3 proofs); all 21 paired rounds were faster. Host load
4–15.

| Notes | Native proof ms | Native peak RSS MiB | Browser proof ms | Browser parse ms | Browser peak RSS MiB |
|---:|---:|---:|---:|---:|---:|
| 2 | 1,808.7 -> 1,523.4 (−15.8%) | 298.8 -> 241.5 (−19.2%) | 4,643.4 -> 3,989.7 (−14.1%) | 1,196.0 -> 1,207.9 | 777.9 -> 777.5 |
| 5 | 2,448.5 -> 1,998.1 (−18.4%) | 420.5 -> 324.9 (−22.7%) | 6,477.2 -> 5,194.3 (−19.8%) | 1,716.7 -> 1,713.4 | 968.2 -> 967.3 |
| 10 | 4,610.3 -> 3,587.5 (−22.2%) | 743.8 -> 565.8 (−23.9%) | 12,162.9 -> 9,407.6 (−22.7%) | 3,022.3 -> 3,036.4 | 1,421.1 -> 1,421.9 |

Browser memory does not move because the WASM heap peaks during authenticated
parse. Portable prover module 804,300 -> 780,221 B raw (−3.0%), gzip 279,797 ->
274,864 B. Serial window check (fixed widths for queries ≥ 4,096 points vs the
policy's 14/14/15 bits, 5 rounds): 13 bits −5.1% / −1.0% / +5.1%, 12 bits
−1.3% / +1.9% / +11.9%, 15 bits +8.5% at 2 notes; no width wins on all three,
so `serial_window_bits` is unchanged (noise ≈ 2%).

### 6.6 Threaded WASM after batch-affine (1 Oct 2026)

`build-wasm.sh web --threads`, 4 workers, `c620a33` (pre-batch-affine) vs the
current tree, 7 ABBA rounds × (1 warm-up + 5 proofs); every paired round faster.

| Notes | Before ms | After ms | Change | Peak RSS MiB |
|---:|---:|---:|---:|---:|
| 2 | 1,490.0 | 1,065.3 | −28.5% | 788.8 -> 791.3 |
| 5 | 2,123.8 | 1,457.9 | −31.4% | 980.8 -> 981.3 |
| 10 | 3,855.4 | 2,837.1 | −26.4% | 1,433.4 -> 1,434.2 |

Parse time and WASM heap unchanged. Threaded module 901,617 -> 936,440 B raw.

### 6.7 SPARROW browser window width (1 Oct 2026)

`tools/browser/sparrow-window.html` (one-pass manifest proofs, 65,536-point
chunks as in `StreamingConfig::default`, SIGNET v1 graphs compiled to SAGE,
1 MiB-chunk manifests). 6 rounds of a fresh browser per mode and circuit,
widths rotated in-page: 12 proofs per width. Threaded = 4 workers.

| Mode | Notes | w11 | w12 | w13 (default) | w14 |
|---|---:|---:|---:|---:|---:|
| portable | 2 | 4,154.8 (+3.0%) | 4,017.7 (−0.4%) | 4,032.0 | 4,252.5 (+5.5%) |
| portable | 5 | 5,677.0 (+6.5%) | 5,486.8 (+2.9%) | 5,331.2 | 5,511.3 (+3.4%) |
| portable | 10 | 11,121.4 (+8.2%) | 10,668.7 (+3.8%) | 10,283.0 | 10,137.6 (−1.4%) |
| threaded | 2 | 1,295.8 (+0.3%) | 1,312.4 (+1.5%) | 1,292.5 | 1,381.0 (+6.8%) |
| threaded | 5 | 1,810.4 (+2.9%) | 1,790.0 (+1.7%) | 1,759.6 | 1,799.8 (+2.3%) |
| threaded | 10 | 3,459.1 (+6.8%) | 3,423.3 (+5.7%) | 3,238.7 | 3,249.3 (+0.3%) |

**Conclusion.** No width beats 13 by ≥3% in either mode, so the browser default
stays 13 bits (unlike native, where 12 won: browsers stream 65,536-point
chunks, not 524,288). WASM heap peak 85.6 / 90.1 / 121.1 MiB portable, 93.0 /
96.2 / 129.2 MiB threaded; persistent G2 buckets 3.3 / 6.1 / 11.1 / 21.2 MB for
w11–w14.

### 6.8 Mobile: Samsung Galaxy Z Fold2 (1 Oct 2026)

First physical-device run. SM-F976B (Snapdragon 865, 8 logical CPUs, 8 GiB),
Android 10, Chrome 153, over USB (`adb reverse`, `http://localhost`, secure and
cross-origin isolated), charging at 49%. `crates/prover/js/mobile-harness.html`
in all-circuits mode: SPARROW threaded build (`build-wasm.sh web --threads --sparrow` at `6598555`),
8 workers, 13-bit windows, 65,536-point chunks, one-pass manifest proofs
(1 MiB chunks), trusted SAGE program pins (run 1 compiles and stores the
program; runs 2–3 load it from Cache API). Every proof self-verified and
matched `expectedPublics`.

| Notes | Proof + verify ms (runs 1/2/3) | Median | Prover init ms (cold / warm) |
|---:|---|---:|---:|
| 2 | 1,565 / 1,509 / 1,557 | 1,557 | 241 / 67–69 |
| 5 | 2,079 / 2,200 / 2,774 | 2,200 | 242 / 96–123 |
| 10 | 6,849 / 6,956 / 6,976 | 6,956 | 660 / 275–277 |

Module import + WASM + 8-worker pool startup: 92 ms (once). Peak page JS heap
209 MiB; origin storage 505 MiB after caching all three circuits.

**Reading.** 2 and 5 notes prove within ~1.2x of the desktop threaded SPARROW
numbers (6.7, 4 workers on Apple M-series), but 10 notes is ~2.1x slower than
desktop, so the largest client circuit hits a memory or bandwidth limit on this
device rather than scaling with points. The third 5-note run (+26%) suggests
thermal throttling after ~15 s of sustained proving. Not yet covered: the
portable build, 4- and 7-worker runs (the harness recommends leaving one CPU
free), longer thermal runs, and iOS/Safari. Raw report kept locally under
`tools/benchmarks/results/mobile-2026-10-01/` (not tracked).

### 6.9 Mobile A/B: SIMD MSM + FFT experiment (2 Oct 2026, branch `poc/wasm-simd`)

Same Fold2 (Chrome 154, Android 10, USB `adb reverse`, charging 59–63%).
Two harness servers served the same SPARROW profiles from different builds:
baseline (`build-wasm.sh web [--threads] --sparrow`) and SIMD
(`... --sparrow --simd`: `wasm-simd-msm` + `wasm-simd-fft`); each report
records the served build label and wasm SHA-256. 13-bit windows, 65,536-point
chunks, pinned SAGE cache, `Run all circuits` × 3 runs. All 72 proofs
self-verified and matched `expectedPublics`. Median proof + verify, seconds:

| Mode | 2 notes | 5 notes | 10 notes |
|---|---:|---:|---:|
| Portable | 7.36 -> 3.64 (−51%) | 10.96 -> 6.30 (−42%) | 19.96 -> 10.25 (−49%) |
| Threaded, 8 workers | 1.63 -> 1.13 (−30%) | 3.78 -> 2.14 (−43%) | 7.08 -> 4.22 (−40%) |
| Threaded, 7 workers | 2.49 -> 1.20 (−52%) | 4.08 -> 2.67 (−35%) | 8.28 -> 5.15 (−38%) |
| Threaded, 4 workers | 2.44 -> 2.03 (−17%) | 5.24 -> 2.97 (−43%) | 11.34 -> 6.52 (−42%) |

**Caveats.** Runs were not interleaved: SIMD threaded ran first (08:13–08:17),
baseline threaded and portable next (08:19–08:25), SIMD portable last
(08:26). The phone throttles within a run (e.g. SIMD portable 2 notes 2.23 ->
3.64 -> 4.72 s), so threaded deltas may flatter SIMD and the portable delta
may understate it. Treat these as "SIMD is faster in every configuration,
roughly 1.4–2x", not as precise ratios.

**Findings.** The gain on the phone is at least as large as on the M4 Pro
(desktop portable 1.83x). More workers win on this 1+3+4-core SoC: 8 workers
beat 4 by ~1.8x in both builds, so the SIMD FFT (active only at ≤4 workers)
does not offset dropping to 4 workers; intra-transform FFT parallelism would
be needed for it to help at 8.

### Re-run

```sh
scripts/build.sh wasm-web && scripts/build.sh wasm-web-threads
npm ci --prefix tools/browser --ignore-scripts && npx --prefix tools/browser playwright install chromium firefox
node tools/browser/serve.mjs CASES.json &   # benchmark cases on port 8127; see tools/browser/README.md
node tools/browser/measure.mjs "$OUT/browser.json" 2,5,10   # header comment documents A/B build mode
node tools/benchmarks/signing-boundary.cjs BEFORE_PKG_DIR crates/wasm/pkg-node
```

### 6.4 Nested vs compact matrices in Chromium (1 Oct 2026)

Question: should the shipped threaded and portable browser builds use
`--compact-matrix`? Rule: switch only if peak memory drops at least 15% and
median proof time is no more than 3% worse.

Chromium 143 (Playwright 1.57), headless, fresh browser per run, builds
alternated ABBA. Production 2/5/10-note keys (pins as above), cases from the
6 Sep fixtures. Threaded: 4 workers, 7 runs × (1 warm-up + 5 proofs). Portable:
7 runs × (1 warm-up + 3 proofs). Host heavily loaded by parallel builds
(load 9–49 on 14 cores), so absolute times run 5–15% slower than 6.1; the
ABBA deltas are the result. RSS is the browser process tree; "above base"
subtracts the ~269 MiB idle browser; WASM heap is the memory high-water mark.

| Notes | Build | Proof ms | Parse ms | Peak RSS MiB | Above base MiB | WASM heap MiB |
|---:|---|---:|---:|---:|---:|---:|
| 2 | threaded nested | 1,635.2 | 1,193.3 | 785.2 | 516.1 | 275.7 |
| 2 | threaded compact | 1,659.8 (+1.5%) | 1,173.5 | 746.7 (−4.9%) | 477.6 (−7.5%) | 236.2 (−14.3%) |
| 5 | threaded nested | 2,290.9 | 1,693.5 | 976.7 | 708.6 | 390.3 |
| 5 | threaded compact | 2,258.5 (−1.4%) | 1,661.4 | 920.5 (−5.8%) | 651.5 (−8.1%) | 334.1 (−14.4%) |
| 10 | threaded nested | 4,193.3 | 3,000.1 | 1,428.7 | 1,161.0 | 665.2 |
| 10 | threaded compact | 4,080.0 (−2.7%) | 2,914.4 | 1,356.9 (−5.0%) | 1,087.9 (−6.3%) | 580.2 (−12.8%) |
| 2 | portable nested | 4,797.8 | 1,230.3 | 775.0 | 505.7 | 267.6 |
| 2 | portable compact | 5,077.9 (+5.8%) | 1,174.0 | 735.4 (−5.1%) | 467.3 (−7.6%) | 228.4 (−14.6%) |
| 5 | portable nested | 6,758.6 | 1,759.1 | 965.6 | 696.8 | 382.2 |
| 5 | portable compact | 6,774.0 (+0.2%) | 1,656.6 | 908.6 (−5.9%) | 640.2 (−8.1%) | 326.5 (−14.6%) |
| 10 | portable nested | 12,612.2 | 3,128.7 | 1,418.4 | 1,149.1 | 657.1 |
| 10 | portable compact | 12,523.3 (−0.7%) | 2,860.9 | 1,318.0 (−7.1%) | 1,050.0 (−8.6%) | 558.0 (−15.1%) |

**Conclusion.** Neither shipped browser build switches. Compact saves 39–99 MiB,
but browser peak RSS falls only 5–7%: the WASM heap peaks during authenticated
parse, when it holds the raw zkey copy plus the parsed key (matrices are a small
share), and the page also keeps the fetched zkey. Portable compact is also
5.8% slower at 2 notes (slower in all 7 rounds). The native ~1014 -> 350 MiB
figure is a 2^24-domain projection and does not transfer to these keys.

```sh
# Builds outside the in-tree pkg-* dirs, then an ABBA comparison:
CURVY_WASM_OUT_DIR="$OUT/nested"  scripts/build-wasm.sh web --threads
CURVY_WASM_OUT_DIR="$OUT/compact" scripts/build-wasm.sh web --threads --compact-matrix
CURVY_BROWSER_BUILDS="$OUT/nested,$OUT/compact" node tools/browser/measure.mjs "$OUT/threaded.json" 2,5,10
# See the header of tools/browser/measure.mjs for portable mode and options.
```

## 7. Poseidon

### 7.1 Direct vs optimized schedule (25 Aug 2026)

`poseidon_schedules`, seven samples of 3,000 chained hashes per arity
(µs/hash). The protocol hashes at arities 1, 2, 3 and 5.

| Arity | Direct | Optimized | Speedup | Field multiplies |
|---:|---:|---:|---:|---:|
| 1 | 6.297 | 5.482 | 1.15x | 472 -> 416 |
| 2 | 11.035 | 7.753 | 1.42x | 828 -> 600 |
| 3 | 17.632 | 10.224 | 1.72x | 1,288 -> 784 |
| 5 | 38.170 | 16.725 | 2.28x | 2,772 -> 1,272 |
| 16 | 304.953 | 68.651 | 4.44x | 22,576 -> 5,168 |

The factored schedule saves exactly `R_P * (t - 1)^2` multiplications, so the
gain tracks arity. Merkle workloads (`poseidon_merkle`, 9 samples):
4,096-leaf depth-16 build 43.259 -> 30.532 ms; 256 inserts at depth 30
80.720 -> 57.311 ms (both −29%).

### 7.2 Lazy per-arity table decoding

15 fresh processes, first binary hash: eager 2.710 ms / 3,552 KiB vs lazy
0.046 ms / 1,944 KiB. Steady-state throughput unchanged.

### 7.3 Earlier change (25 Aug 2026)

Stack-buffer permutation (no per-round heap allocation): 50,000 chained binary
hashes, five runs, 11,939.1 -> 10,915.2 ns/hash (−8.6%).

### 7.4 Fixed-width backend (8 Sep 2026)

Both schedules moved to fixed-width BN254 arithmetic for timing safety. Signing
stage profile: the five-input hash stage went from 13–17 µs to 21–23 µs; whole
calls ~0.3 ms (seed) and 3.7–3.9 ms (scalar). No Merkle-throughput
re-measurement exists.

Stale since: 7.1 and 7.3 absolute numbers predate the fixed-width backend.

### Re-run

```sh
# The benchmark package depends on curvy-core with default-features = false (direct schedule).
cargo run --release --locked -p curvy-benchmarks --bin poseidon_schedules -- 3000 7
cargo run --release --locked -p curvy-benchmarks --features poseidon-optimized --bin poseidon_schedules -- 3000 7
cargo run --release --locked -p curvy-benchmarks --features poseidon-optimized --bin poseidon_schedules -- --cold-only
cargo run --release --locked -p curvy-benchmarks --features poseidon-optimized --bin poseidon_merkle
cargo test -p curvy-core --locked --release --all-features optimized_schedule_matches_160k_reference_cases -- --ignored
```

## 8. Leakage and constant-time testing

Methodology and annotations: [tools/leakage/README.md](../tools/leakage/README.md).
Scope and limits: [security.md](security.md#constant-time-scope). dudect
threshold is `|t| > 10`; the variable-time affine multiplier is a required
positive control.

### 8.1 Native dudect, Apple M4 Pro (7 and 8 Sep 2026)

Maximum `|t|`, fixed/random then sparse/dense. 131,028 analyzed samples per
focused check.

| Operation | 7 Sep | 8 Sep (hardened Poseidon) |
|---|---:|---:|
| Affine multiplier (control) | 509.78 / 2,246.97 | 398.28 / 1,776.11 |
| `base_mul` | 6.38 / 3.14 | 1.44 / 1.72 |
| `reduce_wide`, `nonce_candidate`, `response` | all ≤ 1.94 | not rerun |
| BLAKE-512 | 1.73 / 1.22 | not rerun |
| Poseidon, private input | **341.97** / 5.70 | 1.96 / 1.20 |
| Decimal conversion (via owner hash on 8 Sep) | 2.15 / 1.80 | 1.71 / 2.77 |
| Seed signing, complete call | **26.29** / 1.65 | 2.71 / 3.16 |
| Scalar signing, complete call | **61.82 / 137.95** | not rerun (see 8.4) |

### 8.2 Secret-taint (Valgrind 3.19.0 Memcheck, Linux arm64 container)

`rust@sha256:365468470075493dc4583f47387001854321c5a8583ea9604b297e67f01c5a4f`.
Final 8 Sep run: the control and the optional arkworks Poseidon flag
secret-dependent control flow; private-input Poseidon (all 16 arities), decimal
conversion, complete seed signing and complete scalar signing show no
secret-dependent branches or addresses. An earlier 8 Sep run caught branches in
compiled modular add/negate during decimal accumulation; they were removed with
explicit selection behind a ctutils optimization barrier (nothing declassified).

### 8.3 Browser engines (best effort)

| Date | Engine | Calls per check | Timer tick | Signals beyond controls |
|---|---|---:|---:|---|
| 7 Sep | Chromium 143 | 30,000 | 5 µs | seed signing (f/r), scalar signing (both), Poseidon private (f/r) |
| 7 Sep | Firefox 144 | 1,024–30,000 | 20 µs | scalar signing (s/d) |
| 8 Sep | Chromium 143 | 9,216–30,000 | 5 µs | scalar signing (both) |
| 8 Sep | Firefox 144 | 1,024–30,000 | 20 µs | scalar signing (s/d) |

On 8 Sep neither engine detected private-input Poseidon, decimal conversion or
seed signing. Both detected both controls.

### 8.4 Signing stage attribution (8 Sep 2026)

`run.py phases`, 30,000 samples per profile and family (`|t|`, before -> after).

| Stage | Before | After |
|---|---:|---:|
| Seed challenge hash, f/r | 111.08 | 0.26 |
| Seed whole call, f/r | 13.01 | 1.09 |
| Scalar challenge hash, f/r | 67.08 | 0.62 |
| Scalar public verification, s/d | 49.17 | 63.60 |
| Scalar whole call, s/d | 44.64 | 58.82 |

The remaining scalar-signing difference (115 µs s/d, 44 µs f/r) sits in public
signature verification: the public replay needs 264 vs 238 affine additions
(502 doublings each), determined by public scalars.

### Re-run

```sh
python3 tools/leakage/run.py dudect --out "$OUT/dudect" --samples 200000 --allow-variable-time sign_scalar
python3 tools/leakage/run.py timecop --out "$OUT/timecop"          # Linux + Valgrind headers
python3 tools/leakage/run.py phases --out "$OUT/phases" --samples 30000
node tools/leakage/public-transcripts.cjs "$OUT/public-transcripts.json"
bash tools/leakage/build-wasm.sh
node tools/leakage/wasm.mjs "$OUT/wasm" 30000 chromium firefox --seconds-per-case=60 \
  --cases=poseidon_secret,owner_hash_decimal,sign_seed,sign_scalar
```

`.github/workflows/leakage.yml` runs dudect and timecop weekly on GitHub-hosted
Linux x86-64 and arm64; no result from it is recorded here.


## 9. MSM bucket accumulation (1 Oct 2026)

Batch-affine accumulation (`AffineBuckets` in `crates/prover/src/msm.rs`):
affine buckets, additions batched so every bucket in a batch is distinct, one
shared inversion per batch (Montgomery's trick). Doubling, `P + (-P)` and
identity bases are classified before the inversion; points whose bucket is
already scheduled are deferred, and repeatedly hit buckets fall back to XYZZ
overflow buckets so adversarial digit patterns cost about the old XYZZ price.
Resident BN254 G1/G2 MSMs use it from 4,096 points (`BATCH_AFFINE_MIN_POINTS`);
SPARROW keeps affine buckets across chunks at every size. Parallel and SPARROW
adaptive windows were retuned (`adaptive_window_bits`):

| Points | Before | After |
|---:|---:|---:|
| 4,096–16,383 | 8 | 10 |
| 16,384–65,536 | 8–9 | 12 |
| 65,537–524,288 | 10–11 | 12 (13 on synthetic data; see the real-key sweep below) |
| > 524,288 | 12–13 | 14 |

Host: reference Apple M-series, 14 cores, loaded by parallel builds (load
5–50); every comparison interleaves before/after samples and checks the two
results are the same group element. Uniform scalars, median ms, 7–9 samples.

**Resident MSM, 13 Rayon workers** (before = XYZZ with old widths):

| Points | G1 before | G1 after | G2 before | G2 after |
|---:|---:|---:|---:|---:|
| 2^12 | 2.52 | 2.17 (−13.9%) | 7.88 | 5.41 (−31.4%) |
| 2^14 | 9.57 | 6.99 (−26.9%) | 27.45 | 16.36 (−40.4%) |
| 2^16 | 33.76 | 21.25 (−37.1%) | 107.46 | 54.20 (−49.6%) |
| 2^18 | 111.93 | 80.80 (−27.8%) | 343.33 | 224.94 (−34.5%) |
| 2^20 | 416.23 | 317.45 (−23.7%) | 1,462.4 | 921.7 (−37.0%) |

**Resident MSM, 1 worker, same widths before and after:** G1 −12% (2^12) to
−27% (2^20); G2 −28% to −41%. Below 4,096 points the code is unchanged
(21-sample reruns within ±2%). Accumulator alone at a fixed width: G1 −20 to
−27%; the rest of the parallel gain is the wider windows. Witness-like scalars
(¼ each 0, 1, 64-bit, uniform): G1 parallel +1.0% at 2^12, −21 to −25% from
2^13. All scalars = 1 (one bucket): +0.3 to +3.2% (≈1 ms at 2^12).

**SPARROW query MSM** (decode + streamed accumulation + reduction; before =
projective buckets; 14 samples):

| Points | Parallel G1 | Parallel G2 | Serial G1 (w13) | Serial G2 (w13) |
|---:|---:|---:|---:|---:|
| 2^12 | 3.81 -> 2.48 (−34.8%) | 9.15 -> 5.72 (−37.5%) | 35.9 -> 27.3 (−24.0%) | 107.3 -> 81.8 (−23.7%) |
| 2^16 | 50.96 -> 23.81 (−53.3%) | 117.2 -> 60.5 (−48.4%) | 283.0 -> 178.0 (−37.1%) | 773.5 -> 462.7 (−40.2%) |
| 2^18 | 147.8 -> 92.0 (−37.8%) | 469.3 -> 241.0 (−48.7%) | 1,066.7 -> 659.8 (−38.1%) | — |
| 2^20 | 524.3 -> 304.1 (−42.0%) | — | — | — |

Profile (single thread, G1 2^20): accumulation is ~95% of MSM time before and
after; inside batch-affine accumulation, field multiplication ~60%, squaring
~8%, batch apply ~22%, scheduling ~6%, inversion ~4% (one inversion ≈ 165
multiplications). Memory (computed): SPARROW browser default (w13) buckets G1
7.9 -> 5.2 MB, G2 15.7 -> 10.5 MB; native adaptive at 2^20 (w12 -> w14) G1
4.3 -> 10 MB, G2 8.7 -> 20 MB; resident +≈0.7/1.4 MB per running window.

**Whole proofs, production keys** (`curvy-native-prover`, release, before =
`b3578e9`, after = this change; 6 rounds alternating, median proof-generation
ms; every proof self-verified and matched `expectedPublics`; witness and load
times unchanged within noise):

| Notes | Features | 1 thread | 8 threads |
|---:|---|---:|---:|
| 2 | parallel | 2,009.6 -> 1,470.9 (−26.8%) | 328.6 -> 240.5 (−26.8%) |
| 2 | compact-matrix,parallel | 1,981.0 -> 1,440.2 (−27.3%) | 325.7 -> 237.1 (−27.2%) |
| 5 | parallel | 2,824.8 -> 1,933.4 (−31.6%) | 456.1 -> 315.6 (−30.8%) |
| 5 | compact-matrix,parallel | 2,892.5 -> 1,980.6 (−31.5%) | 443.4 -> 307.6 (−30.6%) |
| 10 | parallel | 5,182.4 -> 3,696.1 (−28.7%) | 739.5 -> 609.7 (−17.6%) |
| 10 | compact-matrix,parallel | 5,136.9 -> 3,684.3 (−28.3%) | 746.8 -> 607.5 (−18.7%) |

`CURVY_PROVER_NUM_THREADS` selects the pool size (default 1). At the time of
this run, builds without `parallel` or `compact-matrix` still used stock
ark-groth16; they now use the same path (6.5).

**Real-key window check.** The table above was first tuned on synthetic
scalars, which put 65,537–524,288 points at 13 bits. Production witnesses have
many small values and favor narrower windows, so it was re-checked on the
2/5/10-note keys (queries of 150k–520k points). SPARROW: `native_window_sweep`
(chunk manifests at 1 MiB, snarkjs witnesses, 7 samples, median ms of one
self-verified proof; `adaptive` was 13 bits at the time):

| Notes | Threads | 11 | 12 | 13 | 14 | 16 | adaptive (13) |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 2 | 8 | 266.1 | **264.7** | 273.2 | 291.5 | 325.9 | 274.1 |
| 5 | 8 | 362.3 | **340.0** | 362.9 | 375.5 | 395.0 | 358.2 |
| 10 | 8 | 696.1 | **649.4** | 675.4 | 674.5 | 650.9 | 680.0 |
| 2 | 13 | 243.6 | **235.8** | 243.2 | 249.0 | 349.2 | 249.4 |
| 5 | 13 | 328.2 | 327.2 | 341.2 | 330.7 | 411.6 | **320.1** |
| 10 | 13 | 590.6 | 560.1 | 545.0 | **526.5** | 583.9 | 555.1 |

Whole resident proofs (`curvy-native-prover --features parallel`, 9 rounds
alternating) with the band at 12 instead of 13: 8 threads −5.5% / −4.5% /
−2.5% (2/5/10 notes); 13 threads +2.5% / −2.0% / −2.4%. Twelve wins or ties in
10 of 12 comparisons, so 16,384–524,288 points now use 12 bits. Host load was
8–13 during these runs.

`sparrow::phase_bench` (`phase_kernels`, and the browser phase page) times the
production SPARROW kernel (`accumulate_affine_windows`, affine buckets) on one
chunk of synthetic pairs. 1 Oct, 8 threads: G1 2^17 w13 17.96 ms, G2 2^16 w13
23.80 ms. Earlier `phase_kernels` numbers timed projective buckets and are not
comparable.

```sh
cargo run --release --locked -p curvy-benchmarks --bin msm_accumulation -- compare g1 12,14,16,18,20 13 9 uniform
cargo run --release --locked -p curvy-benchmarks --bin msm_accumulation -- sweep g1 16 13 10,12,13,14 xyzz,affine
cargo run --release --locked -p curvy-benchmarks --bin msm_accumulation -- profile g1 20 15 affine
# SPARROW query MSM (see the usage text in the bin for argument order;
# build with --no-default-features for the serial variant):
cargo run --release --locked -p curvy-benchmarks --bin sparrow_query_msm -- g1 16 13 0 524288
# Real keys: manifest from the zkey_chunk_manifest example, witness from snarkjs.
cargo run --release --locked -p curvy-benchmarks --bin native_window_sweep -- ZKEY ZKEY_SHA256 MANIFEST MANIFEST_SHA256 WTNS 8 524288 11,12,13,14,16,adaptive 7
```

## Recording a new result

Record artifact digests, assignment/domain size, target, worker count, window
policy, MSM chunk size, allocator, warm/cold file state, sample count, proof
verification, peak-memory method, and the SHA-256 of every executable. For
browsers also record engine/OS/device, cross-origin isolation, WASM variant,
worker placement and thermal state. Do not run timing alongside builds. Adopt a
setting only when repeated self-verifying runs beat the current policy by more
than run-to-run noise.
