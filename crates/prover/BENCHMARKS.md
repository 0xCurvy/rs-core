# Prover benchmarks

Current resident loader, SAGE, queue, and scratch results are in
[the 5 September report](../../RESIDENT_OPTIMIZATIONS.md). The earlier
[reader comparison](../../READER_STARTUP_BENCHMARKS.md) has a correction: its
previous/fixed binary labels did not identify distinct builds.

These measurements help integrators choose between the HAWK `ResidentProver`
and SPARROW `StreamingProver`, and decide whether an origin-local SAGE cache is
worthwhile. They are reference points, not capacity guarantees.

## Method

The native comparison used an Apple M4 Pro with 14 CPU cores and 48 GiB of RAM,
a release build, 13 Rayon threads, warm local files, and authenticated artifacts.
Each timing is the median of seven alternating runs after one warm-up. Every
proof self-verified. Peak RSS came from a separate macOS `time -l` run at the
same configuration.

The two representative circuits are identified by assignment size instead of a
product-specific circuit name:

- medium: 224,505 BN254 witness fields;
- large: 1,583,596 BN254 witness fields.

`SPARROW total` includes authenticated SAGE loading, input evaluation, manifest
decoding, one authenticated zkey pass, proof construction, and
self-verification. `Whole-key total` includes SIGNET v2 and compact-matrix zkey
loading, input evaluation, proof construction, and self-verification.

## Resident prover (HAWK) compared with streaming prover (SPARROW)

| Circuit | Warm SPARROW total | Optimized whole-key total | Latency difference | SPARROW RSS | Whole-key RSS | RSS reduction |
|---|---:|---:|---:|---:|---:|---:|
| Medium | 495.155 ms | 482.349 ms | +2.7% | 205.7 MiB | 253.8 MiB | 19.0% |
| Large | 3,455.497 ms | 3,453.205 ms | +0.1% | 506.3 MiB | 1,696.0 MiB | 70.1% |

On these profiles, SPARROW preserved approximately the whole-key latency while
substantially reducing peak memory. The benefit grows with proving-key size
because SPARROW retains one bounded query batch and bucket set rather than the
complete proving key.

Do not extrapolate these ratios to a different curve, proving-key layout, CPU,
browser, or memory allocator. Re-run the paired comparison on the deployment
target.

## SAGE first use and warm load

The SAGE cache comparison measures CPU work only. File reads and browser Cache
API writes are excluded. A cold run authenticates and compiles the SIGNET graph,
serializes `SAGEPC01`, hashes it, and validates one round-trip load. A warm run
hashes and validates the stored program.

| Circuit | SIGNET source | SAGE program | Cold CPU | Warm load |
|---|---:|---:|---:|---:|
| Medium | 1.62 MiB | 18.62 MiB | 75.614 ms | 18.772 ms |
| Large | 9.43 MiB | 125.67 MiB | 514.306 ms | 127.210 ms |

The cache trades origin quota and higher first-use peak memory for lower warm
startup CPU. Cache only active circuit profiles on quota-constrained devices.
The source SIGNET digest remains authoritative; a cached program is derived
state and must be validated on every load.

## Tuning guidance

Native SPARROW should start with `StreamingConfig::native_adaptive()`. The measured
query-size policy selects smaller windows for small queries and larger windows
for large queries. Browser and mobile builds should use fixed settings measured
on their target devices.

The following settings are useful starting points, not universal defaults:

| Target | Window policy | MSM chunk points |
|---|---|---:|
| Native | `native_adaptive()` | 524,288 |
| Browser or mobile baseline | fixed 13-bit window | 65,536 |
| Browser or mobile with measured headroom | fixed 13-bit window | 262,144 |

Larger chunks can reduce boundary overhead but increase transient memory. In the
measured large-browser profile, increasing beyond 524,288 points produced no
material latency improvement and raised process footprint.

## Reproduce the comparison

Benchmark binaries live in the non-published `curvy-benchmarks` workspace
package. They are excluded from the `curvy-prover` crate archive.

Run a paired whole-key and one-pass comparison:

```bash
cargo run --release -p curvy-benchmarks --bin whole_key_wtns -- \
  circuit.zkey ZKEY_SHA256 circuit.wtns 13

cargo run --release -p curvy-benchmarks --bin sparrow_manifest_wtns -- \
  circuit.zkey ZKEY_SHA256 circuit.manifest MANIFEST_SHA256 \
  circuit.wtns 13 adaptive 524288
```

Measure SAGE cache startup:

```bash
cargo run --release -p curvy-benchmarks --bin sage_cache -- \
  circuit.signet GRAPH_SHA256 client 7
```

Sweep native window widths:

```bash
cargo run --release -p curvy-benchmarks --bin native_window_sweep -- \
  circuit.zkey ZKEY_SHA256 circuit.manifest MANIFEST_SHA256 \
  circuit.wtns 13 524288 8,9,10,11,12,13 5
```

Record the exact artifact digests, target, worker count, window policy, chunk
sizes, crate commit, sample count, and peak-memory method with the result. A
configuration should be adopted only when repeated self-verifying runs beat the
starting policy by more than normal thermal and scheduling noise.
