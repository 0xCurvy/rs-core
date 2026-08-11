# Prover benchmarks

These measurements help integrators choose between the ordinary whole-key
prover and SPARROW, and decide whether an origin-local SAGE cache is worthwhile.
They are reference points, not capacity guarantees.

## Method

The native comparison used an Apple M4 Pro with 14 CPU cores and 48 GiB of RAM,
a release build, 13 Rayon threads, warm local files, and authenticated artifacts.
Each timing is the median of three paired runs. Every proof self-verified. Peak
RSS came from a separate macOS `time -l` run at the same configuration.

The two representative circuits are identified by assignment size instead of a
product-specific circuit name:

- medium: 224,505 BN254 witness fields;
- large: 1,583,596 BN254 witness fields.

`SPARROW total` includes WTNS and manifest decoding, one authenticated zkey pass,
proof construction, and self-verification. `Whole-key total` includes zkey read,
authentication, parsing, the same WTNS, proof construction, and
self-verification.

## Whole-key prover compared with SPARROW

| Circuit | SPARROW total | Whole-key total | Latency difference | SPARROW RSS | Whole-key RSS | RSS reduction |
|---|---:|---:|---:|---:|---:|---:|
| Medium | 463 ms | 451 ms | +2.7% | 167.8 MiB | 440.4 MiB | 61.9% |
| Large | 3.208 s | 3.188 s | +0.6% | 541 MiB | 2.83 GiB | 81.3% |

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
| Medium | 1.62 MiB | 18.62 MiB | 77.4 ms | 18.7 ms |
| Large | 9.43 MiB | 125.67 MiB | 536.7 ms | 128.2 ms |

The cache trades origin quota and higher first-use peak memory for lower warm
startup CPU. Cache only active circuit profiles on quota-constrained devices.
The source SIGNET digest remains authoritative; a cached program is derived
state and must be validated on every load.

## Tuning guidance

Native SPARROW should start with `SparrowConfig::native_adaptive()`. The measured
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
