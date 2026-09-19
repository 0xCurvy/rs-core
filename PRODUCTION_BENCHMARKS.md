# Production proving benchmark

Current implementation and audit status: [6 September follow-up](SECURITY_PERFORMANCE_AUDIT.md). This document retains historical context and measurements.

Measurements and validation status as of 25 August 2026. This report uses the
four deployed pending-notes-commitment v2 proving keys, not padded or synthetic
stand-ins.

The [4 September reader-startup follow-up](READER_STARTUP_BENCHMARKS.md)
measures the audit's authentication fix against the previous reader on the
available 2-, 5-, and 10-note keys. The end-to-end results below remain the
25 August measurements.

## Result in one table

The four profiles below distinguish cold process startup from a cached witness
program. Every one of the 112 timed proofs self-verified.

| Notes | Stock resident baseline | HAWK resident | Change | SPARROW cold | Change | SPARROW warm | Change | Warm SPARROW vs HAWK |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 2 | 372.662 ms | 343.186 ms | 7.9% faster | 390.763 ms | 4.9% slower | 366.750 ms | 1.6% faster | 6.9% slower |
| 5 | 528.679 ms | 482.349 ms | 8.8% faster | 536.929 ms | 1.6% slower | 495.155 ms | 6.3% faster | 2.7% slower |
| 10 | 913.909 ms | 831.957 ms | 9.0% faster | 924.433 ms | 1.2% slower | 855.354 ms | 6.4% faster | 2.8% slower |
| 50 | 3,805.512 ms | 3,453.205 ms | 9.3% faster | 3,706.934 ms | 2.6% faster | 3,455.497 ms | 9.2% faster | 0.1% slower |

Peak process RSS makes the path choice clearer:

| Notes | Stock resident baseline | HAWK resident | Reduction | SPARROW cold | Reduction | SPARROW warm | Reduction |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 2 | 250.7 MiB | 192.6 MiB | 23.2% | 171.1 MiB | 31.8% | 163.0 MiB | 35.0% |
| 5 | 334.9 MiB | 253.8 MiB | 24.2% | 188.4 MiB | 43.7% | 205.7 MiB | 38.6% |
| 10 | 573.7 MiB | 455.9 MiB | 20.5% | 255.5 MiB | 55.5% | 246.6 MiB | 57.0% |
| 50 | 2,291.7 MiB | 1,696.0 MiB | 26.0% | 591.0 MiB | 74.2% | 506.3 MiB | 77.9% |

The profiles mean:

| Profile | Witness artifact | Key representation | Key execution | Poseidon |
|---|---|---|---|---|
| Stock resident baseline | SIGNET v1 | nested arkworks matrices | authenticate, parse and retain the whole key | direct reference at the application boundary |
| HAWK resident | SIGNET v2 | compact CSR matrices | authenticate, parse and retain the whole key | optimized default at the application boundary |
| SPARROW cold | SIGNET v2 compiled to SAGE in this process | not materialized | one-pass manifest-authenticated stream | optimized default at the application boundary |
| SPARROW warm | authenticated precompiled SAGE | not materialized | one-pass manifest-authenticated stream | optimized default at the application boundary |

Compact matrices are deliberately **not applicable** to SPARROW. The compact
representation improves a retained whole key; SPARROW streams query sections
into bounded MSM buckets and never constructs constraint matrices. Combining
both in one proof would add work without retaining either design's advantage.

Poseidon is also reported separately below. These end-to-end prover fixtures
begin with an already-built circuit input JSON. SIGNET/SAGE evaluates the
compiled circuit operations and does not call `curvy-core::poseidon`, so adding
the standalone Poseidon win to these totals would double-count work that is not
present. Optimized Poseidon speeds the application's tree, note, and circuit
input preparation before this measured proving boundary.

## Method

- Host: Apple M4 Pro, 10 performance plus 4 efficiency cores, 48 GB RAM.
- OS/toolchain: macOS 26.5.1, Rust 1.94.0, Node 22.22.3.
- Repository base: `e17b71116bcd8c68795df3c1a4f7cec32b3068a8`, plus the
  optimization work recorded in this report.
- Build: Rust release profile, 13 Rayon workers, warm local files.
- SPARROW: native adaptive Pippenger windows, 524,288-point MSM chunks,
  authenticated 1 MiB zkey chunks.
- Timing: one warm-up followed by seven samples per profile and circuit. Profile
  order alternated on each sample. Standard deviation is population standard
  deviation.
- Memory: a separate process per profile under macOS `/usr/bin/time -l`; peak
  RSS is a high-water mark, not retained idle memory.
- Correctness: each timed path generated a randomized Groth16 proof and
  self-verified it before returning.

The reusable runner is `tools/benchmarks/measure_profiles.mjs`. The native
harnesses are `whole_key_signet`, `sparrow_manifest_signet`, and
`sparrow_manifest_sage` in the non-published `curvy-benchmarks` package.

## Timing distributions

Ranges are min/median/max in milliseconds, followed by standard deviation.

| Notes | Profile | Total range | Standard deviation |
|---:|---|---:|---:|
| 2 | Stock whole | 367.732 / 372.662 / 389.443 | 6.499 |
| 2 | Optimized whole | 336.523 / 343.186 / 350.064 | 4.177 |
| 2 | Stream, cold | 386.265 / 390.763 / 408.469 | 7.099 |
| 2 | Stream, warm | 359.858 / 366.750 / 383.765 | 7.603 |
| 5 | Stock whole | 523.967 / 528.679 / 538.317 | 5.453 |
| 5 | Optimized whole | 467.791 / 482.349 / 486.391 | 7.236 |
| 5 | Stream, cold | 523.722 / 536.929 / 548.683 | 7.011 |
| 5 | Stream, warm | 485.333 / 495.155 / 506.718 | 7.823 |
| 10 | Stock whole | 905.157 / 913.909 / 927.892 | 7.298 |
| 10 | Optimized whole | 814.467 / 831.957 / 841.268 | 9.910 |
| 10 | Stream, cold | 910.936 / 924.433 / 934.979 | 7.649 |
| 10 | Stream, warm | 846.440 / 855.354 / 930.988 | 27.288 |
| 50 | Stock whole | 3,736.112 / 3,805.512 / 3,811.011 | 24.683 |
| 50 | Optimized whole | 3,422.691 / 3,453.205 / 3,482.467 | 19.766 |
| 50 | Stream, cold | 3,668.324 / 3,706.934 / 3,816.740 | 43.141 |
| 50 | Stream, warm | 3,416.161 / 3,455.497 / 3,591.576 | 62.152 |

### Whole-key phase attribution

The dominant end-to-end improvement comes from SIGNET v2 plus compact zkey
loading. Proof latency is unchanged within normal run-to-run noise.

| Notes | Stock bundle load | Optimized bundle load | Change | Stock witness | Optimized witness | Change | Stock proof + verify | Optimized proof + verify | Change |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 2 | 123.274 ms | 91.603 ms | 25.7% faster | 18.027 ms | 18.026 ms | 0.0% | 231.572 ms | 234.146 ms | 1.1% slower |
| 5 | 179.681 ms | 131.596 ms | 26.8% faster | 27.039 ms | 26.201 ms | 3.1% faster | 321.104 ms | 323.982 ms | 0.9% slower |
| 10 | 308.687 ms | 224.365 ms | 27.3% faster | 44.954 ms | 43.235 ms | 3.8% faster | 561.754 ms | 558.549 ms | 0.6% faster |
| 50 | 1,283.189 ms | 936.623 ms | 27.0% faster | 178.111 ms | 176.757 ms | 0.8% faster | 2,333.733 ms | 2,345.596 ms | 0.5% slower |

If a service retains an initialized optimized whole-key prover, it avoids the
bundle-load phase on subsequent proofs. Adding the median witness and proof
phases gives approximately 252, 350, 602, and 2,522 ms for 2/5/10/50 notes.
Warm SPARROW is then about 45%, 41%, 42%, and 37% slower respectively because it
rereads and reduces the zkey for every proof. This is the main latency reason to
choose a resident whole-key service when memory is already provisioned.

### Streaming phase attribution

| Notes | Cold SIGNET -> SAGE compile | Warm SAGE read + authenticated load | Cold witness | Warm witness | Cold SPARROW proof + verify | Warm SPARROW proof + verify |
|---:|---:|---:|---:|---:|---:|---:|
| 2 | 33.995 ms | 9.503 ms | 18.573 ms | 18.149 ms | 338.263 ms | 338.864 ms |
| 5 | 51.100 ms | 14.540 ms | 26.378 ms | 26.194 ms | 459.516 ms | 454.111 ms |
| 10 | 84.546 ms | 24.985 ms | 43.831 ms | 42.540 ms | 794.557 ms | 788.448 ms |
| 50 | 351.521 ms | 102.695 ms | 170.007 ms | 167.628 ms | 3,183.279 ms | 3,185.677 ms |

Manifest parsing is below 0.1 ms at every size. The proof phase includes one
zkey pass, per-chunk authentication before unchecked point parsing, bounded MSM
reduction, proof creation, and self-verification.

## Production artifacts

### Proving keys and witnesses

| Notes | Zkey bytes | WTNS bytes | Constraints | Witness fields | Zkey SHA-256 |
|---:|---:|---:|---:|---:|---|
| 2 | 91,785,620 | 4,782,540 | 150,769 | 149,452 | `dea6b15860701dee9c77ee2a6916ccda7735590012572d526a3714f8e429ed33` |
| 5 | 129,200,756 | 7,184,236 | 226,236 | 224,505 | `efb4c3d4d3350f931860faeb6319b6010303c5fbf06d8ef414d708e9cf907847` |
| 10 | 227,925,172 | 12,431,308 | 391,313 | 388,476 | `6986b1a778c87fe3cc29c31b74785e62e8e987b0ddc885fd9062265e6c037d22` |
| 50 | 925,400,177 | 50,675,148 | 1,594,033 | 1,583,596 | `cdb5cdff6bbb9a58d9cce8d811811d8244e6851ecdf6fabb2e90704416af62ee` |

### SIGNET v2 provenance and parity

The graphs were generated from the exact production circuit sources. The
generation script first confirmed that its original and operation-schema-patched
`circom --O2` outputs had byte-identical R1CS files. The locked producer was
`curvy-signet-builder 0.1.0-rc.1`; its executable SHA-256 was
`5a05ed1b05c29323e247a4cafa3f2cbfc579d8b0d82236af098e9985b94ec6a5`.

Every v1 and v2 artifact was independently evaluated and compared field for
field with the corresponding snarkjs WTNS. The canonical full-assignment hashes
below therefore cover all 2,346,029 witness fields, not only public outputs.

| Notes | R1CS SHA-256 | Producer postcard | Upstream nodes | Final SIGNET nodes | Assignment SHA-256 |
|---:|---|---:|---:|---:|---|
| 2 | `d3318087ee07708ae52c644c7a7f7015eee0b943d4fe7b0451842d26242cb136` | 5,837,665 B | 2,931,941 | 729,816 | `84315ec72b9b0794849d863b36eb277ffc8061f54496dac1cdf55226b5b7d1b9` |
| 5 | `150cc21f7bb6384a6b691a299319b86fc9bc69a361d7a52a3895f0792e5b1a44` | 9,026,876 B | 4,186,959 | 1,106,576 | `d47c6f9b4e22987c496647f8c0e3cd5f475cdbea4a9406545f52c11c28fee30c` |
| 10 | `e65ad1be09a3f1c1c95ee84c57d8e5c896660ea1f1cf064495887bd23fa934e3` | 15,117,345 B | 7,099,221 | 1,848,663 | `300788eb149d647f97bead0c92dc22f0b1c40c8a8df461a3e26bd23ae7a9a473` |
| 50 | `dbe303161a71ce23e19876e45edee5e8503c372d25bd26802e0f974e7d941dbb` | 70,841,012 B | 27,935,601 | 7,442,816 | `befb95e7edc3c79267ab1f155c8a48ca7a6560f242c0304e01a1102ee490d6d1` |

SIGNET v2 reduces the canonical operation body, not its semantics:

| Notes | v1 raw | v2 raw | Reduction | v1 zstd -9 | v2 zstd -9 | Reduction |
|---:|---:|---:|---:|---:|---:|---:|
| 2 | 7,912,521 B | 3,371,554 B | 57.4% | 3,098,974 B | 1,178,187 B | 62.0% |
| 5 | 11,978,841 B | 5,040,445 B | 57.9% | 4,703,448 B | 1,697,063 B | 63.9% |
| 10 | 20,055,807 B | 8,382,744 B | 58.2% | 7,852,559 B | 2,759,980 B | 64.9% |
| 50 | 80,771,417 B | 35,635,673 B | 55.9% | 31,639,881 B | 9,886,519 B | 68.8% |

| Notes | v1 compressed SHA-256 | v2 compressed SHA-256 |
|---:|---|---|
| 2 | `73241359eec29d2f19516ca4daa04ad2c1a893782b692c598885c33c58415822` | `c2f8da1dd7f3ae23ffe64c754ba1e6d720229d459ae348f2a66319b8523bd27a` |
| 5 | `69fa449825732a0958ccd0689ad361d9e8df1223231d8b71932d0efc4a07d8f0` | `f1852372eb4e220fbc5c92f0cab0bbaa0b1fa80690ec1bc56f10367ea734aad6` |
| 10 | `9ca2c4b05a54a23b90146175a8b6a03af68cd7da8c69ac32e8cffe60caaf7dc7` | `192c0bbe73d233ba92bc3c15b99269ef09154469c110c3898894a07a26638dae` |
| 50 | `6df82c04eeda1b3b506fc2c40755344c2bdeac677d72d001bace4867a4e81e1a` | `6d33b1e6a4d0edbaa991f3e8789758547bbf0c54814f7c6dc52791efaad52864` |

The 50-note v1 graph is larger than the normal 64 MiB client output ceiling and
requires the explicit 96 MiB batch-prover profile. SIGNET v2 fits the client
ceiling. This validation found that the native CLI selected the batch limit for
file reads but lost it during graph decoding; the constructor now accepts an
explicit resource budget and the CLI carries that budget through. Client
defaults were not widened. A release build of the stock serial CLI then loaded
the 50-note v1 bundle, generated a proof, and self-verified it successfully.

Generation also exposed a system-zstd pipe deadlock on the 80.8 MB v1 graph.
The compressor now drains stdout concurrently with stdin writes, with a 2 MiB
incompressible regression fixture covering the former pipe-capacity failure.

### SAGE caches and SPARROW manifests

Every cache round-tripped through authenticated loading and reproduced the same
assignment as SIGNET and snarkjs.

| Notes | SAGE program | Slots | Program SHA-256 | Manifest | Manifest SHA-256 |
|---:|---:|---:|---|---:|---|
| 2 | 12,896,156 B | 4,148 | `9f49afbdaa78eed17c8eea1da01a0b3a5e1079798c5b24be713743938f594dc1` | 2,876 B | `87df938aa2cd855392b3272b47e6d115198dd08f41497d2b7f409c5a24b5f02c` |
| 5 | 19,523,332 B | 4,916 | `d746e4e33ded6140a444e1a875e1caea828494fee87956193f07d778269eddec` | 4,028 B | `843456931b21086b3e8386ed20b9e36eb148a668fa094b8fa4ac596960bb8a25` |
| 10 | 32,709,900 B | 6,196 | `518c38c20dc818921e5a3c0388de585eef11442a6716d6bf5890c217ce02c8b1` | 7,036 B | `0589836b7dda2a390a9e2586aaf6767ec70d26ffbfa51459d86f76b56c5640f7` |
| 50 | 131,777,308 B | 16,436 | `47712452e8a13796b3ba0c757d4d80c3015f0bf8a4f1b5557589a8e396f4d311` | 28,316 B | `53f7c888cfd39b0d9f31fdbccc2ebb3b7b6f89c43c7130b2c2ba3b50e553dbc8` |

The cache pipeline used seven outer samples; every warm validation is itself a
median of seven loads.

| Notes | Compile | Serialize | Digest | First authenticated load | Complete cold CPU | Warm authenticated validation |
|---:|---:|---:|---:|---:|---:|---:|
| 2 | 34.383 ms | 3.362 ms | 4.474 ms | 7.836 ms | 50.033 ms | 12.395 ms |
| 5 | 51.272 ms | 5.157 ms | 6.880 ms | 11.942 ms | 75.614 ms | 18.772 ms |
| 10 | 86.431 ms | 8.425 ms | 11.555 ms | 20.348 ms | 126.571 ms | 31.754 ms |
| 50 | 353.428 ms | 33.510 ms | 45.821 ms | 81.210 ms | 514.306 ms | 127.210 ms |

The SAGE cache is intentionally larger than compressed SIGNET. It trades storage
quota for lower warm startup CPU and a substantially smaller live evaluator.
Treat it as derived, replaceable state: the SIGNET digest remains authoritative,
and every cache load must authenticate its program and source-graph binding.

## Compact matrices in isolation

The whole-key end-to-end profile mixes SIGNET and matrix effects. A separate
WTNS sweep holds witness generation constant and changes only the retained
constraint representation. It used seven alternating samples and 56
self-verifying measured proofs.

| Notes | Nested auth + parse | Compact auth + parse | Change | Nested proof | Compact proof | Change | Nested total | Compact total | Change |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 2 | 92.571 ms | 78.652 ms | 15.0% faster | 237.548 ms | 236.500 ms | 0.4% faster | 333.404 ms | 318.810 ms | 4.4% faster |
| 5 | 131.591 ms | 112.600 ms | 14.4% faster | 325.270 ms | 324.589 ms | 0.2% faster | 462.168 ms | 440.820 ms | 4.6% faster |
| 10 | 228.913 ms | 192.482 ms | 15.9% faster | 571.729 ms | 573.605 ms | 0.3% slower | 809.385 ms | 775.331 ms | 4.2% faster |
| 50 | 914.943 ms | 768.871 ms | 16.0% faster | 2,360.440 ms | 2,362.510 ms | 0.1% slower | 3,310.764 ms | 3,164.197 ms | 4.4% faster |

| Notes | Matrix payload nested -> compact | Load RSS nested -> compact | Proof RSS nested -> compact |
|---:|---:|---:|---:|
| 2 | 35.6 -> 22.4 MiB | 161.0 -> 111.3 MiB | 198.4 -> 143.1 MiB |
| 5 | 47.2 -> 33.4 MiB | 217.4 -> 150.7 MiB | 259.9 -> 180.7 MiB |
| 10 | 84.7 -> 57.6 MiB | 377.9 -> 242.7 MiB | 442.3 -> 315.4 MiB |
| 50 | 342.6 -> 234.1 MiB | 1,412.7 -> 870.6 MiB | 1,736.3 -> 1,191.7 MiB |

Compact matrices reduce initialization and retained memory; they do not speed
the dominant FFT/MSM proof phase. The production parser uses two sequential
passes so it never holds nested and compact forms together.

## Poseidon speedup, in detail

The optimized schedule changes only algebraic evaluation. Parameters, state
initialization, domain separation, round counts, and outputs are unchanged. The
generator derives folded `C`, transition `P`, and sparse `S` tables from the
canonical `C/M` data. The committed table is 754 KiB with SHA-256
`d0c52916660a9de7e0d2ee457a741db6dcf28f6e1ae253c9f2bca9be79bfd36e`.

Seven samples of 3,000 chained hashes per arity produced:

| Arity | Direct median | Optimized median | Latency reduction | Throughput | Field multiplies direct -> optimized | Arithmetic reduction |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 6.297 us | 5.482 us | 12.9% | 1.15x | 472 -> 416 | 11.9% |
| 2 | 11.035 us | 7.753 us | 29.7% | 1.42x | 828 -> 600 | 27.5% |
| 3 | 17.632 us | 10.224 us | 42.0% | 1.72x | 1,288 -> 784 | 39.1% |
| 4 | 27.383 us | 13.644 us | 50.2% | 2.01x | 2,000 -> 1,040 | 48.0% |
| 5 | 38.170 us | 16.725 us | 56.2% | 2.28x | 2,772 -> 1,272 | 54.1% |
| 6 | 52.505 us | 20.598 us | 60.8% | 2.55x | 3,836 -> 1,568 | 59.1% |
| 7 | 68.776 us | 24.365 us | 64.6% | 2.82x | 4,992 -> 1,856 | 62.8% |
| 8 | 84.333 us | 28.021 us | 66.8% | 3.01x | 6,156 -> 2,124 | 65.5% |
| 9 | 100.460 us | 31.267 us | 68.9% | 3.21x | 7,220 -> 2,360 | 67.3% |
| 10 | 131.052 us | 37.610 us | 71.3% | 3.48x | 9,416 -> 2,816 | 70.1% |
| 11 | 142.160 us | 40.003 us | 71.9% | 3.55x | 10,260 -> 3,000 | 70.8% |
| 12 | 177.022 us | 46.389 us | 73.8% | 3.82x | 12,844 -> 3,484 | 72.9% |
| 13 | 216.798 us | 53.452 us | 75.3% | 4.06x | 15,834 -> 4,004 | 74.7% |
| 14 | 215.980 us | 54.544 us | 74.7% | 3.96x | 15,840 -> 4,080 | 74.2% |
| 15 | 258.185 us | 61.135 us | 76.3% | 4.22x | 19,008 -> 4,608 | 75.8% |
| 16 | 304.953 us | 68.651 us | 77.5% | 4.44x | 22,576 -> 5,168 | 77.1% |

For state width `t` and `R_P` partial rounds, the direct matrix layers cost
`(8 + R_P) * t^2` multiplications. The factored schedule costs
`8 * t^2 + R_P * (2t - 1)`, saving exactly `R_P * (t - 1)^2`. The S-box count
does not change. This is why the latency improvement grows with arity and tracks
the counted multiplication reduction closely.

Application-level tree work is dominated by binary Poseidon, so it realizes the
arity-2 gain rather than the much larger high-arity numbers:

| Workload | Direct median | Optimized median | Reduction |
|---|---:|---:|---:|
| Build 4,096-leaf indexed tree, depth 16 | 43.259 ms | 30.532 ms | 29.4% |
| Insert 256 leaves, depth 30 | 80.720 ms | 57.311 ms | 29.0% |
| First binary-hash initialization, fresh process | 4.295 ms | 1.922 ms | 55.3% |

The initialization row above measured the original eager loader, which decoded
all 16 arities on the first hash. Constants are now decoded per arity on
demand, behind a framing pass that still validates the source digest and every
declared table dimension up front. Re-measured on one arm64 host over 15 fresh
processes, first binary-hash initialization fell from 2.228/2.710/6.367 ms to
0.030/0.046/0.309 ms, and peak RSS from 3,552 to 1,944 KiB. Steady-state hash
throughput is unchanged.

The optimized native benchmark binary is smaller: 1,668,656 -> 1,353,664 bytes
(18.9%). Portable WASM is 301,986 raw bytes smaller (11.8%), but its high-entropy
field tables compress less well: gzip is 942,085 -> 1,173,605 bytes, an increase
of 231,520 bytes (226.1 KiB, 24.6%). The optimized compressed module is therefore
1.12 MiB total. Against the approximately 5 MB Go artifact it replaces, the
total remains roughly four times smaller while providing much higher throughput.

The size tradeoff was accepted, so `poseidon-optimized` is now the
`curvy-core` default. `default-features = false` retains the direct schedule for
size-sensitive consumers and as a continuously tested independent oracle.

## Validation gates completed

- SIGNET v1/v2: exact full-assignment parity with all four snarkjs production
  WTNS files; malformed-header, checksum, limit, and cross-version negatives.
- SAGE: deterministic compile, authenticated program/source binding, serialize
  round-trip, and full-assignment parity for every production graph.
- SPARROW: complete manifest-table and zkey digest checks, per-chunk
  authentication before point parsing, and self-verification for every proof.
- Compact matrices: randomized row differential tests including empty and
  duplicate-bearing rows, exact H vectors, fixed-randomizer proof equality,
  randomized proofs, native production keys, portable WASM build, and threaded
  WASM build.
- Poseidon: generated-table byte-for-byte regeneration, digest checks for every
  emitted table, 160,000 deterministic full-width differential cases across all
  arities, independent poseidon-lite and pso-poseidon vectors, Merkle/note/EdDSA
  vectors, FFI tests, native Node tests, 371 portable-WASM JS parity checks, and
  a threaded-WASM all-features build.
- System compression: large incompressible zstd pipe regression after fixing
  concurrent stdin/stdout handling.

## Resident (HAWK) versus streaming (SPARROW): which to use

Use HAWK `ResidentProver` when:

- a long-lived native service proves repeatedly with the same circuit;
- roughly 193 MiB to 1.70 GiB per initialized production profile is comfortably
  inside the service's memory and concurrency budget;
- lowest steady-state latency matters more than bounded per-proof memory; or
- operational simplicity matters: one authenticated graph plus zkey and no
  manifest/cache lifecycle.

It authenticates and parses once, then reuses the key. Its disadvantages are
the startup load, large resident allocation, and multiplication of that memory
when several circuits or prover processes are live.

Use SPARROW `StreamingProver` when:

- browser, mobile, desktop client, serverless, or memory-constrained native
  proving must avoid retaining a complete key;
- large profiles or concurrent proofs make whole-key RSS operationally risky;
- zkeys arrive as streams or cached chunks; or
- a slightly slower repeated-proof path is acceptable for predictable memory.

SPARROW authenticates each complete chunk before unchecked parsing and rereads
the key once per proof. Its costs are the manifest, a derived SAGE cache if warm
startup matters, more integration states, and approximately 37-45% more latency
than an already-resident optimized whole key in this native sweep. For cold
one-shot processes, however, warm SPARROW is within 0.1-6.9% of optimized
whole-key end-to-end latency and saves up to 77.9% peak RSS.

Recommended deployment policy:

1. Native, single/few circuits, provisioned memory, repeated proofs: HAWK
   `ResidentProver`.
2. Browser/mobile or untrusted device memory: SPARROW `StreamingProver` in a
   worker.
3. Native multi-tenant or many simultaneously active large circuits: benchmark
   both, but default to SPARROW when the aggregate resident-key budget is not
   comfortably below the process/container limit.
4. One-shot CLI: HAWK for smaller circuits; SPARROW for the 50-note/larger class
   when the extra artifact plumbing is available.

## Developer and architecture names

The optimized whole-key path is **HAWK**: High-throughput Authenticated
Whole-Key prover. Its public API is `ResidentProver`, its `ProverMode` value is
`Resident`, and its operational mode/profile strings are `resident` / `HAWK`.
It authenticates and parses once, retains the key and matrices, and reuses them
for fast repeated proofs.

The bounded-memory path is **SPARROW**: Streaming Prover Architecture for
Resource-Restricted One-pass Workflows. Its public API is `StreamingProver`, its
`ProverMode` value is `Streaming`, and its operational mode/profile strings are
`streaming` / `SPARROW`. It authenticates manifest chunks and processes the
zkey sequentially for each proof.

Use the descriptive class names in code and the acronyms in architecture,
deployment profiles, dashboards, and benchmark labels. Artifact names remain
SIGNET, SAGE, zkey, and manifest because both modes consume the same circuit
identity; HAWK and SPARROW describe execution and memory ownership, not formats.
