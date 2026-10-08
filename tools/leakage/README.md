# Leakage assessment

Build and run on the native target being assessed:

```sh
python3 tools/leakage/run.py dudect --out /tmp/curvy-timing --samples 200000
python3 tools/leakage/run.py timecop --out /tmp/curvy-taint
```

The timing harness uses pinned upstream [dudect](https://github.com/oreparaz/dudect).
Its Welch tests, cropped distributions and second-order test are unchanged.
The portability patch uses `CLOCK_MONOTONIC_RAW` nanoseconds on ARM64; x86-64 uses
the upstream timestamp counter. Each run warms up the operation and discards a
32,768-sample calibration batch. Both fixed/random and equal-bit-length
sparse/dense input classes are tested. Inputs are prepared outside measurement.
The variable-time affine multiplier must be detected before other results count.
The threshold is upstream's `|t| > 10`; a finite run reports evidence only for its
recorded sample counts, input classes, binary, compiler, CPU and runtime.

`timecop` uses unmodified Valgrind Memcheck with client requests marking test
secrets undefined. It requires Linux and the Valgrind development headers.
The `leakage` feature provides test-only observation points for these public values:

- Raw public-point coordinates, before arkworks conversion.
- The signature response scalar, before public serialization/verification.
- Key validity and decimal syntax/range results, which are returned to callers.
- The optional minus sign in reducing decimal syntax; digit count is public.
- Nonce candidate acceptance, observable through rejection retries.
- The projective inversion's nonzero assertion, guaranteed by the complete
  formulas for the fixed generator and checked by arithmetic differential tests.

No secret keys, nonces, hash state or projective coordinates are declassified.
Signing checks vary key material with the public message `42`; they do not
assess confidentiality of a secret message.
The callback only changes Memcheck's definedness metadata. Native timing uses
the same assessment build without installing that callback. The feature is
development-only and is not enabled by either binding's production build.

Private-input Poseidon, decimal-to-owner-hash conversion and seed signing are
gating timing cases. The Poseidon taint case also exercises all 16 arities with
all input fields marked secret. Scalar signing includes variable-time public
signature verification. The scheduled timing job records that complete call
with `--allow-variable-time sign_scalar`; its secret calculations and the
entire signer still gate in the taint job. No production hash case is exempted.

`poseidon_vartime` is an optional diagnostic using the arkworks backend, compiled
only with the development feature. To compare it explicitly, select it with
`--cases poseidon_vartime` and `--allow-variable-time poseidon_vartime`. Its alerts
remain in the report. The affine multiplier remains the required control.

Profile the stages of actual signing calls with:

```sh
python3 tools/leakage/run.py phases --out /tmp/curvy-signing-phases --samples 30000
node tools/leakage/public-transcripts.cjs /tmp/curvy-public-transcripts.json
```

The stage profiler uses first-order Welch statistics and records time spent in
key/nonce point arithmetic, encoding, hashing, response calculation and public
verification. It includes observation overhead and is diagnostic, not a
standalone leakage or throughput assessment. The transcript tool uses the built
production WASM binding, destroys each synthetic signer and replays verification
using only its public key, message and signature. It records the public scalars'
bit lengths and set-bit counts, which determine work in the affine verifier.

Results include raw logs, the executable, source/binary hashes, toolchain and CPU
metadata, and sample counts. Do not run timing alongside builds or benchmarks,
or treat emulated CPU results as native evidence. Hosted-runner noise can obscure
small signals. The scheduled workflow covers native Linux ARM64 and x86-64;
it does not run on each commit. Passing these checks is not a constant-time proof.

The Memcheck check does not establish instruction latency, physical side-channel
resistance, complete erasure, or behaviour of a browser JIT. WASM engine timing
is a separate best-effort assessment.

Build and measure WASM after completing native measurements:

```sh
bash tools/leakage/build-wasm.sh
node tools/leakage/wasm.mjs /tmp/curvy-wasm-timing 100000 chromium firefox
```

For slow engines, `--seconds-per-case=60` caps measurement time after at least
1,024 samples, checked every 256 calls. Warmup is separate. The report retains
the actual class counts and whether the time budget stopped each case; fewer
samples reduce the power to detect small differences.
Use `--cases=poseidon_secret,owner_hash_decimal,sign_seed,sign_scalar` to select
operations. Both multiplier controls are always included; available names come
from the loaded WASM module.

The browser runner uses the existing Playwright installation in `tools/browser`.
It records the engine version, observed timer resolution, module hash and
first-order Welch statistics. It requires detection of the variable-time multiplier in
each engine. Warmup reduces startup noise, but JIT tier changes, garbage
collection and timer coarsening can still obscure or introduce differences.
These results are weaker than the native dudect suite and do not establish an
engine-independent timing guarantee.
