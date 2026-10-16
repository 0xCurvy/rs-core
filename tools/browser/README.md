# Browser proof checks

```sh
scripts/build.sh wasm-web-threads   # the threaded release build
scripts/build.sh wasm-web           # the portable release build
npm ci --prefix tools/browser --ignore-scripts
npx --prefix tools/browser playwright install chromium firefox
scripts/check.sh browser                    # both modes
scripts/check.sh browser threaded           # or one mode
scripts/check.sh browser portable
```

`check.mjs` runs a real Groth16 proof in isolated Chromium and Firefox sessions,
checks the expected public signals, and checks that malformed inputs and an
incorrect artifact pin are refused. `threaded` loads
`crates/prover/pkg-web-threads` and proves with two Rayon workers; `portable`
loads `crates/prover/pkg-web` on the main thread. Each mode checks that it
loaded the matching build. The localhost server sends COOP/COEP headers and
resolves wasm-bindgen-rayon's package-directory worker import as a bundler
would.

`node tools/browser/node-proof-check.mjs [curvy_prover.js]` runs the same
fixture through a Node.js prover build (default: `crates/prover/pkg-node`, from
`scripts/build.sh wasm-nodejs`; `scripts/check.sh wasm` runs it). It pins the fixture digests, checks the
prover's verifying-key digest against one re-derived from
`crates/prover/testdata/multiplier.vk.json`, proves `a=3, b=11` to public signal
`33`, and checks that wrong pins, malformed input, and a corrupted proving key
are refused. `scripts/check.sh npm` runs the same check against the portable
prover entry of the packed npm tarball.

## SIMD self-tests

The opt-in SIMD MSM and FFT (`scripts/build.sh wasm-* --simd`) have
development-only self-tests, randomized stress rounds and a kernel benchmark.
They are compiled in only with `--simd-selftest` (curvy-prover
`wasm-simd-selftest`); release builds never export them.
`scripts/check.sh simd` runs them; the suite is in `simd-selftest-suite.mjs`
and the browser page in `simd-selftest.html`.

```sh
scripts/build.sh wasm-nodejs --sparrow --simd --simd-selftest
scripts/check.sh simd --stress 60                   # Node: fixed seeds, 60 s stress, speed gate
scripts/build.sh wasm-web-threads --sparrow --simd --simd-selftest
scripts/check.sh simd --engine chromium --mode threaded
```

- The fixed suite compares the SIMD MSM (direct and through SPARROW's streamed
  buckets) and the SIMD witness-map FFT with arkworks for several seeds.
- `--stress SECONDS` runs randomized differential checks against arkworks for
  that time budget: field operations, MSMs, SPARROW queries with random
  chunking, single NTTs and witness maps. A failure prints a
  `--repro KIND:SEED:ARG` command.
- The benchmark times the SIMD kernel and the arkworks batch-affine path on one
  input in one process and fails below `--min-speedup` (default 1.4x).
- `scripts/check.sh simd-codegen` (needs `wasm-tools`) checks that the 4-lane
  multiplies stay `i64x2.extmul`, not emulated `i64x2.mul`.

Threaded builds need a browser. Playwright WebKit runs the portable build
(`--engine webkit`, after `npx --prefix tools/browser playwright install
webkit`); with Playwright 1.57's WebKit 26.0, threaded builds trap in
`initThreadPool`.

## Manual checks and measurements

Run `node tools/browser/serve.mjs` and open the printed URL; the page shows all
results. `?mode=portable` uses a `scripts/build.sh wasm-web` build.
`?threads=4&samples=11` controls the threaded run.

The server takes an optional JSON file with an array of benchmark cases, each
with `notes`, `zkeyUrl`, `graphUrl`, `zkeyPath`, `graphPath`, `zkeySha256`,
`graphSha256`, `input`, and `expectedPublics`. Only the named external files are
served. Select a case by its `notes` value, for example `?scenario=2`. The
server binds only to loopback. Run measurements without concurrent builds or
benchmarks.

To check or measure a package built elsewhere, point the server at its prover
package directory: `CURVY_BROWSER_PKG_WEB` replaces `crates/prover/pkg-web` and
`CURVY_BROWSER_PKG_WEB_THREADS` replaces `crates/prover/pkg-web-threads`.
`check.mjs` passes both through to the server it starts.
`CURVY_WASM_OUT_DIR=DIR scripts/build.sh wasm-...` writes the packages to
`DIR/wasm/pkg-*` and `DIR/prover/pkg-*` instead of `crates/`.

`node tools/browser/measure.mjs output.json 2,5,10` measures the in-tree
packages through an already running `node tools/browser/serve.mjs cases.json`.
It launches a fresh Chromium process tree per mode and circuit and takes one
warm-up and five measured proofs. It records aggregate process RSS sampled every 50 ms
(including browser overhead and shared pages), the WASM linear-memory size (the
prover heap's high-water mark), and load time split into WASM/worker
initialization, artifact fetch, and authenticated parse. It needs permission to
inspect its own process IDs. Set `CURVY_BROWSER_BUILD_PROFILE` to describe the
builds being measured.

To compare builds, name their prover package directories and the artifact case
file; the script starts its own servers and alternates the builds in ABBA order:

```sh
CURVY_BROWSER_ARTIFACTS=cases.json CURVY_BROWSER_ROUNDS=7 \
CURVY_BROWSER_BUILDS="nested=threaded:out-a/prover/pkg-web-threads,compact=threaded:out-b/prover/pkg-web-threads" \
  node tools/browser/measure.mjs output.json 2,5,10
```

`CURVY_BROWSER_SAMPLES` (default 5) and `CURVY_BROWSER_THREADS` (default 4) set
the measured proofs per run and the threaded worker count. The output records
each served prover's SHA-256 and a per-circuit summary with medians and changes
relative to the first build.

For packages built with `--bench`, each run also records named load and proof
phases; `node tools/browser/phase-summary.mjs output.json` prints their medians.

`node tools/browser/sparrow-window.mjs output.json 2,5,10` sweeps fixed SPARROW
MSM window widths in Chromium (`sparrow-window.html`):

- point `CURVY_BROWSER_PKG_WEB` and `CURVY_BROWSER_PKG_WEB_THREADS` at
  `scripts/build.sh wasm-web --sparrow` and `wasm-web-threads --sparrow` prover
  packages;
- give each case in `CURVY_BROWSER_ARTIFACTS` a 1 MiB-chunk manifest from the
  `zkey_chunk_manifest` example as `manifestUrl`, `manifestPath` and
  `manifestSha256`;
- `CURVY_SPARROW_WIDTHS` sets the widths (default `11,12,13,14`) and
  `CURVY_SPARROW_CHUNK` the MSM chunk (default 65,536 points, the browser
  default).

Each run is a fresh browser per mode and circuit with one warm-up and
`CURVY_BROWSER_SAMPLES` one-pass manifest proofs per width, rotated so every
width sees each position equally often.

## Benchmark pages

`bench/` holds two standalone pages, `sparrow.html` (SPARROW proofs) and
`phases.html` (phase timings of a `--bench` build). Serve the
repository with `node tools/browser/bench/serve.mjs [port]` from its root and open
the printed URL; `node tools/browser/bench/run.mjs <url> [desktop|mobile]
[cpu-throttle]` drives a page in Puppeteer (`CURVY_PUPPETEER_MODULE` names the
module). `node tools/benchmarks/sparrow-node.mjs` runs SPARROW proofs in Node.js against
a `wasm-nodejs --sparrow` build.
