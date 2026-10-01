# Browser proof checks

```sh
scripts/build.sh wasm-web-threads   # the threaded release build
scripts/build.sh wasm-web           # the portable release build
npm ci --prefix tools/browser --ignore-scripts
npx --prefix tools/browser playwright install chromium firefox
node tools/browser/check.mjs                # both modes
node tools/browser/check.mjs threaded       # or one mode
node tools/browser/check.mjs portable
```

This runs a real Groth16 proof in isolated Chromium and Firefox sessions, checks expected public signals, and checks malformed inputs and an incorrect artifact pin. `threaded` loads `crates/prover/pkg-web-threads` and proves with two Rayon workers; `portable` loads `crates/prover/pkg-web` on the main thread. Each mode checks that it loaded the matching build. CI builds each package with the exact release command (plus a `scripts/build-wasm.sh web --threads --compact-matrix` variant) and runs the matching mode; it also installs the browser system dependencies. The shipped builds keep nested matrices: with the production 2-, 5- and 10-note pending-notes keys in Chromium 143 (October 2026), compact matrices lowered peak browser RSS by only 5-7% (the WASM heap by 13-15%) and made the portable 2-note proof about 6% slower. The localhost server supplies COOP/COEP headers and resolves wasm-bindgen-rayon's package-directory worker import as a bundler would.

`node tools/browser/node-proof-check.mjs [curvy_prover.js]` runs the same fixture through a Node.js prover build (default: `crates/prover/pkg-node`, from `scripts/build.sh wasm-nodejs`). It pins the fixture digests, checks that the prover's verifying-key digest equals one re-derived from `crates/prover/testdata/multiplier.vk.json`, proves `a=3, b=11` to public signal `33`, and checks that wrong pins, malformed input, and a corrupted proving key are refused. `scripts/smoke-npm.mjs` runs the same check against the portable prover entry of the packed npm tarball.

For manual checks, run `node tools/browser/serve.mjs` and open the printed URL. The page displays all results. `?mode=portable` uses a `scripts/build.sh wasm-web` build. `?threads=4&samples=11` controls the threaded run.

The server optionally accepts a JSON array of benchmark cases containing `notes`, `zkeyUrl`, `graphUrl`, `zkeyPath`, `graphPath`, `zkeySha256`, `graphSha256`, `input`, and `expectedPublics`. Only the named external files are exposed. Select one with `?scenario=2`; production measurements should run without concurrent builds or other benchmarks. It binds only to loopback.

To check or measure a package built elsewhere, point the server at its prover
package directory: `CURVY_BROWSER_PKG_WEB` replaces `crates/prover/pkg-web` and
`CURVY_BROWSER_PKG_WEB_THREADS` replaces `crates/prover/pkg-web-threads`.
`check.mjs` passes both through to the server it starts.
`CURVY_WASM_OUT_DIR=DIR scripts/build-wasm.sh ...` writes the packages to
`DIR/wasm/pkg-*` and `DIR/prover/pkg-*` instead of `crates/`.

`node tools/browser/measure.mjs output.json 2,5,10` launches a fresh Chromium
process tree per mode/circuit, takes one warm-up and five measured proofs, and
samples aggregate process RSS every 50 ms. This RSS includes browser overhead
and counts shared pages per process; it is not a unique-physical-memory metric.
The page also reports WASM linear-memory size, which never shrinks and so is
the prover heap's high-water mark, and splits load time into WASM/worker
initialization, artifact fetch, and authenticated parse.
The browser measurement command needs permission to inspect its own process IDs.
Set `CURVY_BROWSER_BUILD_PROFILE` to describe the builds being measured.

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

`node tools/browser/sparrow-window.mjs output.json 2,5,10` sweeps fixed
SPARROW MSM window widths in Chromium (`sparrow-window.html`). Point
`CURVY_BROWSER_PKG_WEB` and `CURVY_BROWSER_PKG_WEB_THREADS` at
`scripts/build-wasm.sh web --sparrow` and `web --threads --sparrow` prover
packages, and give each case in `CURVY_BROWSER_ARTIFACTS` a 1 MiB-chunk
manifest from the `zkey_chunk_manifest` example as `manifestUrl`,
`manifestPath` and `manifestSha256`. Each run is a fresh browser per mode and
circuit with one warm-up and `CURVY_BROWSER_SAMPLES` one-pass manifest proofs
per width in `CURVY_SPARROW_WIDTHS` (default `11,12,13,14`), rotated so every
width sees each position equally often; `CURVY_SPARROW_CHUNK` sets the MSM
chunk (default 65,536 points, the browser default).
