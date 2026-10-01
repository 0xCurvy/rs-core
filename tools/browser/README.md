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

This runs a real Groth16 proof in isolated Chromium and Firefox sessions, checks expected public signals, and checks malformed inputs and an incorrect artifact pin. `threaded` loads `crates/prover/pkg-web-threads` and proves with two Rayon workers; `portable` loads `crates/prover/pkg-web` on the main thread. Each mode checks that it loaded the matching build. CI builds each package with the exact release command (plus a `scripts/build-wasm.sh web --threads --compact-matrix` variant) and runs the matching mode; it also installs the browser system dependencies. The localhost server supplies COOP/COEP headers and resolves wasm-bindgen-rayon's package-directory worker import as a bundler would.

`node tools/browser/node-proof-check.mjs [curvy_prover.js]` runs the same fixture through a Node.js prover build (default: `crates/prover/pkg-node`, from `scripts/build.sh wasm-nodejs`). It pins the fixture digests, checks that the prover's verifying-key digest equals one re-derived from `crates/prover/testdata/multiplier.vk.json`, proves `a=3, b=11` to public signal `33`, and checks that wrong pins, malformed input, and a corrupted proving key are refused. `scripts/smoke-npm.mjs` runs the same check against the portable prover entry of the packed npm tarball.

For manual checks, run `node tools/browser/serve.mjs` and open the printed URL. The page displays all results. `?mode=portable` uses a `scripts/build.sh wasm-web` build. `?threads=4&samples=11` controls the threaded run.

The server optionally accepts a JSON array of benchmark cases containing `notes`, `zkeyUrl`, `graphUrl`, `zkeyPath`, `graphPath`, `zkeySha256`, `graphSha256`, `input`, and `expectedPublics`. Only the named external files are exposed. Select one with `?scenario=2`; production measurements should run without concurrent builds or other benchmarks. It binds only to loopback.

`node tools/browser/measure.mjs output.json 2,5,10` launches a fresh Chromium
process tree per mode/circuit, takes one warm-up and five measured proofs, and
samples aggregate process RSS every 50 ms. This RSS includes browser overhead
and counts shared pages per process; it is not a unique-physical-memory metric.
The browser measurement command needs permission to inspect its own process IDs.
Set `CURVY_BROWSER_BUILD_PROFILE` to describe the builds being measured.
