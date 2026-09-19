# Browser proof checks

```sh
scripts/build-wasm.sh web --threads --compact-matrix
npm ci --prefix tools/browser --ignore-scripts
npx --prefix tools/browser playwright install chromium firefox
node tools/browser/check.mjs
```

This runs a real Groth16 proof with two Rayon workers in isolated Chromium and Firefox sessions, checks expected public signals, and checks malformed inputs and an incorrect artifact pin. CI installs the browser system dependencies too. The localhost server supplies COOP/COEP headers and resolves wasm-bindgen-rayon's package-directory worker import as a bundler would.

For manual checks, run `node tools/browser/serve.mjs` and open the printed URL. The page displays all results. `?mode=portable` uses a `scripts/build-wasm.sh web` build. `?threads=4&samples=11` controls the threaded run.

The server optionally accepts a JSON array of benchmark cases containing `notes`, `zkeyUrl`, `graphUrl`, `zkeyPath`, `graphPath`, `zkeySha256`, `graphSha256`, `input`, and `expectedPublics`. Only the named external files are exposed. Select one with `?scenario=2`; production measurements should run without concurrent builds or other benchmarks. It binds only to loopback.

`node tools/browser/measure.mjs output.json 2,5,10` launches a fresh Chromium
process tree per mode/circuit, takes one warm-up and five measured proofs, and
samples aggregate process RSS every 50 ms. This RSS includes browser overhead
and counts shared pages per process; it is not a unique-physical-memory metric.
The browser measurement command needs permission to inspect its own process IDs.
