# Timing and taint tests

Build and run on the native target being measured:

```sh
python3 tools/leakage/run.py dudect --out /tmp/curvy-timing --samples 200000
python3 tools/leakage/run.py timecop --out /tmp/curvy-taint
python3 tools/leakage/run.py phases --out /tmp/curvy-signing-phases --samples 30000
node tools/leakage/public-transcripts.cjs /tmp/curvy-public-transcripts.json
```

`dudect` uses pinned upstream [dudect](https://github.com/oreparaz/dudect).
`timecop` uses Valgrind Memcheck and needs Linux with the Valgrind development
headers. The `leakage` Cargo feature these builds enable is development-only; no
binding's production build turns it on.

WASM, after the native runs:

```sh
bash tools/leakage/build-wasm.sh
node tools/leakage/wasm.mjs /tmp/curvy-wasm-timing 100000 chromium firefox
```

`--seconds-per-case=60` caps the time per case on slow engines and
`--cases=poseidon_secret,owner_hash_decimal,sign_seed,sign_scalar` selects
operations. The browser runner uses the Playwright installation in
`tools/browser`.

Do not run these alongside builds or benchmarks.
