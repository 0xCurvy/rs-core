# rs-core

The complete Rust implementation of the Curvy privacy protocol's cryptography:
the crypto core, the WebAssembly bindings, a rayon-threaded scanner, and a
Groth16 prover with a browser benchmark harness.

This repository is the **source of truth** for the Rust core. Consumers (the web
SDK, node services) use the **built wasm artifacts** produced here; nothing here
is compiled inside the consuming projects.

## Crates

| Crate | What it is |
|---|---|
| [`curvy-core`](crates/core) | The cryptography: Poseidon, BabyJubjub + EdDSA-Poseidon, BLAKE-512, the note cipher, note commitments, incremental Merkle trees, dual-curve stealth addressing, and the circuit witness builders. Pure compute - no I/O, no global state. |
| [`curvy-wasm`](crates/wasm) | `wasm-bindgen` bindings exposing the core to JavaScript across a decimal-string boundary. Builds single-threaded, or threaded (rayon) for cross-origin-isolated pages. |
| [`curvy-prover`](crates/prover) | arkworks Groth16 prover over snarkjs `.zkey`/`.wtns` artifacts - native (rayon) and wasm32 - with a browser benchmark harness. Detached workspace; contains vendored `ark-circom` code (see its README). |

```
Cargo.toml            workspace (curvy-core, curvy-wasm)
rust-toolchain.toml   pinned toolchain
deny.toml             cargo-deny supply-chain policy
scripts/
  build-wasm.sh          single-threaded wasm build (nodejs | web | bundler)
  build-wasm-threads.sh  threaded (rayon) wasm build for isolated pages
crates/
  curvy-core/         the cryptography (+ conformance tests, committed vectors)
  curvy-wasm/         the wasm-bindgen bindings
  prover/             the Groth16 prover + www/ browser harness
```

## Prerequisites

The easiest path is the flake: `nix develop` provides everything below (pinned
Rust, protoc, libclang, libffi, pkg-config, cmake). Otherwise:

- **Rust** — stable, pinned by `rust-toolchain.toml` (rustup picks it up
  automatically). Enough for the core workspace (`crates/`).
- **Git LFS** — the proving keys in `zk-keys/v2` are LFS objects. Install
  `git-lfs`, then `git lfs pull` to materialize them (~160 MB). Needed for the
  SDK e2e and the strict `poc/blokli-env` flow, not for the core build.
- **protobuf-compiler (`protoc`), libclang, pkg-config, cmake** — build-time
  deps of the SDK workspace (`sdk/`): `prost-build` shells out to `protoc`,
  `bindgen` needs libclang. Debian/Ubuntu:
  `apt install protobuf-compiler libclang-dev pkg-config cmake`.
- **Docker** — only for the `poc/blokli-env` stack (`run.sh image-up`).
- **wasm tooling** — only for the wasm builds; see
  [Building the wasm](#building-the-wasm).

## Build & test (native)

```bash
cargo test                                   # conformance + unit tests (single-threaded)
cargo test --features curvy-core/parallel    # same, with the rayon scan path
cargo clippy --all-targets                   # lints
cargo deny check                             # advisories / licenses / bans / sources
```

`curvy-core` builds on stable Rust. The `parallel` feature turns on rayon for the
scan loop; it changes throughput, not results - the sparse match list is
byte-identical either way, pinned by the tests.

## Building the wasm

Two build variants come out of the same source. Requirements:

- `rustup target add wasm32-unknown-unknown`
- `cargo install wasm-bindgen-cli --version 0.2.114`
- for the threaded build only: `rustup toolchain install nightly --component rust-src`

### Single-threaded (works everywhere)

```bash
scripts/build-wasm.sh web       # → crates/curvy-wasm/pkg-web      (async ESM, browser)
scripts/build-wasm.sh nodejs    # → crates/curvy-wasm/pkg-node     (CommonJS, node)
scripts/build-wasm.sh bundler   # → crates/curvy-wasm/pkg-bundler  (ESM for Vite/webpack)
```

Each produces the `.wasm` plus the wasm-bindgen JS/TS glue in the named directory.
This variant runs on any page - no special headers.

### Threaded (rayon) - for cross-origin-isolated pages

```bash
scripts/build-wasm-threads.sh   # → crates/curvy-wasm/pkg-web-threads
```

Nightly-only: it uses `-Z build-std` plus a specific set of link flags (shared
imported memory + the TLS/heap symbol exports the wasm-bindgen threads transform
requires). The script encodes them; see "Threads and cross-origin isolation"
below for what they mean. The output additionally exports `initThreadPool(n)` and
ships a `snippets/` directory of rayon worker helpers.

## Using the wasm

The bindings cross the boundary as **decimal strings** (`"X.Y"` for curve
points). Load once, then call synchronously:

```js
import init, { scan, poseidon, initThreadPool } from "./pkg-web/curvy_wasm.js";

await init();                      // instantiate the wasm (once)
// threaded build only, on a cross-origin-isolated page:
// await initThreadPool(Math.min(navigator.hardwareConcurrency, 8));

// Recipient scan: sparse matches (index into the input arrays + derived keys).
const matches = scan(spendPrivHex, viewPrivHex, ephemeralPoints, viewTags);
```

The **single-threaded** and **threaded** builds export the identical API and
produce identical results - the threaded one just parallelizes `scan` across a
worker pool. A consumer typically feature-detects `crossOriginIsolated` and loads
the threaded package when it is `true`, falling back to the single-threaded one
otherwise (see below).

Key surface (all string-in / string-out): `poseidon`, `ownerHash`, `noteId`,
`nullifier`, `pubFromPrivateKey`, `ephemeralPubKey`, `sign`, `encryptAmountToken`
/ `decryptAmountToken`, `sha256BigInt`, and the stealth core `new_meta`,
`get_meta`, `send`, `scan`, `viewerScan`.

## Threads, cross-origin isolation, and CORS quirks

The threaded build uses WebAssembly threads (rayon over `SharedArrayBuffer`).
Browsers only expose `SharedArrayBuffer` and wasm threads to pages that are
**cross-origin isolated** - this is the single biggest operational constraint, so
it's worth understanding fully.

### Getting `crossOriginIsolated === true`

A page is cross-origin isolated when it is served with one of:

- **`Document-Isolation-Policy: isolate-and-credentialless`** (recommended).
  Chromium ≥ 137 becomes isolated with **no side effects** - popups keep
  `window.opener`, and cross-origin no-CORS subresources still load (fetched
  without credentials). Firefox and Safari currently ignore this header, so they
  simply stay non-isolated. One header, no collateral damage.
- **`Cross-Origin-Opener-Policy: same-origin`** + **`Cross-Origin-Embedder-Policy:
  require-corp`** (the classic pair). Isolates on **all** browsers, but has two
  costs: it severs `window.opener` for cross-origin popups (breaks popup-based
  OAuth / wallet flows), and it requires every embedded cross-origin subresource
  to opt in via CORS or a `Cross-Origin-Resource-Policy` header (so no-CORS images
  / fonts / widgets break unless proxied or self-hosted). `COEP: credentialless`
  relaxes the subresource rule (fetch without cookies instead of requiring CORP),
  but Safari does not support it.

Verify at runtime with `globalThis.crossOriginIsolated` (also available in
workers, which inherit the document's isolation).

### The fallback ladder

Because isolation is not universally available, a consumer should degrade
gracefully:

1. `crossOriginIsolated` is `true` and `initThreadPool` succeeds → threaded scan.
2. isolated but thread-pool init fails (older engines) → catch and fall back.
3. not isolated → load the single-threaded build.

All three produce correct results; only throughput differs.

### Build-flag quirks (why the threaded script looks the way it does)

The threaded build needs more than `--target-feature=+atomics`:

- `-Z build-std=panic_abort,std` - the standard library must be recompiled with
  atomics; the prebuilt std is not thread-enabled.
- `--shared-memory --import-memory --max-memory=…` - the wasm memory must be a
  **shared, imported** memory so the main thread and workers address the same
  bytes.
- `--export=__heap_base --export=__wasm_init_tls --export=__tls_size/…` - the
  wasm-bindgen threads transform injects thread-local setup and needs these
  symbols exported, or it fails with `failed to find __heap_base` /
  `__wasm_init_tls`.

### Serving / bundler quirks

- **`wasm-bindgen-rayon` imports the package *directory***. Its worker helper does
  `import("../../..")` (the package root), so a plain static file server must map
  a request for the package directory to its main JS module - bundlers do this
  automatically, but a hand-rolled server (like the harness `server.mjs`) needs a
  small rule for it.
- **Serve the threaded package's `snippets/` directory** alongside the `.wasm`;
  the rayon worker helpers live there.
- **COOP/COEP (or DIP) must be on every response**, including the worker scripts
  and the wasm, or the workers won't be created in an isolated context.

### Thread count

Scan throughput saturates around **8 threads** (coordination overhead dominates
beyond that, and can even regress for small batches). Pool at
`min(hardwareConcurrency, 8)`.

## Prover and harness

`curvy-prover` is a native + wasm arkworks Groth16 prover for the protocol's
circuits. It parses a snarkjs `.zkey` and `.wtns` and emits a snarkjs-shaped proof
(so snarkjs and the on-chain verifier accept it). It parses the `.zkey` without
per-point on-curve re-validation (a verifying-key anchor spot-check guards against
gross corruption) - so callers must pin/verify the `.zkey` by content hash. See
[`crates/prover/README.md`](crates/prover/README.md) for measured performance and
the native CLI.

The browser harness in `crates/prover/www/` measures proving and scanning in
a real cross-origin-isolated page:

```bash
scripts/build-wasm-threads.sh                 # build the threaded wasm the harness loads
node crates/prover/www/server.mjs         # COOP/COEP static server on :8787
# http://localhost:8787/scan-bench.html       (scan throughput; self-contained)
# http://localhost:8787/index.html            (prover; needs circuit artifacts - see www/data/README.md)
```

The **scan** harness is self-contained (it generates announcements via the wasm
core). The **prover** harness needs the circuit `.zkey`/`.wtns` placed in
`www/data/` - those are gitignored (large); see
[`crates/prover/www/data/README.md`](crates/prover/www/data/README.md).

## Verification

Correctness is measured against committed reference vectors
(`crates/curvy-core/testdata/`), one suite per module in
`crates/curvy-core/tests/`:

- Standard primitives (Poseidon, BabyJubjub, EdDSA-Poseidon, the incremental
  Merkle tree) are checked against their circomlib / `@zk-kit` references.
- Poseidon is additionally cross-checked against an independent, audited Rust
  implementation ([`light-poseidon`](https://crates.io/crates/light-poseidon)).
- The stealth core and witness builders are checked end-to-end against recorded
  vectors.

## Dependency policy

Small and pinned. `curvy-core` depends only on **arkworks** (field / curve /
pairing) and **RustCrypto** (the note cipher), plus `num-bigint`, `getrandom`,
and `serde` for the boundary and the compiled-in Poseidon constants. Poseidon is
implemented directly from the circomlib constants (no thin third-party crate).

All versions are exact-pinned (`=x.y.z`), the committed `Cargo.lock` records
exact versions and checksums, and `cargo deny` gates advisories, licenses, bans,
and sources (crates.io only) - see `deny.toml`.

`curvy-prover` additionally vendors two files from `ark-circom 0.5.0`
(`src/zkey.rs`, `src/qap.rs`; MIT OR Apache-2.0) - flagged in their headers.

## Toolchain

Stable Rust for everything except the threaded wasm build, which needs nightly
with `rust-src` (`rustup toolchain install nightly --component rust-src`). The
stable channel is pinned in `rust-toolchain.toml`.
