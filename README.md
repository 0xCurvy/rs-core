# Curvy Rust core

[![crates.io](https://img.shields.io/crates/v/curvy-core?logo=rust&logoColor=black&label=crates.io&labelColor=white&color=orange)](https://crates.io/crates/curvy-core)
[![wasm-bindings](https://img.shields.io/npm/v/@0xcurvy/rs-core-wasm?logo=npm&logoColor=black&label=wasm-bindings&labelColor=white&color=red)](https://www.npmjs.com/package/@0xcurvy/rs-core-wasm)
[![CI](https://img.shields.io/github/actions/workflow/status/0xCurvy/rs-core/ci.yml?branch=main&logo=github&logoColor=black&label=CI&labelColor=white)](https://github.com/0xCurvy/rs-core/actions/workflows/ci.yml)
[![docs.rs](https://img.shields.io/docsrs/curvy-core?logo=docsdotrs&logoColor=black&label=docs.rs&labelColor=white&color=blue)](https://docs.rs/curvy-core)

Production-compatible Rust cryptography, witness evaluation, and Groth16 proving
for the Curvy protocol.

## Crates and documentation

This repository publishes four crates. Choose the narrowest crate that owns the
layer you need:

| Crate | Add it when you need | API documentation |
|---|---|---|
| `curvy-core` | Poseidon, BabyJubjub, both supported signing profiles, note commitments, stealth addressing, Merkle trees, or circuit-input builders | [docs.rs/curvy-core](https://docs.rs/curvy-core) |
| `curvy-witness` | Authenticated `curvy-graph-v1` parsing and Circom witness evaluation without a prover | [docs.rs/curvy-witness](https://docs.rs/curvy-witness) |
| `curvy-prover` | Authenticated graph evaluation plus snarkjs `.zkey` parsing and self-verified arkworks Groth16 proofs; it also provides the native prover executable and prover WASM module | [docs.rs/curvy-prover](https://docs.rs/curvy-prover) |
| `curvy-wasm` | JavaScript bindings for the `curvy-core` cryptography and tree APIs | [docs.rs/curvy-wasm](https://docs.rs/curvy-wasm) |

> The crates are release candidates. Pin the exact version until the stable API is
published.

## Install

Most native applications only need `curvy-core`:

```toml
[dependencies]
curvy-core = "=0.1.0-rc.3"
```

Add witness evaluation or local proving only when your application needs it:

```toml
[dependencies]
curvy-core = "=0.1.0-rc.3"
curvy-witness = "=0.1.0-rc.3"
curvy-prover = "=0.1.0-rc.3"
```

Rust 1.94 or newer is required.

## BabyJubjub signing profiles

`curvy-core` supports two first-class BabyJubjub signing profiles. Both are
supported APIs, both produce Curvy-compatible EdDSA-Poseidon signatures, and
both can build the same withdrawal and aggregation witness shapes. Neither
profile is deprecated and using one does not imply a migration away from the
other.

| Profile | Key material and public-key derivation | Rust entry points |
|---|---|---|
| Seed-backed | Hex-encoded private seed bytes; the established Curvy BLAKE-512 and pruning derivation produces the signing scalar and public point | `pub_from_private_key_hex`, `sign_hex`, and `SeedNoteSigner` |
| Direct-scalar | A checked, non-zero canonical BabyJubjub subgroup scalar; the public point is `scalar * Base8` | `ScalarSigningKey`, `BabyJubSecretScalar`, and `BabyJubPoint` |

Select the profile that matches how the account key was created and stored. The
same byte or number interpreted through the other profile represents a different
key, so implementers must not silently convert between profiles.

The direct-scalar API is:

```rust
use curvy_core::eddsa::{verify_scalar_compat, ScalarSigningKey};
use curvy_core::field::Bn254Fr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = ScalarSigningKey::from_decimal("1")?;
    let message = Bn254Fr::try_from_dec("42")?;
    let signature = key.sign_curvy_v1(message)?;

    assert!(verify_scalar_compat(
        message,
        key.verifying_key(),
        &signature,
    ));
    Ok(())
}
```

Use the checked boundary types for values received from storage, RPC, or users:

- `Bn254Fr` rejects non-canonical BN254 field encodings.
- `BabyJubSecretScalar` rejects zero and values outside the BabyJubjub subgroup
  scalar range.
- `BabyJubPoint` validates the curve, prime-order subgroup, and identity rules.
- `ScalarSigningKey` keeps the scalar and its derived public key together.

`SeedNoteSigner` and `ScalarSigningKey` both implement `NoteSigner`, so either can
be passed to `build_withdrawal_with_signer` and
`build_aggregation_with_signer`. The original `build_withdrawal` and
`build_aggregation` functions continue to use the seed-backed profile for source
compatibility.

## Witness evaluation and proving

`curvy-witness` evaluates a deployment's compiled `curvy-graph-v1` artifact.
`curvy-prover` combines that graph with the matching snarkjs `.zkey` and returns a
self-verified Groth16 proof in snarkjs JSON format:

```rust
use curvy_prover::CircuitProver;

fn prove(
    zkey: &[u8],
    zkey_sha256: &str,
    graph: &[u8],
    graph_sha256: &str,
    inputs: &str,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let prover = CircuitProver::from_artifacts(
        zkey,
        zkey_sha256,
        graph,
        graph_sha256,
    )?;
    let proof = prover.prove_json(inputs)?;

    Ok((proof.proof_json, proof.public_signals_json))
}
```

Both artifact hashes are required. Authentication happens before unchecked
proving-key coordinates or graph data are parsed. The graph and `.zkey` must be
the matching pair supplied by the Curvy deployment you are interacting with;
they are not bundled into these crates.

## Build targets

The repository has two complete build entry points: native and WASM. Both build
the crypto core, witness evaluator, and Groth16 prover.

### Select a build

Run the selector without arguments for an interactive menu:

```bash
scripts/build.sh
```

For CI or repeatable local builds, pass the choice directly:

```bash
scripts/build.sh native
scripts/build.sh wasm-web
scripts/build.sh --help
```

| Selector choice | What it builds | Output | Parallel behavior |
|---|---|---|---|
| `native` | `curvy-core`, `curvy-witness`, `curvy-prover`, and `curvy-native-prover` | Native Cargo artifacts and `target/release/curvy-native-prover` | Rayon support is compiled in; thread count is selected at runtime |
| `wasm-nodejs` | Portable `curvy-wasm` core bindings and `curvy-prover` bindings for Node.js | `crates/wasm/pkg-node` and `crates/prover/pkg-node` with CommonJS metadata | Single-threaded; no shared-memory or browser isolation requirement |
| `wasm-web` | Portable ES-module bindings for direct browser loading | Matching `pkg-web` directories | Single-threaded and supported without cross-origin isolation |
| `wasm-bundler` | Portable bindings intended for webpack, Vite, Rollup, and similar bundlers | Matching `pkg-bundler` directories | Single-threaded |
| `wasm-web-threads` | Browser ES modules compiled with WASM atomics, shared memory, and Rayon workers | Matching `pkg-web-threads` directories | Thread count is supplied to each module's `initThreadPool(n)` |
| `all-portable` | Native plus Node.js, web, and bundler portable builds | All non-threaded outputs above | Excludes `wasm-web-threads` because that target requires nightly and browser isolation |

Every WASM choice emits two independent modules: `curvy-wasm` contains the core
cryptography/tree bindings, while `curvy-prover` contains witness evaluation and
Groth16 proving. An application may ship only the module it actually uses.

Install [rustup](https://rustup.rs/) before using any build target. The root
`rust-toolchain.toml` then selects Rust 1.94 and installs the portable WASM
standard library automatically. Run all commands below from the repository
root.

### Native

Install the native toolchain and build the complete host target:

```bash
rustup toolchain install 1.94.0 --profile minimal
scripts/build-native.sh
```

This builds `curvy-core`, `curvy-witness`, and `curvy-prover` as optimized native
Rust libraries, enables native core parallelism, and produces
`target/release/curvy-native-prover`. The equivalent Cargo command is:

```bash
cargo build --locked --release \
  -p curvy-core -p curvy-witness -p curvy-prover \
  --features curvy-core/parallel
```

Applications that depend on these crates normally do not need this command;
Cargo compiles the appropriate native libraries as part of the consuming build.
The executable uses the same `curvy-witness` evaluator and arkworks prover as
the library API.

The script compiles multithreading support; it does not hard-code a machine's
core count. Parallel work currently covers independent stealth scans, bulk
Merkle parent construction, proving-key point conversion, and parallel-enabled
arkworks proving operations. Witness-graph evaluation itself remains
deterministic and single-threaded.

For Cargo consumers, `curvy-prover` enables its `parallel` feature by default.
`curvy-core` keeps parallelism opt-in, so enable it explicitly when using the
core crate without this build script:

```toml
[dependencies]
curvy-core = { version = "=0.1.0-rc.3", features = ["parallel"] }
curvy-prover = "=0.1.0-rc.3"
```

After publication, the executable can instead be installed from crates.io:

```bash
cargo install --locked curvy-prover --version 0.1.0-rc.3 \
  --bin curvy-native-prover
```

`cargo install` places the executable at
`$CARGO_HOME/bin/curvy-native-prover` (normally
`~/.cargo/bin/curvy-native-prover`). It accepts authenticated zkey and
`curvy-graph-v1` paths, an input JSON file, and output paths for
snarkjs-compatible proof and public-signal JSON:

```text
curvy-native-prover <zkey> <zkey-sha256> <graph.bin> <graph-sha256> \
  <input.json> <proof.json> <public.json>
```

Set `CURVY_PROVER_NUM_THREADS` to an integer from 1 through 64. It defaults to
one so container CPU quotas do not accidentally create an oversized Rayon pool.
The executable authenticates and parses artifacts through `CircuitProver`; it
does not introduce a second witness runtime or graph format.

```bash
CURVY_PROVER_NUM_THREADS=8 curvy-native-prover \
  <zkey> <zkey-sha256> <graph.bin> <graph-sha256> \
  <input.json> <proof.json> <public.json>
```

Native library consumers can instead set `RAYON_NUM_THREADS` before process
startup or install a global pool with
`rayon::ThreadPoolBuilder::num_threads(...).build_global()` before the first
parallel operation. Without either setting, Rayon chooses from the host's
available parallelism. A global pool can only be configured once; applications
that already own Rayon configuration should configure it themselves and then
call the Curvy APIs normally.

### WASM

Every WASM target needs the pinned wasm-bindgen CLI. Install it once:

```bash
rustup toolchain install 1.94.0 --profile minimal \
  --target wasm32-unknown-unknown
cargo +1.94.0 install wasm-bindgen-cli --version 0.2.126 --locked
```

The build invokes wasm-bindgen for both modules. Outputs are written to matching
directories under `crates/wasm/pkg-*` and `crates/prover/pkg-*`.

#### Node.js target

After installing the common WASM tools above, build CommonJS modules:

```bash
scripts/build.sh wasm-nodejs
node crates/wasm/smoke-test.cjs
```

This creates `crates/wasm/pkg-node` and `crates/prover/pkg-node`. Install Node.js
only when running the generated modules or the optional smoke test; CI uses
Node.js 22. Applications load either output with `require(...)`.

#### Browser target

After installing the common WASM tools, build portable ES modules for direct
browser loading:

```bash
scripts/build.sh wasm-web
```

This creates `crates/wasm/pkg-web` and `crates/prover/pkg-web`. These modules are
single-threaded, require no cross-origin isolation headers, and are initialized
with the default export generated by wasm-bindgen.

#### Bundler target

After installing the common WASM tools, build modules for Vite, webpack,
Rollup, and similar bundlers:

```bash
scripts/build.sh wasm-bundler
```

This creates `crates/wasm/pkg-bundler` and `crates/prover/pkg-bundler`. Point the
application's package or workspace configuration at the output directory for
the module it uses.

#### npm package

JavaScript consumers do not build this repository. The browser output is
assembled into a single npm package, `@0xcurvy/rs-core-wasm`, so downstream
projects depend on a version instead of a working copy:

```bash
scripts/build.sh npm          # web + web-threads, then assemble dist/npm
node scripts/build-npm.mjs --pack   # ... and produce the tarball
```

The package exposes one entry per browser artifact - `core`, `core-threads`,
`prover`, `prover-threads` - plus each raw `.wasm`. The wasm-bindgen output is
copied **unmodified**: its `new URL('curvy_wasm_bg.wasm', import.meta.url)` and
the Rayon helper's self-spawning `new Worker(...)` are the patterns bundlers
resolve natively, so consumers get working assets and workers without patching
generated code. Each entry also carries its own `package.json`, which is what
makes the Rayon snippet's `../../..` import resolve inside a bundler.

#### All portable targets

Install both the native and common WASM prerequisites above, then run:

```bash
scripts/build.sh all-portable
```

This builds native, Node.js, browser, and bundler outputs. It intentionally does
not install or build the nightly-only threaded target.

#### Threaded browser target

In addition to the common WASM tools, install the exact nightly, its standard
library source, and its WASM target:

```bash
rustup toolchain install nightly-2026-07-03 --profile minimal \
  --component rust-src --target wasm32-unknown-unknown
scripts/build.sh wasm-web-threads
```

The threaded build uses the validated `nightly-2026-07-03` toolchain with the
`rust-src` component. This post-Rust-1.94 pin is required because the older
nightly named in wasm-bindgen-rayon's current upstream build notes does not meet
this workspace's Rust 1.94 minimum. Override the pin with
`CURVY_WASM_THREADS_TOOLCHAIN` when testing another nightly. It writes both
modules to their `pkg-web-threads` directories and requires the page to be
cross-origin isolated, normally with these response headers:

```text
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
```

The generated core and prover packages are independent WebAssembly modules.
Each threaded module that an application loads must be initialized and given
its own worker count after the normal wasm-bindgen `init()` call:

```javascript
import initCore, {
  initThreadPool as initCoreThreadPool,
} from "./crates/wasm/pkg-web-threads/curvy_wasm.js";
import initProver, {
  initThreadPool as initProverThreadPool,
} from "./crates/prover/pkg-web-threads/curvy_prover.js";

await Promise.all([initCore(), initProver()]);

const available = navigator.hardwareConcurrency || 1;
const totalWorkers = Math.max(2, Math.min(available, 8));
const coreThreads = Math.floor(totalWorkers / 2);
const proverThreads = totalWorkers - coreThreads;

await Promise.all([
  initCoreThreadPool(coreThreads),
  initProverThreadPool(proverThreads),
]);
```

`initThreadPool(n)` sets that module's worker-pool size. If both modules are
loaded, their worker pools are separate and the approximate total worker budget
is `coreThreads + proverThreads`; choose both values accordingly.
If only one module is used, initialize only that module. Use a portable build
when the desired worker budget is one or the hosting environment cannot provide
cross-origin isolation.

## Features

- `curvy-core/parallel` enables Rayon for independent stealth scans and bulk
  Merkle-tree construction. It is disabled by default for direct Cargo users;
  `scripts/build-native.sh` enables it.
- `curvy-prover` enables native `std` and `parallel` features by default. The
  `wasm` and `wasm-threads` features expose its browser integration.
- `curvy-wasm/wasm-threads` enables Rayon-backed browser workers and requires a
  cross-origin-isolated page.

## License

[MIT](LICENSE) © Curvy Protocol d.o.o.

Portions of this software are ported from permissively licensed third-party
projects. See [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) for the full
attribution list.
