# Curvy Rust core

[![crates.io](https://img.shields.io/crates/v/curvy-core?logo=rust&logoColor=black&label=crates.io&labelColor=white&color=orange)](https://crates.io/crates/curvy-core)
[![wasm-bindings](https://img.shields.io/npm/v/@0xcurvy/rs-core-wasm?logo=npm&logoColor=black&label=wasm-bindings&labelColor=white&color=red)](https://www.npmjs.com/package/@0xcurvy/rs-core-wasm)
[![CI](https://img.shields.io/github/actions/workflow/status/0xCurvy/rs-core/ci.yml?branch=main&logo=github&logoColor=black&label=CI&labelColor=white)](https://github.com/0xCurvy/rs-core/actions/workflows/ci.yml)
[![docs.rs](https://img.shields.io/docsrs/curvy-core?logo=docsdotrs&logoColor=black&label=docs.rs&labelColor=white&color=blue)](https://docs.rs/curvy-core)

Rust cryptography, witness evaluation and Groth16 proving for the Curvy protocol.

## Crates

| Crate | Use it for | API documentation |
|---|---|---|
| `curvy-core` | Poseidon, BabyJubjub, signing, note commitments, stealth addressing, Merkle trees, circuit-input builders | [docs.rs/curvy-core](https://docs.rs/curvy-core) |
| `curvy-witness` | Authenticated `curvy-graph-v1` parsing and Circom witness evaluation | [docs.rs/curvy-witness](https://docs.rs/curvy-witness) |
| `curvy-prover` | Witness evaluation plus snarkjs `.zkey` parsing and self-verified Groth16 proofs; the native prover executable and the prover WASM module | [docs.rs/curvy-prover](https://docs.rs/curvy-prover) |
| `curvy-wasm` | JavaScript bindings for `curvy-core` | [docs.rs/curvy-wasm](https://docs.rs/curvy-wasm) |

The crates share one version and pin each other exactly; depend on the same
version of each.

| Document | Contents |
|---|---|
| [CHANGELOG.md](CHANGELOG.md) | Release notes and migration steps |
| [crates/prover/SPARROW.md](crates/prover/SPARROW.md) | Bounded-memory streaming proving |
| [bindings/ffi](bindings/ffi/README.md), [bindings/node](bindings/node/README.md), [bindings/wasm](bindings/wasm/README.md) | C ABI, native Node.js and npm WASM packages |
| [crates/signet/README.md](crates/signet/README.md) | Building and validating witness-graph artifacts |
| [tools/artifacts/README.md](tools/artifacts/README.md) | Release bundle validation |
| [RELEASING.md](RELEASING.md) | Releasing and publishing |

## Install

```toml
[dependencies]
curvy-core = "=0.1.2"
```

For witness evaluation or proving, add:

```toml
curvy-witness = "=0.1.2"
curvy-prover = "=0.1.2"
```

Requires Rust 1.99 or newer.

## Signing profiles

`curvy-core` signs EdDSA-Poseidon over BabyJubjub with either profile:

| Profile | Key | Rust entry points |
|---|---|---|
| Seed | Hex-encoded private seed bytes, derived to a scalar with BLAKE-512 and pruning | `pub_from_private_key_hex`, `sign_hex`, `SeedNoteSigner` |
| Direct scalar | A non-zero canonical BabyJubjub subgroup scalar; the public key is `scalar * Base8` | `ScalarSigningKey`, `BabyJubSecretScalar`, `BabyJubPoint` |

Use the profile the key was created with. The same bytes read through the other
profile are a different key; never convert between them.

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

Parse values from storage, RPC or users into the checked types:

- `Bn254Fr` rejects non-canonical BN254 field encodings.
- `BabyJubSecretScalar` rejects zero and values outside the subgroup scalar range.
- `BabyJubPoint` checks the curve, the prime-order subgroup and the identity.
- `ScalarSigningKey` keeps the scalar and its public key together.

`SeedNoteSigner` and `ScalarSigningKey` implement `NoteSigner`, which
`build_withdrawal_with_signer` and `build_aggregation_with_signer` take.
`build_withdrawal` and `build_aggregation` use the seed profile.

## Witness evaluation and proving

`curvy-witness` evaluates a deployment's `curvy-graph-v1` artifact. `curvy-prover`
combines it with the matching snarkjs `.zkey` and returns a self-verified Groth16
proof in snarkjs JSON:

- `ResidentProver` (HAWK) authenticates and loads the key once and reuses it.
- `StreamingProver` (SPARROW) authenticates the key in chunks and proves with
  bounded memory; see [SPARROW.md](crates/prover/SPARROW.md).

```rust
use curvy_prover::ResidentProver;

fn prove(
    zkey: &[u8],
    zkey_sha256: &str,
    graph: &[u8],
    graph_sha256: &str,
    inputs: &str,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let prover = ResidentProver::from_artifacts(
        zkey,
        zkey_sha256,
        graph,
        graph_sha256,
    )?;
    let proof = prover.prove_json(inputs)?;

    Ok((proof.proof_json, proof.public_signals_json))
}
```

- Both artifact digests are required, and both artifacts are authenticated before
  they are parsed.
- The graph and `.zkey` come from the Curvy deployment you prove for; the crates
  do not bundle them.
- Native callers reading files should use `ResidentProver::from_artifacts_reader`,
  which does not keep the whole zkey in memory beside the parsed key.

### Native prover executable

```bash
cargo install --locked curvy-prover --version 0.1.2 --bin curvy-native-prover
```

Add `--features parallel` for the multithreaded build that `scripts/build.sh native`
produces. The executable is installed to `$CARGO_HOME/bin` (normally
`~/.cargo/bin`):

```text
curvy-native-prover <zkey> <zkey-sha256> <graph.bin> <graph-sha256> \
  <input.json> <proof.json> <public.json>
```

It runs `ResidentProver` and writes snarkjs-compatible proof and public-signal
JSON; its timing JSON reports `proverMode` and `profile`. With `parallel`,
`CURVY_PROVER_NUM_THREADS` sets the thread count (1 to 64, default 1); a serial
build refuses values above 1.

### Parallelism

`curvy-core` and `curvy-prover` run on one thread unless built with their
`parallel` feature, which uses the host's Rayon global pool:

```toml
curvy-core = { version = "=0.1.2", features = ["parallel"] }
curvy-prover = { version = "=0.1.2", features = ["parallel"] }
```

Configure the pool with `RAYON_NUM_THREADS`, or with
`rayon::ThreadPoolBuilder::num_threads(...).build_global()` before the first
parallel call. Witness evaluation is always single-threaded.

## Building

[rustup](https://rustup.rs/) is the only prerequisite for native builds:
`rust-toolchain.toml` installs Rust 1.99.0 and the WASM target on first use. WASM
builds also need the pinned wasm-bindgen CLI, and the threaded build a pinned
nightly:

```bash
cargo install wasm-bindgen-cli --version 0.2.126 --locked
rustup toolchain install nightly-2026-08-15 --profile minimal \
  --component rust-src --target wasm32-unknown-unknown    # wasm-web-threads only
```

`scripts/build.sh` builds every target; run it without arguments for a menu.

| Command | Output |
|---|---|
| `scripts/build.sh native` | Native libraries with `parallel`, and `target/release/curvy-native-prover` |
| `scripts/build.sh wasm-nodejs` | `crates/wasm/pkg-node`, `crates/prover/pkg-node` (CommonJS) |
| `scripts/build.sh wasm-web` | `crates/{wasm,prover}/pkg-web` (ES modules, single thread) |
| `scripts/build.sh wasm-bundler` | `crates/{wasm,prover}/pkg-bundler` (Vite, webpack, Rollup) |
| `scripts/build.sh wasm-web-threads` | `crates/{wasm,prover}/pkg-web-threads` (ES modules with Rayon workers) |
| `scripts/build.sh all-portable` | `native`, `wasm-nodejs`, `wasm-web` and `wasm-bundler` |
| `scripts/build.sh npm --pack` | `@0xcurvy/rs-core-wasm` in `dist/npm` and its tarball |
| `scripts/build.sh ffi-header` | `bindings/ffi/include/curvy.h` |

Each WASM target writes two independent modules: `curvy-wasm` (core cryptography
and trees) and `curvy-prover` (witness evaluation and proving). Ship only the one
you use. The `wasm-*` targets take build options, for example
`scripts/build.sh wasm-web --sparrow` or `scripts/build.sh wasm-web-threads --simd`;
`scripts/lib/build-wasm.sh` lists them. Published packages are built without
options.

Every WASM build needs WebAssembly SIMD and bulk memory at runtime.

### Threaded browser build

The page must be cross-origin isolated:

```text
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
```

Initialize each threaded module you load, then give it a worker count. The two
modules have separate pools:

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

Use a portable build when the page cannot be cross-origin isolated or one worker
is enough. `CURVY_WASM_THREADS_TOOLCHAIN` selects another nightly.

### npm package

JavaScript projects depend on `@0xcurvy/rs-core-wasm` instead of building this
repository. It has one entry per browser build (`core`, `core-threads`, `prover`,
`prover-threads`) plus each `.wasm`, with the wasm-bindgen output unmodified; see
[bindings/wasm](bindings/wasm/README.md).

## Features

| Feature | Effect |
|---|---|
| `curvy-core/parallel` | Rayon for stealth scans and bulk Merkle construction |
| `curvy-prover/parallel` | Proving on the Rayon global pool |
| `curvy-prover` `signet-v2`, `sparrow`, `wasm`, `wasm-threads`, `bench` | Opt-in; `sparrow` and `bench` enable SAGE (see the [crate README](crates/prover/README.md)) |
| `curvy-wasm/wasm-threads` | Rayon browser workers; needs a cross-origin-isolated page |

## Development

`scripts/check.sh` runs the repository's checks; without arguments it lists them
with the build each needs. `scripts/check.sh all` runs every check whose build and
tools are present.

- Plain `cargo test` covers only `curvy-core` and `curvy-witness`. Run
  `cargo test --workspace --all-targets --locked`, and the per-feature runs in
  `.github/workflows/ci.yml`.
- The golden vectors in `crates/*/testdata` are protocol test oracles; change
  one only together with the reference it comes from.
- crates.io gets `curvy-core`, `curvy-witness`, `curvy-prover` and `curvy-wasm`.
  The SIGNET tooling, bindings, benchmarks and debug CLI are not published.

## License

[MIT](LICENSE) © Curvy Protocol d.o.o.

Portions are ported from permissively licensed third-party projects; see
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
