# @0xcurvy/rs-core-wasm

Browser WebAssembly builds of the [Curvy Rust core](https://github.com/0xCurvy/rs-core) - stealth-address
crypto (Poseidon, BabyJubjub/EdDSA, the note cipher, Merkle state, scanning) and the Groth16 prover.

Generated with `wasm-bindgen --target web` from a tagged `rs-core` release and published unmodified.
The Rust crates are on [crates.io](https://crates.io) (`curvy-core`, `curvy-witness`, `curvy-prover`,
`curvy-wasm`).

Most applications should use [`@0xcurvy/curvy-sdk`](https://www.npmjs.com/package/@0xcurvy/curvy-sdk)
instead of consuming these bindings directly.

## Entry points

| Subpath | Build | Notes |
| --- | --- | --- |
| `@0xcurvy/rs-core-wasm/core` | single-threaded | crypto core; works everywhere |
| `@0xcurvy/rs-core-wasm/core-threads` | Rayon | requires cross-origin isolation |
| `@0xcurvy/rs-core-wasm/prover` | single-threaded | witness + Groth16 |
| `@0xcurvy/rs-core-wasm/prover-threads` | Rayon | requires cross-origin isolation |

Each entry also exports its raw binary (`@0xcurvy/rs-core-wasm/core/curvy_wasm_bg.wasm`) for
`?url`-style imports and for Node.

```js
import init, { poseidon } from "@0xcurvy/rs-core-wasm/core";

await init(); // resolves curvy_wasm_bg.wasm relative to this module
```

Both prover entries load a proving key from a snarkjs `.zkey` or a compact `.czkey`
([curvy-prover's compact zkeys](https://github.com/0xCurvy/rs-core/blob/main/crates/prover/README.md#compact-zkeys)).
`new WasmResidentProver(zkey, zkeySha256, graph, graphSha256)` tells them apart by their first bytes;
`zkeySha256` is the SHA-256 of the file passed, whichever it is. A compact key is about a quarter of
the size and costs about 3 s more to load single-threaded for a 40 MB key.

The witness graph is a SIGNET artifact (`SIGNET01` or `CVYWIT01`) at body version 1 or 2, raw or
zstd-compressed; `graphSha256` is the SHA-256 of the bytes passed. Version 2
([`signet transcode`](https://github.com/0xCurvy/rs-core/blob/main/crates/signet/README.md#re-encoding-the-body-version-with-no-postcard-source))
computes the same witness as version 1 and, at zstd -9, is 48-66% smaller for the shipped graphs. Both entries
accept both versions from 0.1.5; earlier releases refuse version 2 with "unsupported witness graph
format version 2".

## Bundler setup

The generated glue locates its binary with `new URL('curvy_wasm_bg.wasm', import.meta.url)`, and the
threaded builds spawn their Rayon workers with `new Worker(new URL('./workerHelpers.js', import.meta.url),
{ type: 'module' })`. Both require the files to stay where they are in the package.

**Vite** - exclude this package from dependency pre-bundling, which moves the code to
`node_modules/.vite/deps/` and breaks those relative URLs:

```js
export default defineConfig({
  optimizeDeps: { exclude: ["@0xcurvy/rs-core-wasm"] },
});
```

**webpack 5** resolves both patterns; no configuration is needed.

For other bundlers, pass the binary in yourself - `init({ module_or_path: url })` accepts a URL, a
`Response`, bytes, or a compiled `WebAssembly.Module`.

## Threads

The `*-threads` entries are built with atomics and shared memory. They need a
[cross-origin-isolated](https://developer.mozilla.org/docs/Web/API/Window/crossOriginIsolated) page:

```
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
```

or, where third-party embeds must keep working, `Document-Isolation-Policy: isolate-and-credentialless`.
Call `initThreadPool(n)` after `init()`. Feature-detect with `crossOriginIsolated` and fall back to the
single-threaded entry - the two expose the same API.

## Node

`fetch` cannot read `file:` URLs, so pass the bytes explicitly:

```js
import { readFile } from "node:fs/promises";
import init from "@0xcurvy/rs-core-wasm/core";

const wasm = await readFile(
  new URL(import.meta.resolve("@0xcurvy/rs-core-wasm/core/curvy_wasm_bg.wasm")),
);
await init({ module_or_path: wasm });
```

## Versioning

`@0xcurvy/rs-core-wasm@x.y.z` is built from tag `vx.y.z` of `rs-core`, and all four entries come from
that single commit.

Licensed MIT. See `THIRD-PARTY-NOTICES.md` for the dependencies compiled into the binaries.
