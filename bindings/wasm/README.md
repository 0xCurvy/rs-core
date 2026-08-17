# @0xcurvy/rs-core-wasm

Browser WebAssembly builds of the [Curvy Rust core](https://github.com/0xCurvy/rs-core) - stealth-address
crypto (Poseidon, BabyJubjub/EdDSA, the note cipher, Merkle state, scanning) and the Groth16 prover.

This package is generated output: `wasm-bindgen --target web`, published unmodified from a tagged
release of the `rs-core` repository. The Rust crates themselves live on [crates.io](https://crates.io)
(`curvy-core`, `curvy-witness`, `curvy-prover`, `curvy-wasm`); this is the artifact for JavaScript.

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
`?url`-style imports and for Node, which reads the bytes off disk.

```js
import init, { poseidon } from "@0xcurvy/rs-core-wasm/core";

await init(); // resolves curvy_wasm_bg.wasm relative to this module
```

## Bundler setup

The generated glue locates its binary with `new URL('curvy_wasm_bg.wasm', import.meta.url)`, and the
threaded builds spawn their Rayon workers with `new Worker(new URL('./workerHelpers.js', import.meta.url),
{ type: 'module' })`. Both are the patterns bundlers are expected to resolve, and both depend on the
files staying where they are on disk.

**Vite** - exclude this package from dependency pre-bundling. The optimizer copies dependency code
into `node_modules/.vite/deps/`, where those relative URLs no longer point at anything:

```js
export default defineConfig({
  optimizeDeps: { exclude: ["@0xcurvy/rs-core-wasm"] },
});
```

**webpack 5** resolves both patterns natively; no configuration is needed.

For any bundler that does neither, pass the binary in yourself - `init({ module_or_path: url })`
accepts a URL, a `Response`, bytes, or a compiled `WebAssembly.Module`.

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

The version tracks the `rs-core` workspace version exactly: `@0xcurvy/rs-core-wasm@x.y.z` is built from
tag `vx.y.z`, and all four entries always come from that single commit. Releases are published from CI
with [npm provenance](https://docs.npmjs.com/generating-provenance-statements).

Licensed MIT. See `THIRD-PARTY-NOTICES.md` for the dependencies compiled into the binaries.
