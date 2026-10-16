# Releasing

Every crate and package shares one version. A release publishes up to three sets,
each with `scripts/publish.sh`:

| Command | Publishes | Needs |
|---|---|---|
| `scripts/publish.sh crates` | `curvy-core`, `curvy-witness`, `curvy-prover`, `curvy-wasm` to crates.io | `cargo login` |
| `scripts/publish.sh wasm` | `@0xcurvy/rs-core-wasm` to npm | `npm login`, wasm-bindgen 0.2.126, the threads nightly |
| `scripts/publish.sh node` | `@0xcurvy/rs-core-node` and its four platform packages to npm | `npm login`, an Apple Silicon Mac with Docker Buildx, a Windows x64 host to test on |

Run any of them with `--dry-run` first: it builds and checks everything and
publishes nothing.

## 1. Prepare the release commit

1. Set the version everywhere:

   ```bash
   scripts/publish.sh version 0.1.3
   ```

   It updates `Cargo.toml`, the exact internal pins, `bindings/node` (package,
   lockfile and test), the version snippets in the docs and both lockfiles, then
   lists anything that still names the old version.
2. Add the dated `## [0.1.3] - YYYY-MM-DD` entry to `CHANGELOG.md` and its compare
   link at the bottom.
3. Run the checks (`scripts/check.sh all`, plus the ones your change touches) and
   inspect `cargo package --list -p <crate>` for each crate.
4. Merge to `main` and wait for CI to pass. CI does not run for changes to only
   Markdown files or `scripts/publish.sh`; `scripts/publish.sh` then accepts the
   newest earlier commit that CI passed.

## 2. Tag

On the merged commit:

```bash
git tag -a v0.1.3 -m "rs-core 0.1.3"
git push origin v0.1.3
```

`scripts/publish.sh` waits for this tag on `origin` and refuses to publish from any
other commit. A tag publishes nothing by itself.

## 3. Publish

Check out the tagged commit with a clean tree, then:

- **crates**: `scripts/publish.sh crates` publishes `curvy-core` and
  `curvy-witness`, waits for each on the crates.io index, then publishes
  `curvy-prover` and `curvy-wasm`.
- **wasm**: `scripts/publish.sh wasm` builds the browser modules, packs the
  package, installs it in an empty project, proves with it, and publishes that
  tarball.
- **node**: `scripts/publish.sh node` builds macOS arm64 natively and Linux and
  Windows in Docker. Before it publishes, test the Windows binary on a Windows x64
  host: copy `bindings/node/release/npm/win32-x64-msvc/curvy_rs_core_node.win32-x64-msvc.node`
  into `bindings/node` of a checkout of the tag and run
  `npm ci --ignore-scripts && npm test`. It publishes the platform packages, then
  the root package.

Each command asks before every publish, skips what is already published at this
version, and can be run again after a failure. A prerelease version goes to the npm
`next` tag, a release to `latest`.
