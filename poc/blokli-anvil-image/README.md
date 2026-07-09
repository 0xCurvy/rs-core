# curvy-bloklid-anvil — single-container "bloklid-anvil WITH Curvy"

A locally-buildable Docker image (**no Nix**) that reproduces blokli's single-container
dev UX **with Curvy**: one `docker run` yields

```
anvil (chain 31337)  +  HOPR contract suite  +  Curvy v2 suite (deployed + inited)  +  bloklid GraphQL
        :8545                    (both deployed by ONE forked blokli-contract-deployer)          :8080
```

This is the single-container face of `poc/blokli-env/` (which runs the same pieces as a
multi-service `docker compose` stack). The compose path stays the default; this image is
**additive** — driven by `poc/blokli-env/run.sh image-up` / `image-down`.

> **Deliberate deviation from blokli's own `bloklid-anvil` image: we ALSO expose `:8545`.**
> blokli keeps anvil internal (only `:8080`), but the Curvy SDK needs **direct RPC** for
> note indexing (`eth_getLogs` on `PendingNotes`/`CommittedNotes`/`CommittedNullifiers`)
> and root anchoring — bloklid does not index Curvy events yet (plan risk #3). Until it
> does, `:8545` is required.

## Reproduce

```bash
# build the image (records size + wall time):
poc/blokli-anvil-image/build.sh

# bring it up (builds first if missing), all checks, hands addresses to the SDK:
cd poc/blokli-env && ./run.sh image-up

# regression against the CONTAINER:
(cd ../../sdk  && cargo run --release -p curvy-e2e)          # 5/5
(cd ../../hopr && cargo run -p curvy-hopr-runner)            # settle confirmed

# teardown (compose path untouched):
./run.sh image-down
```

`run.sh image-up` runs the single container, waits for `/readyz`, copies
`curvy_deployed_addresses.json` to the SDK's default path, and runs `blokli-smoke`.

## Base-image / binary-compat path (verified) — and why it deviates

The task's preferred base was the published bloklid image + `COPY` anvil/cast onto it.
**That does not work here, and the investigation says why:**

| binary | source image | linkage | runs on… |
|---|---|---|---|
| `bloklid` | published `bloklid` (Nix) | aarch64 **musl, fully static** (no `PT_INTERP`) | any Linux |
| `anvil`/`cast` | `ghcr.io/foundry-rs/foundry` | aarch64 **glibc-dynamic** (Ubuntu 22.04) | needs `/lib/ld-linux-aarch64.so.1` + glibc |

The published bloklid image is a **Nix/musl** rootfs with **no glibc loader** at the
standard path, so foundry's glibc anvil/cast **cannot run on it**. Per the task's own
documented fallback, the runtime base is therefore **`debian:bookworm-slim` (glibc)**:

- `anvil` + `cast` (glibc) run natively on debian;
- `bloklid` (static musl, 18 MB) is `COPY`ied **out** of the published image (`cp -L` to
  dereference its `/nix/store` symlink) and runs anywhere;
- the forked `blokli-contract-deployer` is compiled **glibc** in the builder
  (`rust:1.96-slim-bookworm`, matching the runtime's bookworm glibc).

Both the bloklid image and the runtime are `bookworm`/aarch64, so there is no glibc
version skew. Multi-arch (linux/amd64) is future work — this builds for the host arch
(arm64 → linux/arm64).

## The two-repo build-context problem, and the solution

The blokli fork's `bloklid` crate path-depends on the **`curvy-bindings`** crate (the
hopr-bindings mirror in the v3-e2e contracts package) via an **absolute** path
(`/Users/vanja/Projects/v3-e2e/packages/contracts/evm/bindings/curvy-bindings`;
supersedes the earlier `rs-core/sdk/curvy-deployer` dep). A Docker build context is a
single tree, so the fork alone cannot resolve that dep.

**Solution — chosen: staging (option a).** `build.sh` rsyncs the fork plus ONLY the
`curvy-bindings` crate directory (self-contained: committed forge-bind codegen +
constants + the unlinked-aggregator hex; `--exclude target .forge`) into a clean
context, then rewrites the **staged** fork's path dep to the context-relative
`/build/curvy-bindings` (the **real fork is never touched**). The Dockerfile `COPY`ies
`blokli/ → /build/blokli` and `curvy-bindings/ → /build/curvy-bindings` and builds
`cargo build --release --locked -p bloklid --bin blokli-contract-deployer`.

What actually gets compiled beyond blokli: just `curvy-bindings` — it carries **no
heavy crypto** (the commitment-gas-fee root is a precomputed constant; arkworks never
enters the tree) and pins alloy `=2.1.0` exactly like `hopr-bindings`, so no second
alloy stack exists in the lockfile either. `--locked` uses blokli's committed lock, so
the build is reproducible.

> Alternatives considered: (b) context = the whole `~/Projects` with a `.dockerignore` —
> rejected (huge, and named/extra build contexts don't honor `.dockerignore`);
> (c) `cargo vendor` — heavier and unnecessary since `--locked` + path staging is already
> deterministic.

## Mining-mode design (verified in-container)

- **Deploy phase: automine.** anvil starts with no `--block-time`; the alloy deployers
  (HOPR `.watch()`, Curvy `get_receipt()`) each need their tx mined and automine mines
  per-tx (~seconds for the whole ~29-tx burst). These deployers **stall under interval
  mining**, so the deploy must not run there.
- **After deploy: interval mining `ANVIL_BLOCK_TIME`s (default 1s).** The entrypoint
  flips anvil via `anvil_setIntervalMining` so a block is produced every second. bloklid's
  indexer advances its historical sync on **new-head events**; a frozen (idle-automine)
  chain would stall it below head (the `drain_indexer` problem in `poc/blokli-env`) —
  observed live as `indexer … indexed=0` while the chain sat at a fixed block. Because
  bloklid starts **after** the flip, it sees continuous heads and self-drains to
  `/readyz` ready — **no external mining loop**.
  - **Gotcha (found + fixed live):** anvil's `*setIntervalMining` interval is in
    **SECONDS**, *not* milliseconds like Hardhat's `evm_setIntervalMining`. Passing
    `1000` (ms) sets a 1000-second interval and **freezes the chain**, stalling the
    indexer at `indexed=0`. The entrypoint passes `ANVIL_BLOCK_TIME` (=1) verbatim, then
    **verifies the block number actually advances** and falls back to an explicit
    `evm_mine` loop if it did not — so a wrong unit/method can never silently freeze it.

This is strictly better than blokli's own image (fixed `--block-time 1` from the start,
which would stall our combined deployer) and than `poc/blokli-env` (automine + a manual
`drain_indexer` mining loop in run.sh).

## How the Curvy addresses reach the SDK

The forked deployer writes `curvy_deployed_addresses.json` (Ignition-style) +
`curvy_contracts.toml` into **`/shared`** inside the container. `run.sh image-up` bind
-mounts `poc/blokli-env/generated → /shared`, then copies
`generated/curvy_deployed_addresses.json → poc/blokli-env/curvy_deployed_addresses.json`
— the path `curvy-e2e::deployed_addresses()` reads by default (overridable via
`CURVY_ADDRESSES`). So both `curvy-e2e` and `curvy-hopr-runner` consume the container's
addresses with zero code changes. (Without the mount you could equally
`docker cp curvy-bloklid-anvil:/shared/curvy_deployed_addresses.json .`.)

## Image contents

| path | what |
|---|---|
| `/usr/local/bin/bloklid` | static-musl bloklid, `cp -L`'d from the published image |
| `/usr/local/bin/anvil`, `/cast` | glibc, from `ghcr.io/foundry-rs/foundry:latest` |
| `/usr/local/bin/blokli-contract-deployer` | the **forked** deployer (`--with-curvy`), built here |
| `/etc/bloklid.base.toml` | baked base config (rpc → 127.0.0.1:8545) |
| `/usr/local/bin/entrypoint.sh` | the anvil→deploy→config→interval-mine→bloklid flow |
| `/data` (VOLUME) | bloklid sqlite DBs + assembled `config.toml` |
| `/shared` (VOLUME) | Curvy `curvy_deployed_addresses.json` + `curvy_contracts.toml` |

## Env knobs

`ANVIL_BLOCK_TIME` (post-deploy interval, default 1), `ANVIL_ACCOUNTS` (10),
`ANVIL_BALANCE` (10000), `CURVY` (1 = deploy Curvy, **default on** — it is the point of
this image), `CURVY_SHARED_DIR` (/shared).

## What a future Nix-native / upstream version needs

- **Publish `curvy-bindings`** to crates.io or a git host (hosting is postponed by
  owner decision; it is the final step). Then blokli's `bloklid/Cargo.toml` drops the
  absolute `path` dep, and the whole staging dance disappears — the fork becomes a
  normal git/crates dep (exactly the hopli / hopr-bindings pattern) and the image can
  be a pure blokli build.
- **Nix-native image**: extend blokli's `nix build .#docker-bloklid-anvil-…` to build the
  `--with-curvy` deployer and bake it in — then bloklid can stay on its own musl/Nix base
  (no debian, no `COPY`-out) and anvil/cast come from nixpkgs (musl-compatible) instead of
  the foundry glibc image.
- **Upstream the indexer drain**: blokli's anvil entrypoint should either run the deploy
  under `--block-time` or drain its indexer after the deploy burst (we do the latter via
  post-deploy interval mining) — worth raising with the transplant.
- **Multi-arch** (linux/amd64) via `buildx --platform`.

## Open issues / limitations

1. **bloklid does not index Curvy events** (by design). The SDK reads them via direct RPC
   on `:8545`; bloklid is the `TxSubmitter` only. This is the whole reason `:8545` is
   exposed.
2. **foundry tag is mutable** (`latest`). Pin by digest for CI reproducibility (the
   bloklid base already is digest-pinned).
3. **Absolute path dep in the fork** → the Dockerfile/build.sh are host-path-aware
   (`V3_E2E`, `BLOKLI_FORK` overridable). Resolved cleanly for local builds; the upstream
   fix is publishing `curvy-bindings` (above).
4. **Single-arch** (host arch only) for now.
