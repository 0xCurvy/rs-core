# syntax=docker/dockerfile:1.7
# curvy-bloklid-anvil — single-container "bloklid-anvil WITH Curvy" for the PoC.
#
# One `docker run` yields: anvil (:8545) + HOPR suite + Curvy v2 suite (deployed+inited)
# + bloklid GraphQL (:8080). Built with a plain multi-stage Dockerfile — NO Nix.
#
# Base-image / binary-compat path (VERIFIED, deliberate deviation from blokli's own
# Nix image): the published bloklid image is aarch64 **musl, statically linked** (Nix),
# with no glibc dynamic loader; foundry's anvil/cast are **glibc-dynamic** (Ubuntu) and
# will NOT run on that musl/Nix base. So the runtime base is **debian:bookworm-slim**
# (glibc): anvil/cast run natively, the static-musl bloklid runs anywhere, and the
# forked deployer is built glibc here to match. (blokli's image runs bloklid on its own
# Nix base; we instead COPY bloklid OUT of it — the task's documented fallback.)

# ── external sources (digest-pinned where it matters) ────────────────────────────────
FROM europe-west3-docker.pkg.dev/hoprassociation/docker-images/bloklid:latest@sha256:b76b2a142a2fa161c2dc79cb9f01c3cb6f668eb841c6206748ad3259330147fc AS bloklid-src
# bloklid is a static-musl binary symlinked from /bin into /nix/store; `cp -L`
# dereferences it to a plain file, robust to the store-hash path.
RUN cp -L /bin/bloklid /bloklid.bin

FROM ghcr.io/foundry-rs/foundry:latest AS foundry-src
# anvil + cast are real files under /usr/local/bin (glibc-dynamic, Ubuntu 22.04).

# ── builder: compile the FORKED blokli-contract-deployer (linux/glibc) ───────────────
# The fork path-depends on rs-core/sdk/curvy-deployer; build.sh stages BOTH repos into
# the context (blokli/ + rs-core/) and rewrites the fork's path dep to /build/rs-core/…
# so the two-repo build resolves without touching the real fork. With
# default-features=false the deployer drops arkworks (no curvy-core); only curvy-abi +
# curvy-types come along. `--locked` uses blokli's committed Cargo.lock.
FROM rust:1.96-slim-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential cmake clang libclang-dev pkg-config perl git ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY rs-core /build/rs-core
COPY blokli  /build/blokli
WORKDIR /build/blokli
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/blokli/target \
    cargo build --release --locked -p bloklid --bin blokli-contract-deployer \
 && cp target/release/blokli-contract-deployer /usr/local/bin/blokli-contract-deployer

# ── runtime: debian-slim + the four binaries + entrypoint ────────────────────────────
FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
      curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY --from=bloklid-src /bloklid.bin                              /usr/local/bin/bloklid
COPY --from=foundry-src /usr/local/bin/anvil                      /usr/local/bin/anvil
COPY --from=foundry-src /usr/local/bin/cast                       /usr/local/bin/cast
COPY --from=builder     /usr/local/bin/blokli-contract-deployer   /usr/local/bin/blokli-contract-deployer
COPY config/bloklid.base.toml /etc/bloklid.base.toml
COPY entrypoint.sh            /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/bloklid \
             /usr/local/bin/anvil /usr/local/bin/cast \
             /usr/local/bin/blokli-contract-deployer

# 8080 = bloklid GraphQL/health; 8545 = anvil RPC (deviation: needed by the Curvy SDK
# for note indexing / root anchoring until blokli indexes Curvy events).
EXPOSE 8080 8545
VOLUME ["/data", "/shared"]
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
