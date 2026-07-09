#!/usr/bin/env bash
# build.sh — build the `curvy-bloklid-anvil` single-container image locally (NO Nix).
#
# The two-repo build-context problem: the blokli fork's bloklid crate path-depends on
# rs-core/sdk/curvy-deployer (an ABSOLUTE path on this host). We solve it by STAGING:
# rsync BOTH repos (minus target/.git/heavy-binaries) into a clean build context, and
# rewrite the STAGED fork's path dep to a context-relative /build/rs-core/... location
# (the REAL fork is never touched). The Dockerfile then COPYies both trees and builds
# `blokli-contract-deployer` with `--locked`. See README.md.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

IMAGE="${IMAGE:-curvy-bloklid-anvil:latest}"
RS_CORE="${RS_CORE:-/Users/vanja/Projects/rs-core}"
BLOKLI_FORK="${BLOKLI_FORK:-/Users/vanja/Projects/blokli}"

command -v rsync >/dev/null || { echo "FATAL: rsync required" >&2; exit 1; }
command -v docker >/dev/null || { echo "FATAL: docker required" >&2; exit 1; }

CTX="$(mktemp -d "${TMPDIR:-/tmp}/curvy-bloklid-ctx.XXXXXX")"
cleanup() { rm -rf "$CTX"; }
trap cleanup EXIT

echo "==> assembling build context in $CTX"
cp "$HERE/Dockerfile" "$HERE/entrypoint.sh" "$CTX/"
mkdir -p "$CTX/config"
cp "$HERE/config/bloklid.base.toml" "$CTX/config/"

# Stage the blokli fork (source only).
rsync -a --exclude '.git' --exclude 'target' "$BLOKLI_FORK/" "$CTX/blokli/"

# Stage rs-core (source only; drop heavy build artifacts we don't need — the deployer
# build compiles only curvy-deployer + curvy-abi + curvy-types, but we keep ALL
# Cargo.toml files so cargo's workspace-membership validation resolves cleanly).
rsync -a \
  --exclude '.git' --exclude 'target' \
  --exclude '*.zkey' --exclude '*.wtns' --exclude '*.graph.bin' --exclude '*.wasm' \
  --exclude 'node_modules' \
  "$RS_CORE/" "$CTX/rs-core/"

# Rewrite the STAGED fork's absolute path dep -> context-relative (real fork untouched).
FORK_CARGO="$CTX/blokli/bloklid/Cargo.toml"
grep -q "$RS_CORE/sdk/curvy-deployer" "$FORK_CARGO" \
  || { echo "FATAL: expected path dep '$RS_CORE/sdk/curvy-deployer' not found in fork Cargo.toml" >&2; exit 1; }
sed -i.bak "s|$RS_CORE/sdk/curvy-deployer|/build/rs-core/sdk/curvy-deployer|g" "$FORK_CARGO"
rm -f "$FORK_CARGO.bak"
echo "    rewrote fork path dep -> /build/rs-core/sdk/curvy-deployer (staged copy only)"

echo "==> docker build $IMAGE  (cold builds compile all of bloklid's deps; be patient)"
START=$(date +%s)
DOCKER_BUILDKIT=1 docker build -t "$IMAGE" "$CTX"
END=$(date +%s)

# NB: `docker image inspect .Size` under-counts for a buildx manifest list (it reads the
# attestation config, not the platform image), so report the real on-disk size instead.
SIZE="$(docker images "${IMAGE%%:*}" --format '{{.Size}}' 2>/dev/null | head -1)"
echo
echo "==> built $IMAGE"
echo "    size:       ${SIZE:-unknown}  (on-disk, uncompressed)"
echo "    wall time:  $((END - START)) s"
