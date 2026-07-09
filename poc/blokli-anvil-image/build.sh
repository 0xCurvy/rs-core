#!/usr/bin/env bash
# build.sh — build the `curvy-bloklid-anvil` single-container image locally (NO Nix).
#
# The two-repo build-context problem: the blokli fork's bloklid crate path-depends on
# the `curvy-bindings` crate in the v3-e2e monorepo (an ABSOLUTE path on this host;
# supersedes the earlier rs-core/sdk/curvy-deployer dep). We solve it by STAGING:
# rsync the fork + the (self-contained) curvy-bindings crate into a clean build
# context, and rewrite the STAGED fork's path dep to a context-relative
# /build/curvy-bindings location (the REAL fork is never touched). The Dockerfile then
# COPYies both trees and builds `blokli-contract-deployer` with `--locked`. See README.md.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

IMAGE="${IMAGE:-curvy-bloklid-anvil:latest}"
V3_E2E="${V3_E2E:-/Users/vanja/Projects/v3-e2e}"
CURVY_BINDINGS="$V3_E2E/packages/contracts/evm/bindings/curvy-bindings"
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

# Stage the curvy-bindings crate (self-contained: committed forge-bind codegen +
# constants + the unlinked-aggregator hex; nothing outside the crate directory is
# referenced at build time, so ONLY the crate is staged — the rest of v3-e2e/rs-core
# never enters the context).
[ -f "$CURVY_BINDINGS/Cargo.toml" ] \
  || { echo "FATAL: curvy-bindings not found at $CURVY_BINDINGS (set V3_E2E=…)" >&2; exit 1; }
rsync -a --exclude 'target' --exclude '.forge' "$CURVY_BINDINGS/" "$CTX/curvy-bindings/"

# Rewrite the STAGED fork's absolute path dep -> context-relative (real fork untouched).
FORK_CARGO="$CTX/blokli/bloklid/Cargo.toml"
grep -q "$CURVY_BINDINGS" "$FORK_CARGO" \
  || { echo "FATAL: expected path dep '$CURVY_BINDINGS' not found in fork Cargo.toml" >&2; exit 1; }
sed -i.bak "s|$CURVY_BINDINGS|/build/curvy-bindings|g" "$FORK_CARGO"
rm -f "$FORK_CARGO.bak"
echo "    rewrote fork path dep -> /build/curvy-bindings (staged copy only)"

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
