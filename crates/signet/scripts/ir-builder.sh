#!/usr/bin/env bash
# The graph builder, curvy-signet-ir-builder, at the commit ir-builder.pin names.
#
# Run it directly to build a graph with that builder; the arguments are the
# builder's own (`ir-builder.sh --help` lists them):
#
#   crates/signet/scripts/ir-builder.sh circuit.circom -o graph.bin \
#     --expect-r1cs proving_key.r1cs
#
# build-graph.sh and smoke-graph.sh source it for the builder and for the tool
# checks and scratch directory they share.
#
# curvy-signet-ir-builder compiles a circuit in-process with circom 2.2.3 and
# executes circom's intermediate representation, so it needs no C++ toolchain and
# no circomlib patch. It writes the postcard graph.bin that `signet export` reads,
# with the operation schema `--ops patched` names.
#
# It links circom's compiler and is GPL-3.0, so rs-core runs it as a separate
# program and builds no crate against it. ir-builder.pin names the commit to build
# and the SHA-256 of the lockfile committed beside the builder. The install checks
# out that commit, checks both, and builds it with `cargo install --locked`.

SIGNET_SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SIGNET_IR_BUILDER_PIN="$SIGNET_SCRIPTS_DIR/ir-builder.pin"
IR_BUILDER_GIT="$(sed -n 's/^git=//p' "$SIGNET_IR_BUILDER_PIN")"
IR_BUILDER_REV="$(sed -n 's/^rev=//p' "$SIGNET_IR_BUILDER_PIN")"
IR_BUILDER_LOCK_SHA256="$(sed -n 's/^lock_sha256=//p' "$SIGNET_IR_BUILDER_PIN")"

# Fails unless every named tool is on PATH.
signet_require() {
  local tool
  for tool in "$@"; do
    command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; return 1; }
  done
}

# Fails unless circom 2.2.3, the release the builder compiles with, is on PATH.
signet_require_circom() {
  signet_require circom || return 1
  local version
  version="$(circom --version)" || return 1
  [[ "$version" == "circom compiler 2.2.3" ]] || {
    echo "the builder compiles with circom 2.2.3; found $version" >&2
    return 1
  }
}

# Prints the SHA-256 of a file.
signet_sha256() {
  local digest
  if command -v sha256sum >/dev/null; then
    digest="$(sha256sum "$1")" || return 1
  else
    digest="$(shasum -a 256 "$1")" || return 1
  fi
  echo "${digest%% *}"
}

# Sets SIGNET_WORK to a scratch directory that is removed when the script exits.
signet_work_dir() {
  SIGNET_WORK="$(mktemp -d "${TMPDIR:-/tmp}/signet.XXXXXX")" || return 1
  trap 'rm -rf "$SIGNET_WORK"' EXIT
}

# Sets SIGNET_BUILDER to the builder: SIGNET_IR_BUILDER when it is set, otherwise
# the pinned commit, installed once under rs-core's target directory.
signet_ir_builder() {
  if [[ -n "${SIGNET_IR_BUILDER:-}" ]]; then
    [[ -f "$SIGNET_IR_BUILDER" && -x "$SIGNET_IR_BUILDER" ]] || {
      echo "SIGNET_IR_BUILDER is not an executable file: $SIGNET_IR_BUILDER" >&2
      return 1
    }
    SIGNET_BUILDER="$SIGNET_IR_BUILDER"
    return 0
  fi
  if [[ ! "$IR_BUILDER_REV" =~ ^[0-9a-f]{40}$ || ! "$IR_BUILDER_LOCK_SHA256" =~ ^[0-9a-f]{64}$ ]]; then
    echo "pin rev and lock_sha256 in $SIGNET_IR_BUILDER_PIN, or set SIGNET_IR_BUILDER" >&2
    echo "to a curvy-signet-ir-builder binary" >&2
    return 1
  fi
  local root="${SIGNET_IR_BUILDER_ROOT:-$SIGNET_SCRIPTS_DIR/../../../target/signet-ir-builder}/$IR_BUILDER_REV"
  SIGNET_BUILDER="$root/bin/curvy-signet-ir-builder"
  if [[ -x "$SIGNET_BUILDER" && -f "$root/PROVENANCE" ]]; then
    return 0
  fi
  signet_require git cargo || return 1
  echo "==> installing curvy-signet-ir-builder at $IR_BUILDER_REV" >&2
  mkdir -p "$root" || return 1
  # Each run builds in a directory of its own, so concurrent first runs do not
  # share a build, and the result moves into place with a rename.
  local stage
  stage="$(mktemp -d "$root/install.XXXXXX")" || return 1
  if ! signet_install_ir_builder "$stage" "$root"; then
    rm -rf "$stage"
    return 1
  fi
  rm -rf "$stage"
}

# Checks out and builds the pinned commit in $1, then moves the binary and a
# PROVENANCE record into $2.
signet_install_ir_builder() {
  local stage="$1" root="$2" source="$1/src"
  git init --quiet "$source" || return 1
  git -C "$source" fetch --quiet --depth 1 "$IR_BUILDER_GIT" "$IR_BUILDER_REV" || return 1
  git -C "$source" checkout --quiet FETCH_HEAD || return 1
  [[ "$(git -C "$source" rev-parse HEAD)" == "$IR_BUILDER_REV" ]] || {
    echo "the fetched commit is not $IR_BUILDER_REV" >&2
    return 1
  }
  local lock="$source/ir-builder/Cargo.lock" digest
  [[ -f "$lock" ]] || {
    echo "$IR_BUILDER_REV has no ir-builder/Cargo.lock, so --locked would not fix its dependencies" >&2
    return 1
  }
  digest="$(signet_sha256 "$lock")" || return 1
  [[ "$digest" == "$IR_BUILDER_LOCK_SHA256" ]] || {
    echo "ir-builder/Cargo.lock at $IR_BUILDER_REV is $digest, not lock_sha256 in $SIGNET_IR_BUILDER_PIN" >&2
    return 1
  }
  # rs-core's lint flags are for rs-core's code, not the builder's.
  RUSTFLAGS="" CARGO_TARGET_DIR="$stage/build" cargo install --quiet --locked \
    --path "$source/ir-builder" --root "$stage/install" >&2 || return 1
  local binary="$stage/install/bin/curvy-signet-ir-builder" binary_sha256
  [[ -x "$binary" ]] || { echo "cargo install produced no curvy-signet-ir-builder" >&2; return 1; }
  binary_sha256="$(signet_sha256 "$binary")" || return 1
  printf 'git=%s\nrev=%s\nlock_sha256=%s\nbinary_sha256=%s\n' \
    "$IR_BUILDER_GIT" "$IR_BUILDER_REV" "$IR_BUILDER_LOCK_SHA256" "$binary_sha256" \
    > "$stage/PROVENANCE" || return 1
  mkdir -p "$root/bin" || return 1
  mv -f "$binary" "$SIGNET_BUILDER" || return 1
  mv -f "$stage/PROVENANCE" "$root/PROVENANCE"
}

# Prints what produced a graph, to record with the artifact: the pin, or the
# override that replaced it, and the binary's version and digest.
signet_ir_builder_provenance() {
  local version digest
  version="$("$SIGNET_BUILDER" --version)" || return 1
  digest="$(signet_sha256 "$SIGNET_BUILDER")" || return 1
  if [[ -n "${SIGNET_IR_BUILDER:-}" ]]; then
    echo "builder=$SIGNET_BUILDER (SIGNET_IR_BUILDER, not the pin)"
  else
    echo "builder=$IR_BUILDER_GIT@$IR_BUILDER_REV"
  fi
  echo "builder_version=$version"
  echo "builder_sha256=$digest"
}

# Run directly rather than sourced: install the pinned builder if needed and hand
# it the arguments.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  set -euo pipefail
  signet_ir_builder
  exec "$SIGNET_BUILDER" "$@"
fi
