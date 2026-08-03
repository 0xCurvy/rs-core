#!/usr/bin/env bash
# Interactive build selector. Pass a choice as the first argument for CI.
set -euo pipefail

cd "$(dirname "$0")/.."

usage() {
  cat <<'EOF'
usage: scripts/build.sh [choice]

choices:
  native             complete native Rust core
  wasm-nodejs        complete portable WASM core for Node.js
  wasm-web           complete portable WASM core for browsers
  wasm-bundler       complete portable WASM core for bundlers
  wasm-web-threads   complete threaded WASM core for browsers
  all-portable       native plus all portable WASM targets
EOF
}

run_choice() {
  case "$1" in
    native)
      scripts/build-native.sh
      ;;
    wasm-nodejs)
      scripts/build-wasm.sh nodejs
      ;;
    wasm-web)
      scripts/build-wasm.sh web
      ;;
    wasm-bundler)
      scripts/build-wasm.sh bundler
      ;;
    wasm-web-threads)
      scripts/build-wasm.sh web --threads
      ;;
    all-portable)
      scripts/build-native.sh
      scripts/build-wasm.sh nodejs
      scripts/build-wasm.sh web
      scripts/build-wasm.sh bundler
      ;;
    help|--help|-h)
      usage
      ;;
    *)
      echo "unknown build choice: $1" >&2
      usage >&2
      return 1
      ;;
  esac
}

if [ "$#" -gt 1 ]; then
  usage >&2
  exit 1
fi

if [ "$#" -eq 1 ]; then
  run_choice "$1"
  exit
fi

cat <<'EOF'
What do you want to build?
  1) Complete native Rust core
  2) Complete portable WASM core for Node.js
  3) Complete portable WASM core for browsers
  4) Complete portable WASM core for bundlers
  5) Complete threaded WASM core for browsers
  6) Native plus all portable WASM targets
EOF
read -r -p "Select [1-6]: " selection

case "$selection" in
  1) run_choice native ;;
  2) run_choice wasm-nodejs ;;
  3) run_choice wasm-web ;;
  4) run_choice wasm-bundler ;;
  5) run_choice wasm-web-threads ;;
  6) run_choice all-portable ;;
  *)
    echo "invalid selection: $selection" >&2
    exit 1
    ;;
esac
