#!/usr/bin/env bash
# Publishes a release. RELEASING.md lists the whole release.
#
#   scripts/publish.sh version <new-version>
#   scripts/publish.sh <crates|wasm|node> [--dry-run]
#
#   version  sets the workspace version, the exact internal dependency pins, the
#            Node package and its test, the version snippets in the docs and both
#            lockfiles, then lists anything that still names the old version
#
#   crates   curvy-core and curvy-witness, then curvy-prover and curvy-wasm, to
#            crates.io (needs `cargo login`)
#   wasm     @0xcurvy/rs-core-wasm to npm (needs `npm login`)
#   node     @0xcurvy/rs-core-node and its four platform packages to npm
#            (Apple Silicon Mac with Docker; needs `npm login`)
#
# A run checks that the tree is clean, the versions agree and CHANGELOG.md has a
# dated entry; waits until the annotated tag v<version> for this commit is on
# origin; checks that CI passed for it; builds and checks what it publishes; and
# asks before each publish. Packages already published at this version are
# skipped, so a run that stopped can be repeated.
#
# --dry-run builds and checks everything without publishing. It does not wait
# for the tag or check CI, and reports failed release checks as warnings, so it
# can run before the release commit.
set -euo pipefail

cd "$(dirname "$0")/.."

usage() {
  sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
}

step() { printf '\n==> %s\n' "$*"; }
fail() { echo "error: $*" >&2; exit 1; }
confirm() {
  local answer
  read -r -p "$1 [y/N] " answer
  [[ "$answer" == y || "$answer" == Y ]]
}

# Rewrites every place that names the release version.
set_version() {
  local old new old_re file
  old="$(sed -n '/^\[workspace\.package\]/,/^\[/s/^version *= *"\(.*\)"/\1/p' Cargo.toml)"
  new="$1"
  old_re="${old//./\\.}"
  [[ "$new" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || fail "not a version: $new"
  [[ "$new" != "$old" ]] || fail "the version is already $new"
  step "Setting version $old -> $new"
  # sed -i.bak works with both BSD and GNU sed; only the backups made here are removed.
  edit() {
    local file="${*: -1}"
    sed -i.bak "$@"
    rm -f "$file.bak"
  }
  edit "/^\[workspace\.package\]/,/^\[/s/^version = \"$old_re\"/version = \"$new\"/" Cargo.toml
  # Exact pins in manifests and docs, and the documented cargo install command.
  while IFS= read -r file; do
    edit -e "s/\"=$old_re\"/\"=$new\"/g" -e "s/--version $old_re /--version $new /g" "$file"
  done < <(git grep -l -F -e "\"=$old\"" -e "--version $old " -- '*Cargo.toml' '*.md' ':!CHANGELOG.md')
  edit "s/rsCoreVersion(), \"$old_re\"/rsCoreVersion(), \"$new\"/" bindings/node/test/binding.test.mjs
  (cd bindings/node && npm version "$new" --no-git-tag-version >/dev/null)
  cargo update --workspace --offline --quiet
  cargo update --workspace --offline --quiet --manifest-path fuzz/Cargo.toml
  step "Still naming $old (CHANGELOG.md and lockfiles excluded)"
  git grep -n -F "$old" -- ':!CHANGELOG.md' ':!*.lock' ':!*package-lock.json' || echo "nothing"
  echo
  echo "Next: add a '## [$new] - YYYY-MM-DD' entry to CHANGELOG.md and its link at the bottom."
}

target=""
dry_run=0
new_version=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) dry_run=1 ;;
    crates | wasm | node) target="$1" ;;
    version)
      new_version="${2:?usage: scripts/publish.sh version <new-version>}"
      shift
      ;;
    help | --help | -h) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
  shift
done
if [[ -n "$new_version" ]]; then
  set_version "$new_version"
  exit
fi
if [[ -z "$target" ]]; then
  cat <<'EOF'
What do you want to publish?
  1) crates to crates.io
  2) @0xcurvy/rs-core-wasm to npm
  3) @0xcurvy/rs-core-node to npm
EOF
  read -r -p "Select [1-3]: " selection
  case "$selection" in
    1) target=crates ;;
    2) target=wasm ;;
    3) target=node ;;
    *) fail "invalid selection: $selection" ;;
  esac
fi

# A failed release check stops a real run and warns in a dry run.
release_check() {
  if ((dry_run)); then
    echo "warning: $*" >&2
  else
    fail "$*"
  fi
}

version="$(sed -n '/^\[workspace\.package\]/,/^\[/s/^version *= *"\(.*\)"/\1/p' Cargo.toml)"
[[ -n "$version" ]] || fail "no [workspace.package] version in Cargo.toml"
tag="v$version"
# npm refuses a prerelease without a dist-tag, and a prerelease must not become `latest`.
if [[ "${version%%+*}" == *-* ]]; then dist_tag=next; else dist_tag=latest; fi

step "Checking release $version ($target)"
[[ -z "$(git status --porcelain)" ]] || release_check "the working tree is not clean"
grep -q "^## \[$version\] - [0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\}" CHANGELOG.md ||
  release_check "CHANGELOG.md has no dated '## [$version] - YYYY-MM-DD' entry"
node_version="$(node -p 'require("./bindings/node/package.json").version')"
[[ "$node_version" == "$version" ]] || release_check "bindings/node/package.json is $node_version, not $version"
metadata="$(cargo metadata --no-deps --format-version 1 --locked)"
for crate in curvy-core curvy-witness curvy-prover curvy-wasm; do
  crate_version="$(node -e '
    const packages = JSON.parse(process.argv[1]).packages;
    console.log(packages.find((p) => p.name === process.argv[2])?.version ?? "");
  ' "$metadata" "$crate")"
  [[ "$crate_version" == "$version" ]] || release_check "$crate is $crate_version, not $version"
done
echo "release version: $version"

head_commit="$(git rev-parse HEAD)"
if ((dry_run)); then
  echo "dry run: not waiting for $tag or checking CI"
else
  step "Waiting for the tag $tag on origin at $(git rev-parse --short HEAD)"
  if ! git rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
    echo "Tag the release commit and push the tag:"
    echo "  git tag -a $tag -m \"rs-core $version\" && git push origin $tag"
  fi
  until git fetch --quiet origin "+refs/tags/$tag:refs/tags/$tag" 2>/dev/null; do
    printf '.'
    sleep 15
  done
  echo
  [[ "$(git cat-file -t "$tag")" == tag ]] || fail "$tag is not an annotated tag"
  [[ "$(git rev-parse "$tag^{commit}")" == "$head_commit" ]] ||
    fail "$tag points at $(git rev-parse --short "$tag^{commit}"), not HEAD; check out the tagged commit"
  echo "$tag is on origin at HEAD"

  step "Checking CI for $tag"
  if command -v gh >/dev/null 2>&1; then
    conclusion="$(gh run list --workflow ci.yml --commit "$head_commit" --limit 1 \
      --json conclusion --jq '.[0].conclusion // "none"' 2>/dev/null || echo unknown)"
    echo "ci.yml on $(git rev-parse --short HEAD): $conclusion"
    if [[ "$conclusion" == none ]]; then
      # CI does not run for a commit that changes only Markdown or this script
      # (ci.yml paths-ignore). Accept the newest earlier commit CI passed when
      # nothing else changed since.
      passed=""
      while read -r sha; do
        if git merge-base --is-ancestor "$sha" HEAD 2>/dev/null; then
          passed="$sha"
          break
        fi
      done < <(gh run list --workflow ci.yml --branch main --event push --status success \
        --limit 50 --json headSha --jq '.[].headSha' 2>/dev/null)
      if [[ -n "$passed" ]] &&
        [[ -z "$(git diff --name-only "$passed" HEAD | grep -v -E '\.md$|^scripts/publish\.sh$' || true)" ]]; then
        echo "CI passed on $(git rev-parse --short "$passed"); only Markdown or scripts/publish.sh changed since"
        conclusion=success
      fi
    fi
    [[ "$conclusion" == success ]] || confirm "CI has not passed for this commit. Publish anyway?" ||
      fail "stopped: CI has not passed"
  else
    confirm "gh is not installed, so CI was not checked. Has ci.yml passed for $tag?" ||
      fail "stopped: CI not confirmed"
  fi
fi

# crates.io sparse index entry; names of four or more characters live at aa/bb/name.
crate_published() {
  curl -fsS "https://index.crates.io/${1:0:2}/${1:2:2}/$1" 2>/dev/null |
    grep -q "\"vers\":\"$version\""
}

npm_published() {
  npm view "$1@$version" version >/dev/null 2>&1
}

publish_crates() {
  local crate dirty=()
  ((dry_run)) && dirty=(--allow-dirty)
  for crate in curvy-core curvy-witness curvy-prover curvy-wasm; do
    if crate_published "$crate"; then
      echo "$crate $version is already on crates.io; skipping"
      continue
    fi
    step "Packaging $crate"
    cargo package --locked "${dirty[@]+"${dirty[@]}"}" -p "$crate" --list
    if ((dry_run)); then
      # curvy-prover and curvy-wasm verify against curvy-core and curvy-witness
      # from crates.io, so only those two can be verified before publishing.
      if [[ "$crate" == curvy-core || "$crate" == curvy-witness ]]; then
        cargo publish --locked "${dirty[@]+"${dirty[@]}"}" -p "$crate" --dry-run
      fi
      continue
    fi
    cargo publish --locked -p "$crate" --dry-run
    confirm "Publish $crate $version to crates.io?" || fail "stopped before $crate"
    cargo publish --locked -p "$crate"
    printf 'waiting for %s %s on the crates.io index' "$crate" "$version"
    until crate_published "$crate"; do
      printf '.'
      sleep 10
    done
    echo
  done
}

publish_wasm() {
  local package=@0xcurvy/rs-core-wasm tarball="0xcurvy-rs-core-wasm-$version.tgz"
  if npm_published "$package"; then
    echo "$package@$version is already on npm"
    return
  fi
  step "Building the browser modules and the package"
  scripts/build.sh npm
  step "Packing the package, installing it and proving with it"
  scripts/check.sh npm
  [[ -f "$tarball" ]] || fail "no $tarball"
  echo "$tarball: sha256 $(shasum -a 256 "$tarball" | cut -d' ' -f1), dist-tag $dist_tag"
  ((dry_run)) && return
  npm whoami >/dev/null || fail "not logged in to npm (npm login)"
  confirm "Publish $package@$version with dist-tag $dist_tag?" || fail "stopped before publishing"
  # The package's publishConfig asks for provenance, which only a CI publish can provide.
  npm publish "$tarball" --ignore-scripts --access public --tag "$dist_tag" --provenance=false
}

publish_node() {
  local directory package
  step "Building the native packages"
  (cd bindings/node && npm run build:release)
  ((dry_run)) && return
  echo
  echo "The Windows binary was cross-compiled and never loaded; test it on a Windows"
  echo "x64 host first (bindings/node/README.md, Releasing)."
  confirm "Was the Windows binary tested?" || fail "stopped: test the Windows binary first"
  npm whoami >/dev/null || fail "not logged in to npm (npm login)"
  # Platform packages first, so the root package's optional dependencies resolve.
  for directory in bindings/node/release/npm/*/ bindings/node/release/; do
    package="$(node -p "require('./${directory}package.json').name")"
    if npm_published "$package"; then
      echo "$package@$version is already on npm; skipping"
      continue
    fi
    confirm "Publish $package@$version with dist-tag $dist_tag?" || fail "stopped before $package"
    (cd "$directory" && npm publish . --ignore-scripts --access public --tag "$dist_tag" --provenance=false)
  done
}

"publish_$target"
if ((dry_run)); then
  step "Dry run done: nothing was published"
else
  step "Published $target $version"
fi
