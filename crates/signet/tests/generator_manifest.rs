//! Manifest integrity for the out-of-workspace generator.
//!
//! `generator/` is deliberately its own workspace, so no ordinary `cargo build`,
//! `cargo test` or `cargo clippy` in rs-core ever reads its manifest. That is the
//! right call -- its dependency's build script shells out to `circom` and a C++
//! toolchain, so as a member it would break every workspace command -- but it
//! means a broken manifest there is invisible until someone builds a production
//! artifact.
//!
//! These tests are the cheap half of that gate: they need no toolchain and run
//! with the normal suite. `scripts/smoke-generator.sh` is the other half and
//! actually compiles the thing.

use std::path::PathBuf;
use std::process::Command;

fn generator_manifest() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("generator")
        .join("Cargo.toml")
}

fn cargo_metadata() -> std::process::Output {
    Command::new(env!("CARGO"))
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .arg("--manifest-path")
        .arg(generator_manifest())
        .output()
        .expect("cargo metadata must run")
}

/// Every crate `generator/src/main.rs` names must be a *direct* dependency;
/// a transitive one is present in the lockfile but is not nameable.
///
/// This is the check that catches a dependency written into the wrong table.
/// `eyre` sat under `[profile.release]` exactly that way: Cargo parsed the
/// manifest, silently ignored the key, and the build reached the C++ toolchain
/// before anything noticed. Asserting on Cargo's own `unused manifest key`
/// warning does *not* work here -- that warning is cached, so it stays silent on
/// a repeat run and the test passes with the bug present. Asserting the
/// dependency edge itself is the reliable form.
#[test]
fn generator_declares_every_crate_its_source_names() {
    let output = cargo_metadata();
    assert!(output.status.success(), "cargo metadata failed");
    let metadata = String::from_utf8_lossy(&output.stdout);

    let source = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("generator")
            .join("src")
            .join("main.rs"),
    )
    .expect("generator main.rs must be readable");

    for crate_name in ["eyre", "curvy_signet_builder"] {
        if !source.contains(crate_name) {
            continue;
        }
        // cargo metadata reports package names, which use hyphens.
        let package = crate_name.replace('_', "-");
        assert!(
            metadata.contains(&format!("\"name\":\"{package}\"")),
            "main.rs names `{crate_name}` but `{package}` is not a direct \
             dependency of signet-generator",
        );
    }
}
