//! Runs the graph generator against the circuit named by `WITNESS_CPP`.
//!
//! Upstream compiles the circuit into the binary through its build script, so
//! there is no "generate for circuit X" API - each circuit is its own build. That
//! is why this exists as a crate rather than a function call.

fn main() -> eyre::Result<()> {
    curvy_signet_builder::generate::build_witness()
}
