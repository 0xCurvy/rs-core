//! `curvy-sdk` (L5) — the thin CurvyClient facade the M2 e2e drives.
//!
//! It assembles the plan's L2 seams (chain-api trait objects) with `curvy-abi`
//! calldata/signing and `curvy-witnesscalc` proving to run, entirely from Rust:
//! **shield → commit → aggregate → scan**. All crypto is `curvy-core`; there is no
//! second implementation, and no direct alloy/blokli/reqwest dependency here — the
//! seam is reached only through the adapter crates.
//!
//! Deliberately out of scope for this slice (plan §4 cuts): planner, relayer +
//! Privacy Pass, portals-recovery, Solana, the events bus, at-rest secret storage.

pub mod account;
pub mod client;
pub mod send;

pub use account::{Account, Identity, OwnedNote};
pub use client::{CurvyClient, Discovered, Route, TxLedger};

/// Re-export of the L0 `curvy-core` crate so consumers can name its `Fr`/field API
/// (the same crate instance whose `Fr` appears in [`OwnedNote`]/[`Discovered`]) without
/// declaring a *direct* path-dependency on `../crates/core`. That direct dep is what a
/// nested consumer workspace must avoid: because `crates/core` is a member of the rs-core
/// root workspace, path-depending it directly pulls the root workspace into the build and
/// makes it hijack `workspace = true` inheritance resolution for the sibling `sdk/`
/// crates. Reaching core transitively (through this re-export) sidesteps that entirely.
pub use curvy_core;
