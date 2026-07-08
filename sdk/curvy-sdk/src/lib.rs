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
