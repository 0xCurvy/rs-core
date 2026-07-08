# curvy-hopr-strategy — Curvy as a HOPR strategy (PoC milestone M5)

This detached workspace proves the **API-level integration** between the Curvy Rust SDK
(the `sdk/` workspace, milestone M2) and hoprnet's strategy framework: a `CurvyStrategy`
that `impl hopr_strategy::Strategy` and drops into hoprnet's real
`hopr_strategy::strategy::MultiStrategy` **with zero changes to hoprnet's crates**.

It maps to plan `plans/hopr-blokli-poc.md` §2, §4 M5, and risks 5–6.

## What's here

```
hopr/                         detached workspace (own [workspace] + rust-toolchain.toml)
├── curvy-hopr-strategy/      the library crate
│   ├── src/lib.rs            impl hopr_strategy::Strategy for CurvyStrategy (+ Display),
│   │                         CurvyStrategyConfig, SettleAction, SettleRecord,
│   │                         HeartbeatStrategy (no-op sibling), FaultySibling (isolation)
│   └── tests/isolation.rs    failure-isolation + composition tests against the REAL
│                             hopr_strategy::MultiStrategy (no live stack needed)
└── curvy-hopr-runner/        standalone runner bin — stands in for the hoprd composition
    └── src/main.rs           site; drives the live demo against poc/blokli-env
```

### The strategy

`CurvyStrategy` owns an `Arc<CurvyClient>` (the M2 SDK). It needs **none** of hopr-api's
node traits (channels/tickets) because it talks to its own chain backend (blokli + direct
RPC) — so its only bounds are `Strategy + Send`, exactly the seam hoprnet's own
`test_multi_strategy_accepts_external_strategy` demonstrates.

Policy v0, on an internal interval timer:
1. `sync()` the mirrored committed-notes tree,
2. `scan()` the chain for owned notes (real ECDH stealth discovery + integrity gate),
3. sum the *spendable* (committed, matching-token, unsettled) balance,
4. when it crosses `threshold_wei`, fire a **real settle** (`SettleAction::Withdraw`)
   submitted through blokli.

Transient tick failures are logged and swallowed (the loop keeps polling); the strategy
returns only when `max_settles` is exhausted — mirroring how every HOPR strategy runs
forever and how `MultiStrategy` isolates sub-strategy failures.

## Toolchain & dependency pins (plan risk 6 — the toolchain quarantine)

| item | value |
|---|---|
| this workspace toolchain | `rust-toolchain.toml` → channel **1.96** (matches hoprnet) |
| this workspace edition | 2021 (our crates + the path-consumed `sdk/` crates) |
| `hopr-strategy` | **0.19.2**, edition 2024, NOT on crates.io → git-pinned |
| git pin | `github.com/hoprnet/hoprnet` rev **`ac365f2b82143fcf69adf043f6c0a38203e61f00`** (2026-07-07) |
| `hopr-api` | 1.14.x (pulled transitively from the same hoprnet tree; also on crates.io) |
| `runtime-tokio` feature | enabled on `hopr-strategy` — required so `MultiStrategy::run`'s sub-task `spawn` maps to `tokio::spawn` (which catches panics → isolation) |

`hopr-strategy` is **not published on crates.io** (verified: `cargo info hopr-strategy` →
not found). We depend on it by git, pinned to a commit. Its workspace-inherited fields
(edition 2024, rust-version 1.91, …) resolve from hoprnet's root manifest during the git
build; there is no `[patch]`/`[replace]` in hoprnet's root, so the git dep is clean.

### The `crates/core` cross-workspace gotcha (one isolated `sdk/` change)

`crates/core` (`curvy-core`) is a **member of the rs-core ROOT workspace**. If this
workspace path-depends on it *directly*, cargo pulls the rs-core root workspace into the
build, and the root workspace then hijacks `workspace = true` inheritance resolution for
the sibling `sdk/` crates (they'd try to inherit `anyhow`/etc. from the root workspace,
which doesn't declare them → `error inheriting anyhow …`). Reaching `curvy-core`
*transitively* does not trigger this. So:

- this workspace declares **no** direct `curvy-core` path-dep; it names core types via
  `curvy_sdk::curvy_core::…`;
- `sdk/curvy-sdk/src/lib.rs` gained a single additive line: `pub use curvy_core;`
  (committed separately as the only `sdk/` change; forward-compatible, no API break).

## Reproduce

All cargo commands run from `hopr/` so the 1.96 `rust-toolchain.toml` applies (it shadows
rs-core's root `rust-toolchain.toml`). If rustup hasn't got 1.96:
`rustup toolchain install 1.96`.

```bash
cd hopr

# 1. Compile the trait impl against the REAL hopr-strategy/hopr-api (exit criterion 1+3).
cargo build -p curvy-hopr-strategy

# 2. Failure-isolation + composition tests — no live stack needed (exit criterion 3).
cargo test -p curvy-hopr-strategy --test isolation -- --nocapture

# 3. Live demo (exit criterion 2). Bring the stack up first (~2–3 min warm):
( cd ../poc/blokli-env && ./run.sh up )
cargo run -p curvy-hopr-runner
# … then tear it down:
( cd ../poc/blokli-env && ./run.sh down )
```

The runner seeds a note to the strategy's account (shield + commit), composes
`MultiStrategy::new(vec![CurvyStrategy, HeartbeatStrategy, FaultySibling::panic])`, runs
it, and prints the settle ledger: the CurvyStrategy loop detecting the seeded balance and
settling a real withdrawal tx **through blokli** (tx hash + DEST balance delta), while the
panicking sibling is isolated.

### Verified run (2026-07-09, fresh `blokli-env` stack)

- `cargo test -p curvy-hopr-strategy --test isolation` — 3/3 pass (panicking sibling
  isolated; erroring sibling isolated both ways; out-of-crate composition).
- Runner: seeded shield 1 ETH → net note 0.849 ETH committed; the panic-sibling fired at
  ~2 s and was logged by `MultiStrategy` as `sub-strategy failed` (isolated); the
  CurvyStrategy 5 s tick then detected
  `spendable_wei=849000000000000000 ≥ threshold 100000000000000000` and settled a
  **real withdrawal via blokli**:
  tx `0x305b7931a58d9d057f0249112a7915aad41d4587aa8c0aa2b5d7f0122996aa1d`
  (RPC cross-check: status 0x1, block 92, to = aggregator). DEST `0x…bEEF` received
  exactly `797302000000000000` wei (delivered = gross − vault withdrawalFee − per-token
  withdrawal gas).

## How this maps to the real in-node hoprd integration (phase 2)

The composition site — where strategies are actually assembled into a `MultiStrategy` and
run inside the node — lives in the **separate `hoprnet/hoprd` repo**, not in
`hoprnet/hoprnet` (the lib layer). This runner *is* that composition site, standing in for
hoprd. Because `MultiStrategy` accepts any `Box<dyn Strategy + Send>` from outside its
crate, the in-node wiring is literally:

```rust
let strategies: Vec<Box<dyn Strategy + Send>> = vec![
    Box::new(AutoRedeeming::new(...)),        // hoprd's existing strategies
    // ...
    Box::new(CurvyStrategy::new(client, ...)),// this crate — drop-in
];
MultiStrategy::new(strategies).run().await?;
```

What the true in-node demo still needs (plan risk 5 / phase 2):
- **hoprd node infra**: a running hoprd with Safe/staking/registry set up against the same
  anvil (a full node, likely a permissioned network-registry entry — possibly HOPR-team
  involvement).
- **Config plumbing**: hoprd builds strategies from YAML/CLI; wiring `CurvyStrategy` there
  needs a config entry + a constructor hook (an out-of-tree strategy has no YAML variant
  today, so it's added at the composition site in code, or hoprd gains a plugin seam).
- **Where the `CurvyClient` comes from**: it must be constructed with the node's chain
  access. In the PoC it's blokli (`TxSubmitter`) + direct RPC; in-node it can share the
  node's `hopr-chain-connector`/blokli client.
- **Strategy depth (plan open-question 1)**: policy v0 is a pure scheduler over
  `CurvyClient`. A PIX exit-side strategy (RFC-0012, §1.4) will additionally need
  session-layer hooks (SURB share verification) — i.e. `hopr-api` node-trait bounds — a
  larger integration than this API-contract proof.
