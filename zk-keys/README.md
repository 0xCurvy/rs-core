# zk-keys

Curvy v2 proving keys (Groth16 trusted-setup artifacts), stored via **Git LFS** —
run `git lfs pull` to materialize them. Copied from `curvy-monorepo/packages/zk-keys/v2`
so consumers of this repo don't need access to the private monorepo.

Only the three keys the SDK actually loads are vendored (the loader in
`sdk/curvy-witnesscalc` pins each by sha256):

| circuit | file | sha256 |
|---|---|---|
| withdrawal(2,30) | `v2/withdrawal/verifySingleWithdrawalNoHashing_2_30_0001.zkey` | `c91d9fdb…4716` |
| aggregation(2,3,30) | `v2/aggregation/verifySingleAggregationNoHashing_2_3_30_0001.zkey` | `88a85746…a4e6` |
| pending-notes-commitment(5,30) | `v2/pending-notes-commitment/verifyPendingNotesCommitment_5_30_0001.zkey` | `efb4c3d4…7847` |

The matching `*_verification_key.json` files are included alongside each zkey.
`poc/blokli-env/run.sh` discovers this directory automatically; set
`CURVY_ZK_KEYS_DIR` to override with an external checkout.
