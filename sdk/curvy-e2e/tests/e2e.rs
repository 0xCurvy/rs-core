//! Integration test: the full M2 flow against the live stack. Skips cleanly (passes
//! with a printed notice) when the stack is not up, so `cargo test` never fails just
//! because `poc/blokli-env/run.sh up` has not been run. Bring the stack up to exercise it.

#[tokio::test]
async fn m2_shield_commit_aggregate_scan() {
    if !curvy_e2e::stack_ready().await {
        eprintln!(
            "SKIP: blokli-env stack not ready — run `poc/blokli-env/run.sh up` first \
             (or set BLOKLI_URL/RPC_URL). This test skips rather than fails."
        );
        return;
    }
    let all_passed = curvy_e2e::run().await.expect("e2e flow errored");
    assert!(all_passed, "one or more M2 e2e steps failed");
}
