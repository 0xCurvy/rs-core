//! Full flow against the live Blokli Curvy image. The stack is required.

#[tokio::test]
async fn m2_shield_commit_aggregate_scan() {
    curvy_e2e::run()
        .await
        .expect("strict Curvy E2E flow failed");
}
