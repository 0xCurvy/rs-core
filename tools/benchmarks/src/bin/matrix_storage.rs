//! Print retained constraint payload for the committed multiplier zkey.
//! Run with and without `--features compact-matrix`.

use curvy_prover::Prover;
use sha2::{Digest, Sha256};

const ZKEY: &[u8] = include_bytes!("../../../../crates/prover/testdata/multiplier.zkey");

fn main() {
    let digest = Sha256::digest(ZKEY)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let prover = Prover::from_zkey_bytes(ZKEY, &digest).expect("fixture zkey must parse");
    println!(
        "representation={}",
        if cfg!(feature = "compact-matrix") {
            "compact-csr"
        } else {
            "arkworks-nested"
        }
    );
    println!("constraints={}", prover.num_constraints());
    println!(
        "retained_matrix_payload_bytes={}",
        prover.matrix_storage_bytes()
    );
}
