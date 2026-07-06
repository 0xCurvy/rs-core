//! arkworks Groth16 prover over snarkjs artifacts (`.zkey` + `.wtns`). Proof output
//! is serialized in snarkjs JSON form, so snarkjs — and therefore the on-chain
//! verifier's exact pairing check — accepts it. Builds native (rayon-parallel) and
//! wasm32 from one source.
//!
//! Integrity contract: the `.zkey` is parsed **without** re-validating every point
//! on-curve (that dominates parse time and is redundant for a fixed, trusted
//! proving key). A verifying-key anchor spot-check catches gross corruption, but
//! the caller is responsible for the artifact's authenticity — pin/verify the
//! `.zkey` by content hash before loading it.

pub mod qap;
pub mod wtns;
pub mod zkey;

use ark_bn254::{Bn254, Fq, Fq2, Fr};
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_groth16::{prepare_verifying_key, Groth16, PreparedVerifyingKey, Proof, ProvingKey};
use ark_relations::r1cs::ConstraintMatrices;
use num_bigint::BigUint;

use qap::CircomReduction;

pub struct Prover {
    pk: ProvingKey<Bn254>,
    matrices: ConstraintMatrices<Fr>,
    pvk: PreparedVerifyingKey<Bn254>,
}

impl Prover {
    pub fn from_zkey_bytes(bytes: &[u8]) -> Self {
        let mut cur = std::io::Cursor::new(bytes);
        let (pk, matrices) = zkey::read_zkey(&mut cur).expect("failed to parse zkey");
        let pvk = prepare_verifying_key(&pk.vk);
        Self { pk, matrices, pvk }
    }

    pub fn num_constraints(&self) -> usize {
        self.matrices.num_constraints
    }
    pub fn num_public(&self) -> usize {
        self.matrices.num_instance_variables - 1
    }

    pub fn prove(&self, full_assignment: &[Fr]) -> Proof<Bn254> {
        let mut rng = rand::rngs::OsRng;
        let r = Fr::rand(&mut rng);
        let s = Fr::rand(&mut rng);
        Groth16::<Bn254, CircomReduction>::create_proof_with_reduction_and_matrices(
            &self.pk,
            r,
            s,
            &self.matrices,
            self.matrices.num_instance_variables,
            self.matrices.num_constraints,
            full_assignment,
        )
        .expect("proof generation failed")
    }

    pub fn public_inputs<'a>(&self, full_assignment: &'a [Fr]) -> &'a [Fr] {
        &full_assignment[1..self.matrices.num_instance_variables]
    }

    pub fn verify(&self, proof: &Proof<Bn254>, public_inputs: &[Fr]) -> bool {
        Groth16::<Bn254>::verify_proof(&self.pvk, proof, public_inputs).expect("verify failed")
    }
}

fn fq_dec(x: &Fq) -> String {
    BigUint::from_bytes_be(&x.into_bigint().to_bytes_be()).to_str_radix(10)
}
fn fr_dec(x: &Fr) -> String {
    BigUint::from_bytes_be(&x.into_bigint().to_bytes_be()).to_str_radix(10)
}
fn fq2_json(x: &Fq2) -> String {
    format!("[\"{}\", \"{}\"]", fq_dec(&x.c0), fq_dec(&x.c1))
}

/// snarkjs proof JSON: `{pi_a: [x,y,1], pi_b: [[xc0,xc1],[yc0,yc1],[1,0]], pi_c, protocol, curve}`.
pub fn proof_to_snarkjs_json(proof: &Proof<Bn254>) -> String {
    format!(
        "{{\"pi_a\": [\"{}\", \"{}\", \"1\"], \"pi_b\": [{}, {}, [\"1\", \"0\"]], \"pi_c\": [\"{}\", \"{}\", \"1\"], \"protocol\": \"groth16\", \"curve\": \"bn128\"}}",
        fq_dec(&proof.a.x),
        fq_dec(&proof.a.y),
        fq2_json(&proof.b.x),
        fq2_json(&proof.b.y),
        fq_dec(&proof.c.x),
        fq_dec(&proof.c.y),
    )
}

pub fn publics_to_json(publics: &[Fr]) -> String {
    let items: Vec<String> = publics.iter().map(|p| format!("\"{}\"", fr_dec(p))).collect();
    format!("[{}]", items.join(", "))
}

#[cfg(feature = "wasm-threads")]
pub use wasm_bindgen_rayon::init_thread_pool;

#[cfg(feature = "wasm")]
mod wasm_api {
    use wasm_bindgen::prelude::*;

    /// Holds the parsed zkey across calls — the "parse once, prove many" shape
    /// a real prover would use (snarkjs re-parses per fullProve).
    #[wasm_bindgen]
    pub struct WasmProver(crate::Prover);

    #[wasm_bindgen]
    impl WasmProver {
        #[wasm_bindgen(constructor)]
        pub fn new(zkey: &[u8]) -> WasmProver {
            WasmProver(crate::Prover::from_zkey_bytes(zkey))
        }

        #[wasm_bindgen(js_name = numConstraints)]
        pub fn num_constraints(&self) -> usize {
            self.0.num_constraints()
        }

        /// Returns `{"proof": <snarkjs proof>, "publicSignals": [...]}` as JSON.
        pub fn prove(&self, wtns: &[u8]) -> String {
            let assignment = crate::wtns::read_wtns(wtns);
            let proof = self.0.prove(&assignment);
            let publics = self.0.public_inputs(&assignment);
            assert!(self.0.verify(&proof, publics), "self-verify failed");
            format!(
                "{{\"proof\": {}, \"publicSignals\": {}}}",
                crate::proof_to_snarkjs_json(&proof),
                crate::publics_to_json(publics)
            )
        }

        /// Prove without the self-verify (pure prover timing).
        #[wasm_bindgen(js_name = proveOnly)]
        pub fn prove_only(&self, wtns: &[u8]) -> String {
            let assignment = crate::wtns::read_wtns(wtns);
            let proof = self.0.prove(&assignment);
            crate::proof_to_snarkjs_json(&proof)
        }
    }
}
