//! Note commitments - the Poseidon derivations for a note's `ownerHash`, `id`, and
//! `nullifier`.
//!
//! Note the deliberate input ordering: `ownerHash` and `nullifier` hash the *same
//! three values* in a *different order*.

use crate::field::Fr;
use crate::poseidon::poseidon;

/// `ownerHash = Poseidon([pub.x, pub.y, sharedSecret])`.
pub fn owner_hash(public_key: (Fr, Fr), shared_secret: Fr) -> Fr {
    poseidon(&[public_key.0, public_key.1, shared_secret])
}

/// `id = Poseidon([ownerHash, amount, token])`.
pub fn note_id(owner_hash: Fr, amount: Fr, token: Fr) -> Fr {
    poseidon(&[owner_hash, amount, token])
}

/// `nullifier = Poseidon([sharedSecret, pub.x, pub.y])`.
pub fn nullifier(shared_secret: Fr, public_key: (Fr, Fr)) -> Fr {
    poseidon(&[shared_secret, public_key.0, public_key.1])
}
