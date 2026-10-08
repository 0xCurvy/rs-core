use curvy_core::{
    eddsa::{ScalarSigningKey, Signature, ephemeral_pub_key_bytes},
    encoding::try_dec_to_u256,
    field::{Bn254Fr, fr_to_dec},
    witness::{NoteSigner, SeedNoteSigner},
};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

fn key_bytes(input: &js_sys::Uint8Array) -> Result<Zeroizing<[u8; 32]>, JsError> {
    if !input.is_instance_of::<js_sys::Uint8Array>() || input.length() != 32 {
        return Err(JsError::new(
            "key must be a Uint8Array containing exactly 32 bytes",
        ));
    }
    let mut bytes = Zeroizing::new([0_u8; 32]);
    input.copy_to(&mut bytes[..]);
    Ok(bytes)
}

fn signature_values(signature: Signature) -> Vec<String> {
    vec![
        fr_to_dec(&signature.r8.0),
        fr_to_dec(&signature.r8.1),
        signature.s.to_string(),
    ]
}

/// An owned 32-byte seed signer. Call `free()` to erase the owned seed.
#[wasm_bindgen]
pub struct SeedSigner {
    key: Box<SeedNoteSigner>,
}

#[wasm_bindgen]
impl SeedSigner {
    /// Copies a 32-byte seed. The caller retains ownership of the input buffer.
    #[wasm_bindgen(constructor)]
    pub fn new(seed: js_sys::Uint8Array) -> Result<SeedSigner, JsError> {
        let bytes = key_bytes(&seed)?;
        Ok(Self {
            key: Box::new(SeedNoteSigner::from_bytes(*bytes)),
        })
    }

    #[wasm_bindgen(js_name = publicKey)]
    pub fn public_key(&self) -> Vec<String> {
        let (x, y) = self.key.public_key();
        vec![fr_to_dec(&x), fr_to_dec(&y)]
    }

    /// Signs an unsigned decimal message below `2^256`, returning `[R8.x, R8.y, S]`.
    pub fn sign(&self, message: String) -> Result<Vec<String>, JsError> {
        let message = Zeroizing::new(message);
        let message = try_dec_to_u256(&message).map_err(JsError::new)?;
        Ok(signature_values(self.key.sign_raw(&message)))
    }
}

/// An owned scalar signer. Keys are canonical nonzero little-endian scalars.
/// Call `free()` to erase the owned key.
#[wasm_bindgen]
pub struct ScalarSigner {
    key: Box<ScalarSigningKey>,
}

#[wasm_bindgen]
impl ScalarSigner {
    /// Copies a 32-byte scalar. The caller retains ownership of the input buffer.
    #[wasm_bindgen(constructor)]
    pub fn new(scalar: js_sys::Uint8Array) -> Result<ScalarSigner, JsError> {
        let bytes = key_bytes(&scalar)?;
        let key = ScalarSigningKey::from_le_bytes(*bytes)
            .map_err(|error| JsError::new(&error.to_string()))?;
        Ok(Self { key: Box::new(key) })
    }

    #[wasm_bindgen(js_name = publicKey)]
    pub fn public_key(&self) -> Vec<String> {
        let point = self.key.verifying_key();
        vec![fr_to_dec(&point.x()), fr_to_dec(&point.y())]
    }

    /// Signs a canonical decimal BN254 field message, returning `[R8.x, R8.y, S]`.
    pub fn sign(&self, message: String) -> Result<Vec<String>, JsError> {
        let message = Zeroizing::new(message);
        let message =
            Bn254Fr::try_from_dec(&message).map_err(|error| JsError::new(&error.to_string()))?;
        let signature = self
            .key
            .sign_curvy_v1(message)
            .map_err(|error| JsError::new(&error.to_string()))?;
        Ok(signature_values(signature.to_signature()))
    }
}

/// Public key from a raw 32-byte little-endian scalar, including zero.
#[wasm_bindgen(js_name = ephemeralPubKeyBytes)]
pub fn ephemeral_pub_key_bytes_wasm(scalar: js_sys::Uint8Array) -> Result<Vec<String>, JsError> {
    let bytes = key_bytes(&scalar)?;
    let (x, y) = ephemeral_pub_key_bytes(&bytes);
    Ok(vec![fr_to_dec(&x), fr_to_dec(&y)])
}
