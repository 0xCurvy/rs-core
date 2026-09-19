use curvy_ffi::*;
use std::{
    ffi::{CStr, CString, c_char},
    ptr,
};

unsafe fn strings(output: *mut c_char) -> Vec<String> {
    let values = serde_json::from_str(unsafe { CStr::from_ptr(output) }.to_str().unwrap()).unwrap();
    unsafe { curvy_string_free(output) };
    values
}

#[test]
fn signer_handles_match_string_apis_and_own_their_imports() {
    let mut seed = [1_u8; 32];
    let mut scalar = [0_u8; 32];
    scalar[0] = 7;
    let mut seed_handle = 0;
    let mut scalar_handle = 0;
    assert_eq!(
        unsafe { curvy_seed_signer_new(seed.as_ptr(), 32, &mut seed_handle) },
        CurvyStatus::Ok
    );
    assert_eq!(
        unsafe { curvy_scalar_signer_new(scalar.as_ptr(), 32, &mut scalar_handle) },
        CurvyStatus::Ok
    );
    assert_ne!(seed_handle, scalar_handle);
    seed.fill(0);
    scalar.fill(0);
    let message = CString::new("42").unwrap();
    let hex = CString::new("01".repeat(32)).unwrap();
    let decimal = CString::new("7").unwrap();
    for _ in 0..2 {
        let mut actual = ptr::null_mut();
        let mut expected = ptr::null_mut();
        assert_eq!(
            unsafe { curvy_seed_signer_sign(seed_handle, message.as_ptr(), &mut actual) },
            CurvyStatus::Ok
        );
        assert_eq!(
            unsafe { curvy_sign(message.as_ptr(), hex.as_ptr(), &mut expected) },
            CurvyStatus::Ok
        );
        assert_eq!(unsafe { strings(actual) }, unsafe { strings(expected) });
        assert_eq!(
            unsafe { curvy_scalar_signer_sign(scalar_handle, message.as_ptr(), &mut actual) },
            CurvyStatus::Ok
        );
        assert_eq!(
            unsafe { curvy_sign_with_scalar(message.as_ptr(), decimal.as_ptr(), &mut expected) },
            CurvyStatus::Ok
        );
        assert_eq!(unsafe { strings(actual) }, unsafe { strings(expected) });
    }
    let mut actual = ptr::null_mut();
    let mut expected = ptr::null_mut();
    assert_eq!(
        unsafe { curvy_seed_signer_public_key(seed_handle, &mut actual) },
        CurvyStatus::Ok
    );
    assert_eq!(
        unsafe { curvy_pub_from_private_key(hex.as_ptr(), &mut expected) },
        CurvyStatus::Ok
    );
    assert_eq!(unsafe { strings(actual) }, unsafe { strings(expected) });
    assert_eq!(
        unsafe { curvy_scalar_signer_public_key(scalar_handle, &mut actual) },
        CurvyStatus::Ok
    );
    assert_eq!(
        unsafe { curvy_pub_from_scalar(decimal.as_ptr(), &mut expected) },
        CurvyStatus::Ok
    );
    assert_eq!(unsafe { strings(actual) }, unsafe { strings(expected) });
    assert_eq!(
        curvy_seed_signer_free(scalar_handle),
        CurvyStatus::InvalidArgument
    );
    assert_eq!(
        curvy_scalar_signer_free(seed_handle),
        CurvyStatus::InvalidArgument
    );
    assert_eq!(curvy_seed_signer_free(seed_handle), CurvyStatus::Ok);
    assert_eq!(curvy_scalar_signer_free(scalar_handle), CurvyStatus::Ok);
    assert_eq!(
        curvy_seed_signer_free(seed_handle),
        CurvyStatus::InvalidArgument
    );
    assert_eq!(
        curvy_scalar_signer_free(scalar_handle),
        CurvyStatus::InvalidArgument
    );
    assert_eq!(
        unsafe { curvy_seed_signer_sign(seed_handle, message.as_ptr(), &mut actual) },
        CurvyStatus::InvalidHandle
    );
    assert_eq!(
        unsafe { curvy_scalar_signer_public_key(scalar_handle, &mut actual) },
        CurvyStatus::InvalidHandle
    );
}

#[test]
fn byte_imports_reject_bad_lengths_nulls_and_noncanonical_scalars() {
    let mut handle = 0;
    for len in [0, 1, 31, 33, usize::MAX] {
        assert_eq!(
            unsafe { curvy_seed_signer_new(ptr::null(), len, &mut handle) },
            CurvyStatus::InvalidArgument
        );
        assert_eq!(
            unsafe { curvy_scalar_signer_new(ptr::null(), len, &mut handle) },
            CurvyStatus::InvalidArgument
        );
    }
    assert_eq!(
        unsafe { curvy_seed_signer_new(ptr::null(), 32, &mut handle) },
        CurvyStatus::InvalidArgument
    );
    let bytes = [1_u8; 32];
    assert_eq!(
        unsafe { curvy_seed_signer_new(bytes.as_ptr(), 32, ptr::null_mut()) },
        CurvyStatus::InvalidArgument
    );
    for scalar in [
        [0_u8; 32],
        [0xff_u8; 32],
        curvy_core::babyjubjub::SUB_ORDER
            .to_bytes_le()
            .try_into()
            .unwrap(),
    ] {
        assert_eq!(
            unsafe { curvy_scalar_signer_new(scalar.as_ptr(), 32, &mut handle) },
            CurvyStatus::InvalidArgument
        );
        assert_eq!(handle, 0);
    }
}

#[test]
fn byte_ephemeral_matches_decimal_for_zero_high_bits_and_maximum() {
    for scalar in [
        [0_u8; 32],
        [0xff; 32],
        std::array::from_fn(|i| if i == 31 { 0x80 } else { 0 }),
    ] {
        let value = curvy_core::encoding::le_bytes_to_biguint(&scalar).to_string();
        let decimal = CString::new(value).unwrap();
        let mut actual = ptr::null_mut();
        let mut expected = ptr::null_mut();
        assert_eq!(
            unsafe { curvy_ephemeral_pub_key_bytes(scalar.as_ptr(), 32, &mut actual) },
            CurvyStatus::Ok
        );
        assert_eq!(
            unsafe { curvy_ephemeral_pub_key(decimal.as_ptr(), &mut expected) },
            CurvyStatus::Ok
        );
        assert_eq!(unsafe { strings(actual) }, unsafe { strings(expected) });
    }
}
