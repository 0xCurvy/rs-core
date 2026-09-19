/// # Safety
/// `input` and `output` point to readable/writable 96-byte buffers, respectively.
/// `case` identifies an operation in `curvy_core::leakage::CASES`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_leakage_run(case: u32, input: *const u8, output: *mut u8) {
    let input: &[u8; 96] = unsafe { &*input.cast() };
    let result = curvy_core::leakage::run(case as usize, input);
    unsafe {
        std::ptr::copy_nonoverlapping(result.as_ptr(), output, 96);
    }
}

/// # Safety
/// `input` points to 32 readable bytes containing a canonical big-endian field element.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_leakage_check_poseidon_arities(input: *const u8) {
    curvy_core::leakage::check_poseidon_arities(unsafe { &*input.cast() });
}
use std::sync::OnceLock;

type Declassifier = unsafe extern "C" fn(*mut u8, usize);
static DECLASSIFIER: OnceLock<Declassifier> = OnceLock::new();

type Observer = unsafe extern "C" fn(u32, bool);
static OBSERVER: OnceLock<Observer> = OnceLock::new();

/// # Safety
/// The observer accepts any phase identifier and must not unwind or re-enter the probe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_leakage_set_observer(callback: Observer) {
    OBSERVER.set(callback).expect("observer already configured");
    curvy_core::leakage::set_observer(|phase, start| unsafe {
        OBSERVER.get().unwrap()(phase, start);
    });
}

/// # Safety
/// The callback must preserve byte values and accept any valid mutable slice.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curvy_leakage_set_declassifier(callback: Declassifier) {
    DECLASSIFIER
        .set(callback)
        .expect("declassifier already configured");
    curvy_core::leakage::set_declassifier(|bytes| {
        unsafe { DECLASSIFIER.get().unwrap()(bytes.as_mut_ptr(), bytes.len()) };
    });
}

#[cfg(feature = "wasm")]
#[wasm_bindgen::prelude::wasm_bindgen(js_name = caseNames)]
pub fn case_names() -> Vec<String> {
    curvy_core::leakage::CASES
        .iter()
        .map(|name| (*name).to_owned())
        .collect()
}

#[cfg(feature = "wasm")]
#[wasm_bindgen::prelude::wasm_bindgen(js_name = runCase)]
pub fn run_case(case: u32, input: &[u8]) -> Result<Vec<u8>, wasm_bindgen::JsError> {
    if case as usize >= curvy_core::leakage::CASES.len() || input.len() != 96 {
        return Err(wasm_bindgen::JsError::new(
            "invalid leakage case or input size",
        ));
    }
    Ok(curvy_core::leakage::run(case as usize, input.try_into().unwrap()).to_vec())
}
