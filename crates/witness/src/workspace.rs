//! Bounded evaluation buffers, exclusively borrowed during one calculation.
use ark_bn254::Fr;
use zeroize::Zeroize;

/// Optional retained witness buffers. The limit bounds idle capacity, not peak
/// calculation memory. Retained storage is zeroized even if evaluation or the
/// consumer fails or panics. Caller-owned inputs and copies are not cleared.
pub struct WitnessWorkspace {
    pub(crate) values: Vec<Fr>,
    pub(crate) assignment: Vec<Fr>,
    limit: usize,
}
impl WitnessWorkspace {
    pub fn new(max_retained_bytes: usize) -> Self {
        Self {
            values: Vec::new(),
            assignment: Vec::new(),
            limit: max_retained_bytes,
        }
    }
    pub fn retained_bytes(&self) -> usize {
        (self.values.capacity() + self.assignment.capacity()) * size_of::<Fr>()
    }
    pub fn clear(&mut self) {
        self.values.zeroize();
        self.assignment.zeroize();
        if self.retained_bytes() > self.limit {
            self.values = Vec::new();
            self.assignment = Vec::new();
        }
    }
}
impl Drop for WitnessWorkspace {
    fn drop(&mut self) {
        self.clear();
    }
}
pub(crate) struct Lease<'a>(pub(crate) &'a mut WitnessWorkspace);
impl Drop for Lease<'_> {
    fn drop(&mut self) {
        self.0.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lease_clears_on_unwind_and_enforces_retention_limit() {
        let mut workspace = WitnessWorkspace::new(1024);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let lease = Lease(&mut workspace);
            lease.0.values.push(Fr::from(99));
            panic!("consumer failed");
        }));
        assert!(workspace.values.is_empty());
        assert!(workspace.retained_bytes() > 0);
        workspace.limit = 0;
        workspace.clear();
        assert_eq!(workspace.retained_bytes(), 0);
    }
}
