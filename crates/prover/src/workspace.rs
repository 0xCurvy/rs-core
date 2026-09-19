//! Experimental caller-owned buffers; one workspace per active proof.
use ark_bn254::Fr;
use ark_ff::BigInt;
use zeroize::Zeroize;

/// Reusable FFT and MSM scalar-conversion buffers. Never enabled implicitly.
/// The limit bounds idle retained capacity, not memory needed by an active proof.
/// Buffers are zeroized on success, error, panic unwinding, and drop. This does
/// not clear copies inside third-party FFT/MSM implementations or the caller's witness.
pub struct ProofWorkspace {
    pub(crate) a: Vec<Fr>,
    pub(crate) b: Vec<Fr>,
    pub(crate) c: Vec<Fr>,
    pub(crate) h: Vec<BigInt<4>>,
    pub(crate) assignment: Vec<BigInt<4>>,
    limit: usize,
}
impl ProofWorkspace {
    pub fn new(max_retained_bytes: usize) -> Self {
        Self {
            a: Vec::new(),
            b: Vec::new(),
            c: Vec::new(),
            h: Vec::new(),
            assignment: Vec::new(),
            limit: max_retained_bytes,
        }
    }
    pub fn retained_bytes(&self) -> usize {
        (self.a.capacity() + self.b.capacity() + self.c.capacity()) * size_of::<Fr>()
            + (self.h.capacity() + self.assignment.capacity()) * size_of::<BigInt<4>>()
    }
    pub fn clear(&mut self) {
        self.a.zeroize();
        self.b.zeroize();
        self.c.zeroize();
        self.h.zeroize();
        self.assignment.zeroize();
        if self.retained_bytes() > self.limit {
            self.a = Vec::new();
            self.b = Vec::new();
            self.c = Vec::new();
            self.h = Vec::new();
            self.assignment = Vec::new();
        }
    }
}
impl Drop for ProofWorkspace {
    fn drop(&mut self) {
        self.clear();
    }
}
pub(crate) struct Lease<'a>(pub(crate) &'a mut ProofWorkspace);
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
        let mut workspace = ProofWorkspace::new(1024);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let lease = Lease(&mut workspace);
            lease.0.a.push(Fr::from(99));
            lease.0.assignment.push(BigInt::from(99_u64));
            panic!("proof failed");
        }));
        assert!(workspace.a.is_empty() && workspace.assignment.is_empty());
        assert!(workspace.retained_bytes() > 0);
        workspace.limit = 0;
        workspace.clear();
        assert_eq!(workspace.retained_bytes(), 0);
    }
}
