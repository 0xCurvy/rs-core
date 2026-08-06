//! Minimal snarkjs `.wtns` reader, for parity checking only.
//!
//! An exported artifact is only trustworthy if it evaluates to the same
//! assignment the circuit's own toolchain produces. `signet validate` reads that
//! reference witness here and compares field by field - a checksum would hide a
//! single wrong signal, which is exactly the failure this is meant to catch.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};

use crate::SignetError;

/// Read the full assignment out of a snarkjs witness file.
pub fn read(bytes: &[u8]) -> Result<Vec<Fr>, SignetError> {
    let mut reader = Reader::new(bytes);
    if reader.array::<4>()? != *b"wtns" {
        return Err(SignetError::InvalidWtns("not a wtns file"));
    }
    if reader.u32()? != 2 {
        return Err(SignetError::InvalidWtns("unsupported wtns version"));
    }

    let sections = reader.u32()?;
    let mut declared = None;
    let mut data = None;
    for _ in 0..sections {
        let id = reader.u32()?;
        let size = usize::try_from(reader.u64()?)
            .map_err(|_| SignetError::InvalidWtns("section size out of range"))?;
        let start = reader.position;
        match id {
            1 => {
                if reader.u32()? != 32 {
                    return Err(SignetError::InvalidWtns("unexpected field width"));
                }
                reader.array::<32>()?;
                declared = Some(reader.u32()? as usize);
            }
            2 => data = Some((start, size)),
            _ => {}
        }
        reader.position = start
            .checked_add(size)
            .ok_or(SignetError::InvalidWtns("section overruns the file"))?;
    }

    let declared = declared.ok_or(SignetError::InvalidWtns("missing header section"))?;
    let (start, size) = data.ok_or(SignetError::InvalidWtns("missing data section"))?;
    if size != declared * 32 {
        return Err(SignetError::InvalidWtns(
            "data size disagrees with the header",
        ));
    }

    let mut assignment = Vec::with_capacity(declared);
    for index in 0..declared {
        let offset = start + index * 32;
        let encoded: [u8; 32] = bytes
            .get(offset..offset + 32)
            .ok_or(SignetError::InvalidWtns("truncated witness data"))?
            .try_into()
            .map_err(|_| SignetError::InvalidWtns("truncated witness data"))?;
        assignment.push(Fr::from_le_bytes_mod_order(&encoded));
    }
    Ok(assignment)
}

/// Where two assignments first disagree, if they do.
pub fn first_difference(left: &[Fr], right: &[Fr]) -> Option<usize> {
    if left.len() != right.len() {
        return Some(left.len().min(right.len()));
    }
    left.iter().zip(right).position(|(a, b)| a != b)
}

/// Render one field element the way snarkjs prints it, for a mismatch report.
pub fn decimal(value: Fr) -> String {
    num_bigint::BigUint::from_bytes_le(&value.into_bigint().to_bytes_le()).to_str_radix(10)
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], SignetError> {
        let end = self
            .position
            .checked_add(N)
            .ok_or(SignetError::InvalidWtns("offset overflow"))?;
        let value: [u8; N] = self
            .bytes
            .get(self.position..end)
            .ok_or(SignetError::InvalidWtns("truncated file"))?
            .try_into()
            .map_err(|_| SignetError::InvalidWtns("truncated file"))?;
        self.position = end;
        Ok(value)
    }

    fn u32(&mut self) -> Result<u32, SignetError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, SignetError> {
        Ok(u64::from_le_bytes(self.array()?))
    }
}
