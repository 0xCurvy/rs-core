//! Minimal snarkjs `.wtns` reader: binfile with a header section (n8, prime, count)
//! and a data section of `count` field elements, little-endian standard (non-Montgomery) form.

use ark_bn254::Fr;
use ark_ff::PrimeField;
use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{Cursor, Read, Seek, SeekFrom};

pub fn read_wtns(bytes: &[u8]) -> Vec<Fr> {
    let mut r = Cursor::new(bytes);
    let mut magic = [0u8; 4];
    r.read_exact(&mut magic).expect("wtns magic");
    assert_eq!(&magic, b"wtns", "not a wtns file");
    let _version = r.read_u32::<LittleEndian>().expect("version");
    let n_sections = r.read_u32::<LittleEndian>().expect("nSections");

    let mut n8 = 0usize;
    let mut count = 0usize;
    let mut data_pos = None;

    for _ in 0..n_sections {
        let id = r.read_u32::<LittleEndian>().expect("section id");
        let size = r.read_u64::<LittleEndian>().expect("section size");
        let pos = r.stream_position().expect("pos");
        match id {
            1 => {
                n8 = r.read_u32::<LittleEndian>().expect("n8") as usize;
                let mut prime = vec![0u8; n8];
                r.read_exact(&mut prime).expect("prime");
                count = r.read_u32::<LittleEndian>().expect("count") as usize;
            }
            2 => data_pos = Some(pos),
            _ => {}
        }
        r.seek(SeekFrom::Start(pos + size)).expect("seek");
    }

    let pos = data_pos.expect("wtns: no data section");
    assert!(n8 > 0 && count > 0, "wtns: header section missing");
    r.seek(SeekFrom::Start(pos)).expect("seek data");
    let mut out = Vec::with_capacity(count);
    let mut buf = vec![0u8; n8];
    for _ in 0..count {
        r.read_exact(&mut buf).expect("witness element");
        out.push(Fr::from_le_bytes_mod_order(&buf));
    }
    out
}
