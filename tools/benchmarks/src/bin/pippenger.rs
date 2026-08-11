//! Measure the one-pass, file-backed Pippenger MSM used by SPARROW.
//!
//! Unlike `ChunkedPippenger`, this retains the window buckets across input
//! chunks. Every zkey base is decoded once, while memory is bounded by the
//! assignment, one input chunk, and `windows * (2^window_bits - 1)` buckets.

use std::{
    env,
    fs::File,
    io::{self, BufReader, Read, Seek, SeekFrom},
    mem::size_of,
    sync::mpsc::sync_channel,
    thread,
    time::Instant,
};

use ark_bn254::{Fq, Fr, G1Affine, G1Projective};
use ark_ec::{AdditiveGroup, AffineRepr, CurveGroup};
use ark_ff::{BigInt, BigInteger, PrimeField, Zero};
use rayon::prelude::*;
use sha2::{Digest, Sha256};

fn read_u32<R: Read>(reader: &mut R) -> io::Result<u32> {
    let mut bytes = [0_u8; 4];
    reader.read_exact(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64<R: Read>(reader: &mut R) -> io::Result<u64> {
    let mut bytes = [0_u8; 8];
    reader.read_exact(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

fn limbs(bytes: &[u8]) -> BigInt<4> {
    let mut words = [0_u64; 4];
    for (word, chunk) in words.iter_mut().zip(bytes.chunks_exact(8)) {
        *word = u64::from_le_bytes(chunk.try_into().expect("eight-byte chunk"));
    }
    BigInt(words)
}

fn decode_g1(bytes: &[u8]) -> G1Affine {
    let x = Fq::new_unchecked(limbs(&bytes[..32]));
    let y = Fq::new_unchecked(limbs(&bytes[32..]));
    if x.is_zero() && y.is_zero() {
        G1Affine::identity()
    } else {
        G1Affine::new_unchecked(x, y)
    }
}

fn read_assignment(path: &str) -> Result<Vec<Fr>, Box<dyn std::error::Error>> {
    let mut file = File::open(path)?;
    let mut magic = [0_u8; 4];
    file.read_exact(&mut magic)?;
    if &magic != b"wtns" || read_u32(&mut file)? != 2 {
        return Err("unsupported wtns".into());
    }
    let section_count = read_u32(&mut file)?;
    let mut field_bytes = None;
    let mut witness_count = None;
    let mut data = None;
    for _ in 0..section_count {
        let id = read_u32(&mut file)?;
        let size = read_u64(&mut file)?;
        let offset = file.stream_position()?;
        match id {
            1 => {
                let width = read_u32(&mut file)? as usize;
                if width != 32 {
                    return Err("unexpected witness field width".into());
                }
                file.seek(SeekFrom::Current(width as i64))?;
                field_bytes = Some(width);
                witness_count = Some(read_u32(&mut file)? as usize);
            }
            2 => data = Some((offset, size)),
            _ => {}
        }
        file.seek(SeekFrom::Start(offset + size))?;
    }
    let width = field_bytes.ok_or("missing witness header")?;
    let count = witness_count.ok_or("missing witness count")?;
    let (offset, size) = data.ok_or("missing witness data")?;
    if size as usize != count * width {
        return Err("unexpected witness data size".into());
    }
    file.seek(SeekFrom::Start(offset))?;
    let mut file = BufReader::with_capacity(1024 * 1024, file);
    let mut assignment = Vec::with_capacity(count);
    let mut encoded = [0_u8; 32];
    for _ in 0..count {
        file.read_exact(&mut encoded)?;
        assignment.push(Fr::from_bigint(limbs(&encoded)).ok_or("non-canonical witness field")?);
    }
    Ok(assignment)
}

fn query_section(file: &mut File, wanted: u32) -> Result<(u64, usize), Box<dyn std::error::Error>> {
    let mut magic = [0_u8; 4];
    file.read_exact(&mut magic)?;
    if &magic != b"zkey" || read_u32(file)? != 1 {
        return Err("unsupported zkey".into());
    }
    let section_count = read_u32(file)?;
    let mut found = None;
    for _ in 0..section_count {
        let id = read_u32(file)?;
        let size = read_u64(file)?;
        let offset = file.stream_position()?;
        if id == wanted {
            found = Some((offset, usize::try_from(size)?));
        }
        file.seek(SeekFrom::Start(offset + size))?;
    }
    found.ok_or_else(|| "query section missing".into())
}

fn scalar_window(scalar: &BigInt<4>, start_bit: usize, width: usize) -> usize {
    let limbs = scalar.as_ref();
    let limb = start_bit / 64;
    let shift = start_bit % 64;
    let mut value = limbs.get(limb).copied().unwrap_or(0) >> shift;
    if shift != 0 && shift + width > 64 {
        value |= limbs.get(limb + 1).copied().unwrap_or(0) << (64 - shift);
    }
    (value & ((1_u64 << width) - 1)) as usize
}

fn decode_pairs(bytes: &[u8], scalars: &[Fr]) -> Vec<(G1Affine, BigInt<4>)> {
    bytes
        .chunks_exact(64)
        .map(decode_g1)
        .zip(scalars)
        .filter(|(base, scalar)| !base.is_zero() && !scalar.is_zero())
        .map(|(base, scalar)| (base, scalar.into_bigint()))
        .collect()
}

fn accumulate_pairs(
    buckets: &mut [Vec<G1Projective>],
    pairs: &[(G1Affine, BigInt<4>)],
    window_bits: usize,
) {
    buckets
        .par_iter_mut()
        .enumerate()
        .for_each(|(window, window_buckets)| {
            let start_bit = window * window_bits;
            for (base, scalar) in pairs {
                let digit = scalar_window(scalar, start_bit, window_bits);
                if digit != 0 {
                    window_buckets[digit - 1] += base;
                }
            }
        });
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().collect::<Vec<_>>();
    if !(6..=7).contains(&args.len()) {
        return Err("usage: pippenger <zkey> <wtns> <chunk-points> <window-bits> <threads> [sequential|pipeline]".into());
    }
    let chunk_points = args[3].parse::<usize>()?;
    let window_bits = args[4].parse::<usize>()?;
    let threads = args[5].parse::<usize>()?;
    let mode = args.get(6).map(String::as_str).unwrap_or("sequential");
    if chunk_points == 0 || !(4..=16).contains(&window_bits) || threads == 0 {
        return Err(
            "chunk-points and threads must be positive; window-bits must be in 4..=16".into(),
        );
    }
    if !matches!(mode, "sequential" | "pipeline") {
        return Err("mode must be sequential or pipeline".into());
    }
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()?;

    let load_started = Instant::now();
    let assignment = read_assignment(&args[2])?;
    let assignment_ms = load_started.elapsed().as_secs_f64() * 1_000.0;
    let mut zkey = File::open(&args[1])?;
    let (offset, size) = query_section(&mut zkey, 5)?;
    if size != assignment.len() * 64 {
        return Err("A-query and witness sizes differ".into());
    }
    zkey.seek(SeekFrom::Start(offset))?;
    let mut first = [0_u8; 64];
    zkey.read_exact(&mut first)?;
    let first = decode_g1(&first);

    let scalar_bits = Fr::MODULUS_BIT_SIZE as usize;
    let window_count = scalar_bits.div_ceil(window_bits);
    let bucket_count = (1_usize << window_bits) - 1;
    let mut buckets = (0..window_count)
        .map(|_| vec![G1Projective::zero(); bucket_count])
        .collect::<Vec<_>>();
    let mut included_pairs = 0_usize;

    let started = Instant::now();
    if mode == "sequential" {
        let mut raw = vec![0_u8; chunk_points * 64];
        let mut scalar_index = 1_usize;
        while scalar_index < assignment.len() {
            let count = chunk_points.min(assignment.len() - scalar_index);
            let bytes = &mut raw[..count * 64];
            zkey.read_exact(bytes)?;
            let pairs = decode_pairs(bytes, &assignment[scalar_index..scalar_index + count]);
            included_pairs += pairs.len();
            accumulate_pairs(&mut buckets, &pairs, window_bits);
            scalar_index += count;
        }
    } else {
        let (sender, receiver) = sync_channel::<Vec<(G1Affine, BigInt<4>)>>(1);
        let producer = thread::scope(|scope| {
            let assignment = &assignment;
            let handle = scope.spawn(move || -> io::Result<usize> {
                let mut raw = vec![0_u8; chunk_points * 64];
                let mut scalar_index = 1_usize;
                let mut produced_pairs = 0_usize;
                while scalar_index < assignment.len() {
                    let count = chunk_points.min(assignment.len() - scalar_index);
                    let bytes = &mut raw[..count * 64];
                    zkey.read_exact(bytes)?;
                    let pairs =
                        decode_pairs(bytes, &assignment[scalar_index..scalar_index + count]);
                    produced_pairs += pairs.len();
                    if sender.send(pairs).is_err() {
                        return Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "MSM consumer stopped",
                        ));
                    }
                    scalar_index += count;
                }
                Ok(produced_pairs)
            });
            for pairs in receiver {
                accumulate_pairs(&mut buckets, &pairs, window_bits);
            }
            handle.join().expect("zkey reader thread panicked")
        });
        included_pairs = producer?;
    }

    let window_sums = buckets
        .into_par_iter()
        .map(|window_buckets| {
            let mut running = G1Projective::zero();
            let mut sum = G1Projective::zero();
            for bucket in window_buckets.into_iter().rev() {
                running += bucket;
                sum += running;
            }
            sum
        })
        .collect::<Vec<_>>();

    let mut accumulator = G1Projective::zero();
    for window_sum in window_sums.into_iter().rev() {
        for _ in 0..window_bits {
            accumulator.double_in_place();
        }
        accumulator += window_sum;
    }
    accumulator += first;
    let elapsed_ms = started.elapsed().as_secs_f64() * 1_000.0;

    let affine = accumulator.into_affine();
    let mut digest = Sha256::new();
    digest.update(affine.x.into_bigint().to_bytes_le());
    digest.update(affine.y.into_bigint().to_bytes_le());
    println!("assignment_fields={}", assignment.len());
    println!("assignment_load_ms={assignment_ms:.3}");
    println!("chunk_points={chunk_points}");
    println!("window_bits={window_bits}");
    println!("window_count={window_count}");
    println!("bucket_count_per_window={bucket_count}");
    println!("threads={threads}");
    println!("mode={mode}");
    println!(
        "assignment_storage_bytes={}",
        assignment.len() * size_of::<Fr>()
    );
    println!(
        "bucket_storage_bytes={}",
        window_count * bucket_count * size_of::<G1Projective>()
    );
    println!("raw_chunk_capacity_bytes={}", chunk_points * 64);
    println!(
        "decoded_chunk_capacity_bytes_estimate={}",
        chunk_points
            * (size_of::<G1Affine>() + size_of::<BigInt<4>>())
            * if mode == "pipeline" { 2 } else { 1 }
    );
    println!("included_pairs={included_pairs}");
    println!("a_query_msm_ms={elapsed_ms:.3}");
    let digest = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    println!("result_sha256={digest}");
    Ok(())
}
