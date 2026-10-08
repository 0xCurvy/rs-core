//! A seekable view that only exposes bytes covered by the caller's zkey pin.
//!
//! The first pass authenticates the whole artifact and records chunk hashes.
//! Every later read uses a private, authenticated chunk buffer, including when
//! the parser seeks backwards. Rehashing the file after parsing cannot provide
//! this guarantee: a writer could restore the original bytes before that hash.

use std::io::{self, Read, Seek, SeekFrom};

use sha2::{Digest, Sha256};

use crate::{ProverError, decode_sha256, verify_digest};

const CHUNK_BYTES: usize = 64 * 1024;

pub(crate) struct AuthenticatedReader<'a, R> {
    source: &'a mut R,
    length: u64,
    position: u64,
    hashes: Vec<[u8; 32]>,
    buffer: Vec<u8>,
    cached_chunk: Option<usize>,
}

impl<'a, R: Read + Seek> AuthenticatedReader<'a, R> {
    pub(crate) fn new(source: &'a mut R, expected_sha256: &str) -> Result<Self, ProverError> {
        decode_sha256(expected_sha256)?;
        source.seek(SeekFrom::Start(0))?;
        let mut digest = Sha256::new();
        let mut hashes = Vec::new();
        let mut buffer = vec![0; CHUNK_BYTES];
        let mut length = 0_u64;
        loop {
            let mut filled = 0;
            while filled < buffer.len() {
                match source.read(&mut buffer[filled..]) {
                    Ok(0) => break,
                    Ok(count) => filled += count,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error.into()),
                }
            }
            if filled == 0 {
                break;
            }
            digest.update(&buffer[..filled]);
            hashes.push(Sha256::digest(&buffer[..filled]).into());
            length = length
                .checked_add(filled as u64)
                .ok_or_else(|| io::Error::other("zkey length overflow"))?;
            if filled < CHUNK_BYTES {
                break;
            }
        }
        verify_digest(digest.finalize().into(), expected_sha256)?;
        Ok(Self {
            source,
            length,
            position: 0,
            hashes,
            buffer,
            cached_chunk: None,
        })
    }

    fn cache_chunk(&mut self, index: usize) -> io::Result<()> {
        if self.cached_chunk == Some(index) {
            return Ok(());
        }
        // A failed read must not leave overwritten bytes marked authenticated.
        self.cached_chunk = None;
        let start = index as u64 * CHUNK_BYTES as u64;
        let count = (self.length - start).min(CHUNK_BYTES as u64) as usize;
        self.source.seek(SeekFrom::Start(start))?;
        self.source.read_exact(&mut self.buffer[..count])?;
        let actual: [u8; 32] = Sha256::digest(&self.buffer[..count]).into();
        if actual != self.hashes[index] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("zkey changed after authentication (chunk {index})"),
            ));
        }
        self.cached_chunk = Some(index);
        Ok(())
    }
}

impl<R: Read + Seek> Read for AuthenticatedReader<'_, R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.position >= self.length {
            return Ok(0);
        }
        let index = (self.position / CHUNK_BYTES as u64) as usize;
        self.cache_chunk(index)?;
        let offset = (self.position % CHUNK_BYTES as u64) as usize;
        let count = output
            .len()
            .min(CHUNK_BYTES - offset)
            .min((self.length - self.position).min(CHUNK_BYTES as u64) as usize);
        output[..count].copy_from_slice(&self.buffer[offset..offset + count]);
        self.position += count as u64;
        Ok(count)
    }
}

impl<R: Read + Seek> Seek for AuthenticatedReader<'_, R> {
    fn seek(&mut self, target: SeekFrom) -> io::Result<u64> {
        self.position = match target {
            SeekFrom::Start(position) => Some(position),
            SeekFrom::Current(offset) => self.position.checked_add_signed(offset),
            SeekFrom::End(offset) => self.length.checked_add_signed(offset),
        }
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid zkey seek"))?;
        Ok(self.position)
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, io::Cursor, rc::Rc};

    use super::*;

    fn pin(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    #[test]
    fn seek_and_read_match_an_immutable_snapshot() {
        for length in [0, CHUNK_BYTES, CHUNK_BYTES * 2 + 17] {
            let bytes: Vec<u8> = (0..length).map(|i| (i % 251) as u8).collect();
            let mut source = Cursor::new(&bytes);
            source.set_position(13);
            let mut reader = AuthenticatedReader::new(&mut source, &pin(&bytes)).unwrap();
            let mut decoded = Vec::new();
            reader.read_to_end(&mut decoded).unwrap();
            assert_eq!(decoded, bytes);
            assert!(reader.seek(SeekFrom::Start(0)).is_ok());
            assert!(reader.seek(SeekFrom::Current(-1)).is_err());
            assert_eq!(reader.stream_position().unwrap(), 0);
            if length != 0 {
                reader.seek(SeekFrom::End(-1)).unwrap();
                let mut last = [0];
                reader.read_exact(&mut last).unwrap();
                assert_eq!(last[0], bytes[length - 1]);
                reader.seek(SeekFrom::Start(0)).unwrap();
                let mut first = [0; 7];
                reader.read_exact(&mut first).unwrap();
                assert_eq!(&first, &bytes[..7]);
            }
            reader.seek(SeekFrom::End(10)).unwrap();
            assert_eq!(reader.read(&mut [0; 1]).unwrap(), 0);
        }
    }

    struct SharedReader {
        bytes: Rc<RefCell<Vec<u8>>>,
        position: u64,
    }

    impl Read for SharedReader {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            let bytes = self.bytes.borrow();
            let mut cursor = Cursor::new(bytes.as_slice());
            cursor.set_position(self.position);
            // Exercise short reads during hashing and chunk refills.
            let count = output.len().min(997);
            let count = cursor.read(&mut output[..count])?;
            self.position = cursor.position();
            Ok(count)
        }
    }

    impl Seek for SharedReader {
        fn seek(&mut self, target: SeekFrom) -> io::Result<u64> {
            let bytes = self.bytes.borrow();
            let mut cursor = Cursor::new(bytes.as_slice());
            cursor.set_position(self.position);
            self.position = cursor.seek(target)?;
            Ok(self.position)
        }
    }

    #[test]
    fn changed_chunks_never_escape_even_after_a_failed_refill() {
        let original = vec![7; CHUNK_BYTES * 2 + 17];
        let bytes = Rc::new(RefCell::new(original.clone()));
        let mut source = SharedReader {
            bytes: bytes.clone(),
            position: 0,
        };
        let mut reader = AuthenticatedReader::new(&mut source, &pin(&original)).unwrap();
        reader.read_exact(&mut [0]).unwrap();
        bytes.borrow_mut()[0] = 8;
        reader.seek(SeekFrom::Start(0)).unwrap();
        let mut output = [0];
        reader.read_exact(&mut output).unwrap();
        assert_eq!(output, [7]); // Cached bytes remain the authenticated snapshot.

        bytes.borrow_mut()[CHUNK_BYTES] = 9;
        reader.seek(SeekFrom::Start(CHUNK_BYTES as u64)).unwrap();
        assert_eq!(
            reader.read(&mut output).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(output, [7]);
        reader.seek(SeekFrom::Start(0)).unwrap();
        assert!(reader.read(&mut output).is_err()); // Failed refill invalidated the cache.
        bytes.borrow_mut()[0] = 7;
        reader.read_exact(&mut output).unwrap();
        assert_eq!(output, [7]);

        bytes.borrow_mut().truncate(CHUNK_BYTES);
        reader.seek(SeekFrom::End(-1)).unwrap();
        assert_eq!(
            reader.read(&mut output).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
}
