//! Shared artifact input boundaries for resident and streaming provers.
#[cfg(feature = "zkey-manifest")]
pub mod manifest;

use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    path::Path,
};

/// A seekable artifact source whose byte range is capped even if it grows.
/// Checks the reported length before reading; reads probe at most one byte
/// past the limit and return an error instead of silently truncating the file.
/// This is a resource bound, not authentication.
pub struct BoundedReader<R> {
    inner: R,
    limit: u64,
    position: u64,
}
impl<R: Read + Seek> BoundedReader<R> {
    pub fn new(mut inner: R, limit: u64) -> io::Result<Self> {
        if inner.seek(SeekFrom::End(0))? > limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "artifact exceeds byte limit",
            ));
        }
        inner.seek(SeekFrom::Start(0))?;
        Ok(Self {
            inner,
            limit,
            position: 0,
        })
    }
}
impl<R: Read> Read for BoundedReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let remaining = self.limit - self.position;
        let wanted = (output.len() as u64).min(remaining.saturating_add(1)) as usize;
        let count = self.inner.read(&mut output[..wanted])?;
        if count as u64 > remaining {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "artifact exceeds byte limit",
            ));
        }
        self.position += count as u64;
        Ok(count)
    }
}
impl<R: Seek> Seek for BoundedReader<R> {
    fn seek(&mut self, target: SeekFrom) -> io::Result<u64> {
        let position = match target {
            SeekFrom::Start(position) => Some(position),
            SeekFrom::Current(offset) => self.position.checked_add_signed(offset),
            SeekFrom::End(offset) => {
                let length = self.inner.seek(SeekFrom::End(0))?;
                // Restore our logical position even on a failed seek.
                self.inner.seek(SeekFrom::Start(self.position))?;
                if length > self.limit {
                    None
                } else {
                    length.checked_add_signed(offset)
                }
            }
        }
        .filter(|position| *position <= self.limit)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek exceeds artifact byte limit",
            )
        })?;
        self.inner.seek(SeekFrom::Start(position))?;
        self.position = position;
        Ok(position)
    }
}

/// Read at most `max_bytes` into owned memory. A single extra byte detects
/// excess input; metadata alone cannot enforce a bound on a growing file.
/// Allocation is fallible; requested capacity never exceeds the byte limit.
pub fn read_bounded<R: Read>(reader: &mut R, max_bytes: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 64 * 1024];
    loop {
        let remaining = max_bytes - bytes.len();
        let wanted = remaining.saturating_add(1).min(chunk.len());
        let count = match reader.read(&mut chunk[..wanted]) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if count == 0 {
            return Ok(bytes);
        }
        if count > remaining {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("artifact exceeds {max_bytes} byte limit"),
            ));
        }
        if bytes.len() + count > bytes.capacity() {
            let capacity = bytes
                .capacity()
                .saturating_mul(2)
                .max(chunk.len())
                .min(max_bytes)
                .max(bytes.len() + count);
            bytes
                .try_reserve_exact(capacity - bytes.len())
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::OutOfMemory,
                        "cannot allocate artifact buffer",
                    )
                })?;
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
}

/// Own the bytes which will be authenticated and parsed. Replacing or changing
/// the source file later cannot change this snapshot. Limits also apply when a
/// file grows after its metadata was read or when metadata has no useful size.
pub fn read_file_bounded(path: impl AsRef<Path>, max_bytes: usize) -> io::Result<Vec<u8>> {
    let mut source = File::open(path)?;
    if source.metadata()?.len() > max_bytes as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("artifact exceeds {max_bytes} byte limit"),
        ));
    }
    read_bounded(&mut source, max_bytes)
}

/// Apply the compressed or raw graph bound before reading the whole artifact.
/// Preserve the inspected prefix from this same descriptor in the snapshot.
pub fn read_graph_file_bounded(
    path: impl AsRef<Path>,
    limits: curvy_witness::Limits,
) -> io::Result<Vec<u8>> {
    let mut source = File::open(path)?;
    let mut prefix = Vec::with_capacity(4);
    source.by_ref().take(4).read_to_end(&mut prefix)?;
    let limit = if prefix == [0x28, 0xb5, 0x2f, 0xfd] {
        limits.compressed_graph_bytes
    } else {
        limits.graph_bytes
    };
    if source.metadata()?.len() > limit as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("artifact exceeds {limit} byte limit"),
        ));
    }
    read_bounded(&mut prefix.as_slice().chain(source), limit)
}

#[cfg(test)]
mod tests {
    #[test]
    fn seekable_limit_rejects_oversize_and_growth() {
        use super::BoundedReader;
        use std::io::{Cursor, Read, Seek, SeekFrom};
        assert!(BoundedReader::new(Cursor::new(vec![0; 9]), 8).is_err());
        let mut reader = BoundedReader::new(Cursor::new(vec![1]), 8).unwrap();
        reader.inner.get_mut().resize(9, 2);
        assert!(reader.seek(SeekFrom::End(0)).is_err());
        assert!(reader.seek(SeekFrom::Start(9)).is_err());
        assert!(reader.read_to_end(&mut Vec::new()).is_err());
        let mut reader = BoundedReader::new(Cursor::new(vec![1; 8]), 8).unwrap();
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, vec![1; 8]);
    }

    use super::*;
    #[test]
    fn exact_limit_empty_and_growing_streams_are_bounded() {
        assert_eq!(read_bounded(&mut &b"abc"[..], 3).unwrap(), b"abc");
        assert!(read_bounded(&mut &b""[..], 0).unwrap().is_empty());
        assert!(read_bounded(&mut &b"x"[..], 0).is_err());
        let mut never_ends = io::repeat(1);
        assert_eq!(
            read_bounded(&mut never_ends, 3).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        let mut input = &b"abcdef"[..];
        assert!(read_bounded(&mut input, 3).is_err());
        assert_eq!(input, b"ef"); // Consumes only limit + 1, regardless of source length.
    }
}
