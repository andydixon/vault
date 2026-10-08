// SPDX-License-Identifier: GPL-3.0-or-later

//! The STREAM payload encryption of the Go `internal/stream` package.
//!
//! The plaintext is cut into 64 KiB chunks, each sealed with
//! ChaCha20-Poly1305 under a 12-byte nonce whose bytes 3..11 hold the
//! big-endian chunk index and whose last byte is 1 for the final chunk
//! only. Only the final chunk may be short; it may be empty only when it is
//! the sole chunk (an empty plaintext). A reader rejects truncation (no
//! final-flagged chunk), an empty non-first final chunk, and any byte after
//! the final chunk.
//!
//! Chunk nonces depend only on the index, so chunks may be sealed or opened
//! in any order and produce identical bytes; the readers here classify each
//! chunk as final or not from the shape of the stream (one chunk of
//! read-ahead) and open it exactly once, which is the same verdict Go's
//! sequential try-then-retry reader reaches.

use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use std::io::{self, Read, Write};
use zeroize::Zeroize;

pub const CHUNK_SIZE: usize = 64 * 1024;
pub const TAG_SIZE: usize = 16;
pub const ENC_CHUNK_SIZE: usize = CHUNK_SIZE + TAG_SIZE;
const LAST_CHUNK_FLAG: u8 = 0x01;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamError {
    /// The stream ended before a final chunk.
    Truncated,
    /// A chunk failed to authenticate.
    Auth,
    EmptyLastChunk,
    TrailingData,
    CounterOverflow,
    /// The ciphertext length cannot be a STREAM encoding.
    InvalidSize(u64),
}

impl std::fmt::Display for StreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            StreamError::Truncated => "unexpected eof: encrypted payload is truncated",
            StreamError::Auth => "failed to decrypt and authenticate payload chunk, file may be corrupted or tampered with",
            StreamError::EmptyLastChunk => "last chunk is empty; encrypted payload is malformed",
            StreamError::TrailingData => "trailing data after end of encrypted file",
            StreamError::CounterOverflow => "stream: chunk counter would wrap around",
            StreamError::InvalidSize(n) => return write!(f, "invalid encrypted payload size: {n}"),
        })
    }
}

impl std::error::Error for StreamError {}

impl From<StreamError> for io::Error {
    fn from(e: StreamError) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, e)
    }
}

pub fn nonce(index: u64, last: bool) -> Nonce {
    let mut n = [0u8; 12];
    n[3..11].copy_from_slice(&index.to_be_bytes());
    if last {
        n[11] = LAST_CHUNK_FLAG;
    }
    Nonce::from(n)
}

/// A STREAM key. The cipher state holds a copy of the key that
/// `chacha20poly1305` does not expose for clearing; see SECURITY.md.
pub struct Cipher(ChaCha20Poly1305);

impl Cipher {
    pub fn new(key: &[u8; 32]) -> Self {
        let mut k = Key::from(*key);
        let c = ChaCha20Poly1305::new(&k);
        k.zeroize();
        Cipher(c)
    }

    /// Seals `buf` (at most CHUNK_SIZE bytes of plaintext followed by
    /// TAG_SIZE bytes of room) in place.
    pub fn seal(&self, index: u64, last: bool, buf: &mut [u8]) {
        let n = buf.len() - TAG_SIZE;
        debug_assert!(n <= CHUNK_SIZE);
        let (msg, tag) = buf.split_at_mut(n);
        let t = self
            .0
            .encrypt_inout_detached(&nonce(index, last), &[], msg.into())
            .expect("chunk within aead limits");
        tag.copy_from_slice(&t);
    }

    /// Opens a sealed chunk in place; on success the first `len - 16` bytes
    /// are plaintext. On failure the buffer holds no plaintext.
    pub fn open(&self, index: u64, last: bool, buf: &mut [u8]) -> Result<usize, StreamError> {
        if buf.len() < TAG_SIZE {
            return Err(StreamError::Auth);
        }
        let n = buf.len() - TAG_SIZE;
        let (msg, tag) = buf.split_at_mut(n);
        let tag = Tag::try_from(&*tag).expect("tag size");
        self.0
            .decrypt_inout_detached(&nonce(index, last), &[], msg.into(), &tag)
            .map_err(|_| StreamError::Auth)?;
        Ok(n)
    }
}

fn next_index(i: u64) -> Result<u64, StreamError> {
    i.checked_add(1).ok_or(StreamError::CounterOverflow)
}

/// Encrypting writer. Call [`StreamWriter::finish`] to seal the final
/// chunk; dropping without finishing leaves a truncated stream that every
/// reader rejects.
pub struct StreamWriter<W: Write> {
    cipher: Cipher,
    dst: Option<W>,
    buf: Vec<u8>,
    index: u64,
}

impl<W: Write> StreamWriter<W> {
    pub fn new(key: &[u8; 32], dst: W) -> Self {
        StreamWriter {
            cipher: Cipher::new(key),
            dst: Some(dst),
            buf: Vec::with_capacity(ENC_CHUNK_SIZE),
            index: 0,
        }
    }

    #[cfg(test)]
    fn starting_at(key: &[u8; 32], dst: W, index: u64) -> Self {
        let mut w = Self::new(key, dst);
        w.index = index;
        w
    }

    fn flush_chunk(&mut self, last: bool) -> io::Result<()> {
        let n = self.buf.len();
        self.buf.resize(n + TAG_SIZE, 0);
        self.cipher.seal(self.index, last, &mut self.buf);
        self.dst.as_mut().expect("writer in use").write_all(&self.buf)?;
        self.buf.clear();
        self.index = next_index(self.index)?;
        Ok(())
    }

    pub fn finish(mut self) -> io::Result<W> {
        self.flush_chunk(true)?;
        Ok(self.dst.take().expect("writer in use"))
    }
}

impl<W: Write> Write for StreamWriter<W> {
    fn write(&mut self, mut p: &[u8]) -> io::Result<usize> {
        let total = p.len();
        while !p.is_empty() {
            let take = p.len().min(CHUNK_SIZE - self.buf.len());
            self.buf.extend_from_slice(&p[..take]);
            p = &p[take..];
            // Flush a full chunk only once more data proves it is not the
            // last one.
            if self.buf.len() == CHUNK_SIZE && !p.is_empty() {
                self.flush_chunk(false)?;
            }
        }
        Ok(total)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.dst.as_mut().expect("writer in use").flush()
    }
}

impl<W: Write> Drop for StreamWriter<W> {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

/// Reads until `buf` is full or the source ends; returns the count.
pub fn read_full<R: Read + ?Sized>(src: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match src.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

/// After a final chunk: the source must be at end of input.
fn expect_eof(src: &mut impl Read) -> io::Result<()> {
    let mut b = [0u8; 1];
    loop {
        match src.read(&mut b) {
            Ok(0) => return Ok(()),
            Ok(_) => return Err(StreamError::TrailingData.into()),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

/// Decrypting reader with one chunk of read-ahead: a full-length chunk is
/// held until the next read shows whether anything follows it.
pub struct StreamReader<R: Read> {
    cipher: Cipher,
    src: R,
    index: u64,
    started: bool,
    done: bool,
    failed: bool,
    pending: Option<Vec<u8>>,
    /// Plaintext of a short final chunk, opened together with the chunk
    /// before it and delivered after it.
    queued: Option<Vec<u8>>,
    out: Vec<u8>,
    pos: usize,
    spare: Vec<Vec<u8>>,
}

impl<R: Read> StreamReader<R> {
    pub fn new(key: &[u8; 32], src: R) -> Self {
        StreamReader {
            cipher: Cipher::new(key),
            src,
            index: 0,
            started: false,
            done: false,
            failed: false,
            pending: None,
            queued: None,
            out: Vec::new(),
            pos: 0,
            spare: Vec::new(),
        }
    }

    /// Reads one raw chunk into a recycled buffer, truncated to its length.
    fn read_raw(&mut self) -> io::Result<Vec<u8>> {
        let mut b = self.spare.pop().unwrap_or_default();
        b.resize(ENC_CHUNK_SIZE, 0);
        let n = read_full(&mut self.src, &mut b)?;
        b.truncate(n);
        Ok(b)
    }

    /// Opens `raw` in place as chunk `self.index`, leaving its plaintext.
    fn open(&mut self, mut raw: Vec<u8>, last: bool) -> io::Result<Vec<u8>> {
        match self.cipher.open(self.index, last, &mut raw) {
            Ok(n) => {
                raw.truncate(n);
                self.index = next_index(self.index)?;
                Ok(raw)
            }
            Err(e) => {
                raw.zeroize();
                Err(e.into())
            }
        }
    }

    fn deliver(&mut self, plain: Vec<u8>) {
        let mut old = std::mem::replace(&mut self.out, plain);
        old.zeroize();
        old.clear();
        self.spare.push(old);
        self.pos = 0;
    }

    fn advance(&mut self) -> io::Result<()> {
        if !self.started {
            self.started = true;
            let raw = self.read_raw()?;
            if raw.is_empty() {
                return Err(StreamError::Truncated.into());
            }
            if raw.len() < ENC_CHUNK_SIZE {
                // A short first chunk is final; empty is the empty file.
                let p = self.open(raw, true)?;
                expect_eof(&mut self.src)?;
                self.deliver(p);
                self.done = true;
                return Ok(());
            }
            self.pending = Some(raw);
        }
        let pending = self.pending.take().expect("pending chunk");
        let next = self.read_raw()?;
        if next.is_empty() {
            // Nothing follows: a full-length final chunk, and end of input
            // has just been seen.
            let p = self.open(pending, true)?;
            self.deliver(p);
            self.done = true;
        } else if next.len() < ENC_CHUNK_SIZE {
            if next.len() == TAG_SIZE {
                return Err(StreamError::EmptyLastChunk.into());
            }
            let p = self.open(pending, false)?;
            let q = self.open(next, true)?;
            expect_eof(&mut self.src)?;
            self.deliver(p);
            self.queued = Some(q);
            self.done = true;
        } else {
            let p = self.open(pending, false)?;
            self.deliver(p);
            self.pending = Some(next);
        }
        Ok(())
    }
}

impl<R: Read> Read for StreamReader<R> {
    fn read(&mut self, p: &mut [u8]) -> io::Result<usize> {
        if p.is_empty() {
            return Ok(0);
        }
        loop {
            if self.pos < self.out.len() {
                let n = p.len().min(self.out.len() - self.pos);
                p[..n].copy_from_slice(&self.out[self.pos..self.pos + n]);
                self.pos += n;
                return Ok(n);
            }
            if let Some(q) = self.queued.take() {
                self.deliver(q);
                continue;
            }
            if self.failed {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "encrypted stream already failed"));
            }
            if self.done {
                return Ok(0);
            }
            if let Err(e) = self.advance() {
                self.failed = true;
                self.out.zeroize();
                self.out.clear();
                return Err(e);
            }
        }
    }
}

impl<R: Read> Drop for StreamReader<R> {
    fn drop(&mut self) {
        self.out.zeroize();
        for b in self.pending.iter_mut().chain(self.queued.iter_mut()).chain(self.spare.iter_mut()) {
            b.zeroize();
        }
    }
}

/// Seals a whole plaintext held in memory, chunk by chunk, appending to
/// `out`. Byte-identical to [`StreamWriter`].
pub fn seal_all(key: &[u8; 32], plaintext: &[u8], out: &mut Vec<u8>) {
    let c = Cipher::new(key);
    let chunks = plaintext.len().div_ceil(CHUNK_SIZE).max(1);
    out.reserve(plaintext.len() + chunks * TAG_SIZE);
    for i in 0..chunks {
        let start = i * CHUNK_SIZE;
        let end = (start + CHUNK_SIZE).min(plaintext.len());
        let at = out.len();
        out.extend_from_slice(&plaintext[start..end]);
        out.resize(out.len() + TAG_SIZE, 0);
        c.seal(i as u64, i + 1 == chunks, &mut out[at..]);
    }
}

/// Opens a whole sealed payload in place. On success the plaintext is
/// `buf[..returned]`; on any failure the buffer is cleared.
pub fn open_all(key: &[u8; 32], buf: &mut [u8]) -> Result<usize, StreamError> {
    let r = open_all_inner(key, buf);
    if r.is_err() {
        buf.zeroize();
    }
    r
}

fn open_all_inner(key: &[u8; 32], buf: &mut [u8]) -> Result<usize, StreamError> {
    let size = buf.len() as u64;
    let chunks = encrypted_chunk_count(size)?;
    let c = Cipher::new(key);
    let mut plain = 0usize;
    for i in 0..chunks {
        let start = i as usize * ENC_CHUNK_SIZE;
        let end = (start + ENC_CHUNK_SIZE).min(buf.len());
        let n = c.open(i, i + 1 == chunks, &mut buf[start..end])?;
        // Compact: plaintext of chunk i lands at i*CHUNK_SIZE <= start.
        buf.copy_within(start..start + n, plain);
        plain += n;
    }
    Ok(plain)
}

/// The number of chunks in a payload of `size` bytes, or an error if no
/// STREAM encoding has that size (Go's `EncryptedChunkCount`).
pub fn encrypted_chunk_count(size: u64) -> Result<u64, StreamError> {
    let enc = ENC_CHUNK_SIZE as u64;
    let chunks = size.div_ceil(enc);
    let plain = size.checked_sub(chunks * TAG_SIZE as u64).ok_or(StreamError::InvalidSize(size))?;
    let expected = if plain == 0 { 1 } else { plain.div_ceil(CHUNK_SIZE as u64) };
    if expected != chunks {
        return Err(StreamError::InvalidSize(size));
    }
    Ok(chunks)
}

pub fn plaintext_size(encrypted: u64) -> Result<u64, StreamError> {
    Ok(encrypted - encrypted_chunk_count(encrypted)? * TAG_SIZE as u64)
}

/// Positional reads, as `std::os::unix::fs::FileExt::read_at`.
pub trait ReadAt {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize>;
}

impl ReadAt for [u8] {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        let off = usize::try_from(offset).unwrap_or(usize::MAX).min(self.len());
        let n = buf.len().min(self.len() - off);
        buf[..n].copy_from_slice(&self[off..off + n]);
        Ok(n)
    }
}

impl ReadAt for std::fs::File {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        #[cfg(unix)]
        {
            std::os::unix::fs::FileExt::read_at(self, buf, offset)
        }
        #[cfg(windows)]
        {
            std::os::windows::fs::FileExt::seek_read(self, buf, offset)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (buf, offset);
            Err(io::Error::new(io::ErrorKind::Unsupported, "positional reads unsupported"))
        }
    }
}

fn read_exact_at<S: ReadAt + ?Sized>(src: &S, buf: &mut [u8], mut off: u64) -> io::Result<()> {
    let mut done = 0;
    while done < buf.len() {
        match src.read_at(&mut buf[done..], off) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => {
                done += n;
                off += n as u64;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Random-access decryption (Go's `DecryptReaderAt`). Construction checks
/// the size is a valid encoding and authenticates the final chunk, so a
/// truncated or extended payload is rejected before any read.
pub struct StreamReaderAt<'a, S: ReadAt + ?Sized> {
    cipher: Cipher,
    src: &'a S,
    size: u64,
    chunks: u64,
    cache: std::sync::Mutex<Option<(u64, Vec<u8>)>>,
}

impl<'a, S: ReadAt + ?Sized> StreamReaderAt<'a, S> {
    pub fn new(key: &[u8; 32], src: &'a S, encrypted_size: u64) -> io::Result<Self> {
        let cipher = Cipher::new(key);
        let chunks = encrypted_chunk_count(encrypted_size)?;
        let last = chunks - 1;
        let off = last * ENC_CHUNK_SIZE as u64;
        let mut buf = vec![0u8; (encrypted_size - off) as usize];
        read_exact_at(src, &mut buf, off)?;
        let n = cipher.open(last, true, &mut buf).inspect_err(|_| buf.zeroize())?;
        buf.truncate(n);
        Ok(StreamReaderAt {
            cipher,
            src,
            size: encrypted_size - chunks * TAG_SIZE as u64,
            chunks,
            cache: std::sync::Mutex::new(Some((last, buf))),
        })
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    /// Fills as much of `p` as lies before the end of the plaintext and
    /// returns the count; reading at or past the end returns 0.
    pub fn read_at(&self, p: &mut [u8], mut off: u64) -> io::Result<usize> {
        if off > self.size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("offset out of range [0:{}]: {off}", self.size),
            ));
        }
        let mut n = 0;
        let mut chunk = vec![0u8; ENC_CHUNK_SIZE];
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        while n < p.len() && off < self.size {
            let idx = off / CHUNK_SIZE as u64;
            let plain: &[u8] = match &*cache {
                Some((i, data)) if *i == idx => data,
                _ => {
                    let coff = idx * ENC_CHUNK_SIZE as u64;
                    let enc = (self.size + self.chunks * TAG_SIZE as u64 - coff).min(ENC_CHUNK_SIZE as u64) as usize;
                    read_exact_at(self.src, &mut chunk[..enc], coff)?;
                    let k = self.cipher.open(idx, idx == self.chunks - 1, &mut chunk[..enc])?;
                    if let Some((_, old)) = cache.as_mut() {
                        old.zeroize();
                    }
                    *cache = Some((idx, chunk[..k].to_vec()));
                    &cache.as_ref().expect("just set").1
                }
            };
            let within = (off - idx * CHUNK_SIZE as u64) as usize;
            let take = (plain.len() - within).min(p.len() - n);
            p[n..n + take].copy_from_slice(&plain[within..within + take]);
            n += take;
            off += take as u64;
        }
        chunk.zeroize();
        Ok(n)
    }
}

impl<S: ReadAt + ?Sized> Drop for StreamReaderAt<'_, S> {
    fn drop(&mut self) {
        if let Some((_, d)) = self.cache.get_mut().unwrap_or_else(|e| e.into_inner()).as_mut() {
            d.zeroize();
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn pt(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 13 + 7) as u8).collect()
    }

    fn seal(key: &[u8; 32], p: &[u8]) -> Vec<u8> {
        let mut w = StreamWriter::new(key, Vec::new());
        w.write_all(p).unwrap();
        w.finish().unwrap()
    }

    fn open_stream(key: &[u8; 32], c: &[u8]) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        StreamReader::new(key, c).read_to_end(&mut out)?;
        Ok(out)
    }

    #[derive(serde::Deserialize)]
    struct Vectors {
        key: String,
        vectors: Vec<V>,
    }
    #[derive(serde::Deserialize)]
    struct V {
        size: usize,
        ct_len: usize,
        ct_sha256: String,
        ct_hex: Option<String>,
    }

    fn sha256(b: &[u8]) -> String {
        use sha2::Digest;
        hex(&sha2::Sha256::digest(b))
    }

    pub(crate) fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn go_oracle_vectors() {
        let v: Vectors = serde_json::from_str(include_str!("../../tests/vectors/stream.json")).unwrap();
        let key: [u8; 32] = (1..=32).collect::<Vec<u8>>().try_into().unwrap();
        assert_eq!(hex(&key), v.key);
        for t in v.vectors {
            let p = pt(t.size);
            let c = seal(&key, &p);
            assert_eq!(c.len(), t.ct_len, "size {}", t.size);
            assert_eq!(sha256(&c), t.ct_sha256, "size {}", t.size);
            if let Some(h) = t.ct_hex {
                assert_eq!(hex(&c), h);
            }
            let mut all = Vec::new();
            seal_all(&key, &p, &mut all);
            assert_eq!(all, c, "seal_all size {}", t.size);
            assert_eq!(open_stream(&key, &c).unwrap(), p);
            let n = open_all(&key, &mut all).unwrap();
            assert_eq!(&all[..n], &p[..]);
            assert_eq!(plaintext_size(c.len() as u64).unwrap(), t.size as u64);
        }
    }

    #[test]
    fn writes_in_any_steps_match() {
        let key = [3u8; 32];
        let p = pt(3 * CHUNK_SIZE + 5);
        let whole = seal(&key, &p);
        for step in [1, 7, 4096, CHUNK_SIZE - 1, CHUNK_SIZE, CHUNK_SIZE + 1] {
            let mut w = StreamWriter::new(&key, Vec::new());
            for c in p.chunks(step) {
                w.write_all(c).unwrap();
            }
            assert_eq!(w.finish().unwrap(), whole, "step {step}");
        }
    }

    #[test]
    fn reads_in_any_steps_match() {
        let key = [4u8; 32];
        for size in [0, 1, CHUNK_SIZE, CHUNK_SIZE + 1, 2 * CHUNK_SIZE, 2 * CHUNK_SIZE + 17] {
            let p = pt(size);
            let c = seal(&key, &p);
            for step in [1, 1000, CHUNK_SIZE, CHUNK_SIZE + 3] {
                let mut r = StreamReader::new(&key, &c[..]);
                let mut got = Vec::new();
                let mut b = vec![0u8; step];
                loop {
                    let n = r.read(&mut b).unwrap();
                    if n == 0 {
                        break;
                    }
                    got.extend_from_slice(&b[..n]);
                }
                assert_eq!(got, p, "size {size} step {step}");
            }
        }
    }

    /// Every malformation is rejected by the streaming reader, the in-memory
    /// opener and (where the size is valid) the random-access reader alike.
    #[test]
    fn malformed_streams_rejected_consistently() {
        let key = [5u8; 32];
        let mut cases: Vec<(String, Vec<u8>)> = Vec::new();
        for size in [
            0,
            1,
            CHUNK_SIZE - 1,
            CHUNK_SIZE,
            CHUNK_SIZE + 1,
            2 * CHUNK_SIZE,
            2 * CHUNK_SIZE + 100,
        ] {
            let c = seal(&key, &pt(size));
            cases.push((format!("{size} truncated by one"), c[..c.len() - 1].to_vec()));
            cases.push((format!("{size} trailing byte"), [&c[..], &[0]].concat()));
            cases.push((format!("{size} trailing chunk"), [&c[..], &c[..]].concat()));
            if c.len() > ENC_CHUNK_SIZE {
                cases.push((format!("{size} final chunk dropped"), c[..ENC_CHUNK_SIZE].to_vec()));
                let mut swapped = c.clone();
                swapped[..ENC_CHUNK_SIZE].copy_from_slice(&c[c.len() - ENC_CHUNK_SIZE..]);
                if swapped != c {
                    cases.push((format!("{size} chunk swapped"), swapped));
                }
            }
            for at in [0, c.len() / 2, c.len() - 1] {
                let mut f = c.clone();
                f[at] ^= 0x80;
                cases.push((format!("{size} flipped at {at}"), f));
            }
        }
        cases.push(("empty".into(), Vec::new()));
        cases.push(("tag only, second chunk".into(), {
            // A full non-final chunk followed by an empty final chunk is
            // never produced and must be refused.
            let p = pt(CHUNK_SIZE);
            let c = Cipher::new(&key);
            let mut a = p.clone();
            a.resize(ENC_CHUNK_SIZE, 0);
            c.seal(0, false, &mut a);
            let mut b = vec![0u8; TAG_SIZE];
            c.seal(1, true, &mut b);
            [a, b].concat()
        }));
        for (name, c) in cases {
            assert!(open_stream(&key, &c).is_err(), "stream accepted: {name}");
            let mut b = c.clone();
            assert!(open_all(&key, &mut b).is_err(), "open_all accepted: {name}");
            assert!(b.iter().all(|&x| x == 0), "open_all left data behind: {name}");
            if let Ok(r) = StreamReaderAt::new(&key, &c[..], c.len() as u64) {
                let mut out = vec![0u8; r.size() as usize];
                assert!(r.read_at(&mut out, 0).is_err(), "reader-at accepted: {name}");
            }
        }
        let wrong = seal(&[6u8; 32], b"x");
        assert!(open_stream(&key, &wrong).is_err());
    }

    #[test]
    fn random_access() {
        let key = [8u8; 32];
        for size in [0, 1, CHUNK_SIZE, CHUNK_SIZE + 1, 3 * CHUNK_SIZE - 5] {
            let p = pt(size);
            let c = seal(&key, &p);
            let r = StreamReaderAt::new(&key, &c[..], c.len() as u64).unwrap();
            assert_eq!(r.size(), size as u64);
            for (off, len) in [(0, size), (size / 2, size / 3 + 1), (size.saturating_sub(1), 10), (size, 4)] {
                let mut b = vec![0u8; len];
                let n = r.read_at(&mut b, off as u64).unwrap();
                let want = &p[off.min(size)..(off + len).min(size)];
                assert_eq!(&b[..n], want, "size {size} off {off} len {len}");
            }
            assert!(r.read_at(&mut [0u8; 1], size as u64 + 1).is_err());
        }
        // Concurrent readers share the cache safely.
        let p = pt(4 * CHUNK_SIZE);
        let c = seal(&key, &p);
        let r = StreamReaderAt::new(&key, &c[..], c.len() as u64).unwrap();
        std::thread::scope(|s| {
            for t in 0..8u64 {
                let (r, p) = (&r, &p);
                s.spawn(move || {
                    for i in 0..200u64 {
                        let off = ((i * 7919 + t * 104729) % p.len() as u64) as usize;
                        let mut b = [0u8; 100];
                        let n = r.read_at(&mut b, off as u64).unwrap();
                        assert_eq!(&b[..n], &p[off..(off + 100).min(p.len())]);
                    }
                });
            }
        });
        assert!(StreamReaderAt::new(&key, &c[..], c.len() as u64 - 1).is_err());
        assert!(encrypted_chunk_count(15).is_err());
        assert!(encrypted_chunk_count(ENC_CHUNK_SIZE as u64 + 16).is_err());
    }

    #[test]
    fn counter_overflow_is_refused() {
        let mut w = StreamWriter::starting_at(&[1u8; 32], Vec::new(), u64::MAX);
        w.write_all(&pt(CHUNK_SIZE + 1)).unwrap_err();
        assert_eq!(next_index(u64::MAX), Err(StreamError::CounterOverflow));
    }
}
