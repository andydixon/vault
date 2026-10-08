// SPDX-License-Identifier: GPL-3.0-or-later

//! The Fury header: serialisation and a strict parser matching the Go
//! `internal/format` package byte for byte.
//!
//! ```text
//! fury-encryption.org/v1\n
//! -> TYPE ARG...\n          one stanza per recipient
//! BASE64 body, 64 columns per line, ending with a line shorter than 64
//! --- BASE64(MAC)\n
//! ```
//!
//! Base64 is the standard alphabet without padding, with non-zero trailing
//! bits rejected. A stanza's lines total at most 1 MiB and the header at
//! most 16 MiB.

use base64::Engine;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use std::io::{self, Read, Write};

pub const MAX_HEADER_SIZE: u64 = 16 << 20;
pub const MAX_STANZA_SIZE: u64 = 1 << 20;
pub const INTRO: &[u8] = b"fury-encryption.org/v1\n";
const STANZA_PREFIX: &[u8] = b"->";
const FOOTER_PREFIX: &[u8] = b"---";
const COLUMNS: usize = 64;
const BYTES_PER_LINE: usize = COLUMNS / 4 * 3;

pub const B64: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::RequireNone)
        .with_decode_allow_trailing_bits(false),
);

pub fn encode(b: &[u8]) -> String {
    B64.encode(b)
}

/// Strict unpadded base64; CR and LF are rejected outright, as in Go.
pub fn decode(s: &[u8]) -> Result<Vec<u8>, String> {
    if s.iter().any(|&c| c == b'\n' || c == b'\r') {
        return Err("unexpected newline character".into());
    }
    B64.decode(s).map_err(|e| e.to_string().to_lowercase())
}

#[derive(Clone, PartialEq, Eq)]
pub struct Stanza {
    pub typ: String,
    pub args: Vec<String>,
    pub body: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Header {
    pub recipients: Vec<Stanza>,
    pub mac: [u8; 32],
}

impl Stanza {
    pub fn marshal(&self, w: &mut Vec<u8>) {
        w.extend_from_slice(STANZA_PREFIX);
        for a in std::iter::once(&self.typ).chain(&self.args) {
            w.push(b' ');
            w.extend_from_slice(a.as_bytes());
        }
        w.push(b'\n');
        let enc = encode(&self.body);
        let mut chunks = enc.as_bytes().chunks(COLUMNS).peekable();
        let mut last_full = true;
        while let Some(c) = chunks.next() {
            w.extend_from_slice(c);
            if c.len() == COLUMNS {
                w.push(b'\n');
            } else {
                last_full = false;
            }
            if chunks.peek().is_none() && c.len() < COLUMNS {
                w.push(b'\n');
            }
        }
        // A body whose encoding fills its last line (or is empty) ends with
        // an empty line, so every stanza ends with a short line.
        if last_full {
            w.push(b'\n');
        }
    }
}

impl Header {
    /// Everything the MAC covers: intro, stanzas and the footer prefix.
    pub fn marshal_without_mac(&self) -> Vec<u8> {
        let mut w = INTRO.to_vec();
        for s in &self.recipients {
            s.marshal(&mut w);
        }
        w.extend_from_slice(FOOTER_PREFIX);
        w
    }

    pub fn marshal(&self) -> Vec<u8> {
        let mut w = self.marshal_without_mac();
        w.push(b' ');
        w.extend_from_slice(encode(&self.mac).as_bytes());
        w.push(b'\n');
        w
    }

    pub fn write_to(&self, w: &mut impl Write) -> io::Result<()> {
        w.write_all(&self.marshal())
    }
}

/// A reader with as much look-ahead as the parser needs. After parsing,
/// [`Peek::into_payload`] hands back the unread bytes followed by the rest
/// of the source.
/// The payload after a parsed header: read-ahead bytes, then the source.
pub type Payload<R> = io::Chain<io::Cursor<Vec<u8>>, R>;

pub struct Peek<R> {
    inner: R,
    buf: Vec<u8>,
    pos: usize,
    eof: bool,
}

impl<R: Read> Peek<R> {
    pub fn new(inner: R) -> Self {
        Peek {
            inner,
            buf: Vec::with_capacity(8192),
            pos: 0,
            eof: false,
        }
    }

    fn fill(&mut self) -> io::Result<bool> {
        if self.eof {
            return Ok(false);
        }
        if self.pos > 0 && self.pos == self.buf.len() {
            self.buf.clear();
            self.pos = 0;
        }
        let start = self.buf.len();
        self.buf.resize(start + 8192, 0);
        let n = loop {
            match self.inner.read(&mut self.buf[start..]) {
                Ok(n) => break n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    self.buf.truncate(start);
                    return Err(e);
                }
            }
        };
        self.buf.truncate(start + n);
        if n == 0 {
            self.eof = true;
        }
        Ok(n > 0)
    }

    /// Up to `n` bytes ahead, fewer only at end of input.
    fn peek(&mut self, n: usize) -> io::Result<&[u8]> {
        while self.buf.len() - self.pos < n && self.fill()? {}
        let end = (self.pos + n).min(self.buf.len());
        Ok(&self.buf[self.pos..end])
    }

    /// Reads one line including its newline. Fails if the line, added to
    /// `*count`, would exceed `limit`, or if input ends before a newline.
    fn line(&mut self, count: &mut u64, limit: u64) -> Result<Vec<u8>, LineError> {
        let mut line = Vec::new();
        loop {
            if self.pos == self.buf.len() && !self.fill().map_err(LineError::Io)? {
                return Err(LineError::Eof);
            }
            let avail = &self.buf[self.pos..];
            let (take, done) = match avail.iter().position(|&c| c == b'\n') {
                Some(i) => (i + 1, true),
                None => (avail.len(), false),
            };
            if *count + take as u64 > limit {
                return Err(LineError::TooLong);
            }
            *count += take as u64;
            line.extend_from_slice(&avail[..take]);
            self.pos += take;
            if done {
                return Ok(line);
            }
        }
    }

    pub fn into_payload(self) -> Payload<R> {
        let mut rest = self.buf;
        rest.drain(..self.pos);
        io::Cursor::new(rest).chain(self.inner)
    }
}

enum LineError {
    Io(io::Error),
    Eof,
    TooLong,
}

#[derive(Debug)]
pub enum ParseError {
    Io(io::Error),
    Malformed(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Io(e) => write!(f, "failed to read header: {e}"),
            ParseError::Malformed(m) => write!(f, "parsing fury header: {m}"),
        }
    }
}

fn bad<T>(m: impl Into<String>) -> Result<T, ParseError> {
    Err(ParseError::Malformed(m.into()))
}

fn split_args(line: &[u8]) -> (&[u8], Vec<&[u8]>) {
    let l = line.strip_suffix(b"\n").unwrap_or(line);
    let mut parts = l.split(|&c| c == b' ');
    let first = parts.next().unwrap_or(b"");
    (first, parts.collect())
}

fn valid_string(s: &[u8]) -> bool {
    !s.is_empty() && s.iter().all(|&c| (33..=126).contains(&c))
}

fn read_stanza<R: Read>(p: &mut Peek<R>) -> Result<(Stanza, u64), ParseError> {
    let mut n = 0u64;
    let line = match p.line(&mut n, MAX_STANZA_SIZE) {
        Ok(l) => l,
        Err(LineError::TooLong) => return bad(format!("stanza exceeds {MAX_STANZA_SIZE} byte limit")),
        Err(LineError::Eof) => return bad("failed to read line: unexpected eof"),
        Err(LineError::Io(e)) => return Err(ParseError::Io(e)),
    };
    if !line.starts_with(STANZA_PREFIX) {
        return bad("malformed stanza opening line");
    }
    let (prefix, args) = split_args(&line);
    if prefix != STANZA_PREFIX || args.is_empty() || !args.iter().all(|a| valid_string(a)) {
        return bad("malformed stanza");
    }
    // valid_string admits only printable ASCII, so these are UTF-8.
    let text = |a: &[u8]| String::from_utf8(a.to_vec()).expect("ascii");
    let mut s = Stanza {
        typ: text(args[0]),
        args: args[1..].iter().map(|a| text(a)).collect(),
        body: Vec::new(),
    };
    loop {
        let line = match p.line(&mut n, MAX_STANZA_SIZE) {
            Ok(l) => l,
            Err(LineError::TooLong) => return bad(format!("stanza exceeds {MAX_STANZA_SIZE} byte limit")),
            Err(LineError::Eof) => return bad("failed to read line: unexpected eof"),
            Err(LineError::Io(e)) => return Err(ParseError::Io(e)),
        };
        let b = match decode(line.strip_suffix(b"\n").unwrap_or(&line)) {
            Ok(b) => b,
            Err(e) => {
                if line.starts_with(FOOTER_PREFIX) || line.starts_with(STANZA_PREFIX) {
                    return bad("malformed body line: stanza ended without a short line");
                }
                return bad(format!("malformed body line: {e}"));
            }
        };
        if b.len() > BYTES_PER_LINE {
            return bad("malformed body line: too long");
        }
        let short = b.len() < BYTES_PER_LINE;
        s.body.extend_from_slice(&b);
        if short {
            return Ok((s, n));
        }
    }
}

/// Parses a header, returning it and the reader positioned at the payload.
pub fn parse<R: Read>(input: R) -> Result<(Header, Payload<R>), ParseError> {
    let mut p = Peek::new(input);
    let mut total = 0u64;
    match p.line(&mut total, MAX_HEADER_SIZE) {
        Ok(l) if l == INTRO => {}
        Ok(_) => return bad("unexpected intro"),
        Err(LineError::TooLong) => return bad(format!("header exceeds {MAX_HEADER_SIZE} byte limit")),
        Err(LineError::Eof) if total == 0 => return bad("file is empty"),
        Err(LineError::Eof) => return bad("failed to read intro: unexpected eof"),
        Err(LineError::Io(e)) => return Err(ParseError::Io(e)),
    }
    let mut recipients = Vec::new();
    loop {
        let peek = p.peek(FOOTER_PREFIX.len()).map_err(ParseError::Io)?;
        if peek.len() < FOOTER_PREFIX.len() {
            return bad("failed to read header: unexpected eof");
        }
        if peek == FOOTER_PREFIX {
            let line = match p.line(&mut total, MAX_HEADER_SIZE) {
                Ok(l) => l,
                Err(LineError::TooLong) => return bad(format!("header exceeds {MAX_HEADER_SIZE} byte limit")),
                Err(LineError::Eof) => return bad("failed to read header: unexpected eof"),
                Err(LineError::Io(e)) => return Err(ParseError::Io(e)),
            };
            let (prefix, args) = split_args(&line);
            if prefix != FOOTER_PREFIX || args.len() != 1 {
                return bad("malformed closing line");
            }
            let mac = match decode(args[0]) {
                Ok(m) if m.len() == 32 => m,
                _ => return bad("malformed closing line"),
            };
            let mut m = [0u8; 32];
            m.copy_from_slice(&mac);
            return Ok((Header { recipients, mac: m }, p.into_payload()));
        }
        let (s, n) = read_stanza(&mut p)?;
        total += n;
        if total > MAX_HEADER_SIZE {
            return bad(format!("header exceeds {MAX_HEADER_SIZE} byte limit"));
        }
        recipients.push(s);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stanza(body: usize) -> Stanza {
        Stanza {
            typ: "t".into(),
            args: vec!["a".into()],
            body: vec![7u8; body],
        }
    }

    #[test]
    fn body_line_wrapping() {
        let mut w = Vec::new();
        stanza(0).marshal(&mut w);
        assert_eq!(w, b"-> t a\n\n");
        w.clear();
        stanza(48).marshal(&mut w);
        let line = encode(&[7u8; 48]);
        assert_eq!(line.len(), 64);
        assert_eq!(w, format!("-> t a\n{line}\n\n").as_bytes());
        w.clear();
        stanza(50).marshal(&mut w);
        let enc = encode(&[7u8; 50]);
        assert_eq!(w, format!("-> t a\n{}\n{}\n", &enc[..64], &enc[64..]).as_bytes());
    }

    #[test]
    fn round_trip_and_payload() {
        let h = Header {
            recipients: vec![stanza(48), stanza(3)],
            mac: [9; 32],
        };
        let mut b = h.marshal();
        b.extend_from_slice(b"payload");
        let (got, mut rest) = parse(&b[..]).unwrap();
        assert!(got == h);
        let mut p = Vec::new();
        rest.read_to_end(&mut p).unwrap();
        assert_eq!(p, b"payload");
    }

    #[test]
    fn oversized_stanza_and_header() {
        let big = "A".repeat(MAX_STANZA_SIZE as usize);
        let h = format!("fury-encryption.org/v1\n-> x {big}\n\n--- {}\n", encode(&[0; 32]));
        assert!(parse(h.as_bytes()).is_err());
        // Just under the stanza limit is fine...
        let ok = "A".repeat(MAX_STANZA_SIZE as usize - 10);
        let h = format!("fury-encryption.org/v1\n-> x {ok}\n\n--- {}\n", encode(&[0; 32]));
        assert!(parse(h.as_bytes()).is_ok());
        // ...but seventeen such stanzas pass 16 MiB.
        let mut h = String::from("fury-encryption.org/v1\n");
        for _ in 0..17 {
            h.push_str(&format!("-> x {ok}\n\n"));
        }
        h.push_str(&format!("--- {}\n", encode(&[0; 32])));
        assert!(matches!(parse(h.as_bytes()), Err(ParseError::Malformed(m)) if m.contains("header exceeds")));
    }
}
