// SPDX-License-Identifier: GPL-3.0-or-later
//! The streaming, in-memory and random-access STREAM readers agree on every
//! input: the same plaintext or all reject. Inputs are mostly forgeries;
//! the first byte selects a mode that starts from a valid stream instead.
#![no_main]
use std::io::{Read, Write};
use vault::crypto::stream::{StreamReader, StreamReaderAt, StreamWriter, open_all};

const KEY: [u8; 32] = [7; 32];

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else { return };
    let input = if mode & 1 == 1 {
        // A valid stream of the given plaintext, then a mutation.
        let mut w = StreamWriter::new(&KEY, Vec::new());
        let n = rest.len().min(200_000);
        w.write_all(&rest[..n]).unwrap();
        let mut c = w.finish().unwrap();
        if mode & 2 == 2 && !c.is_empty() {
            let i = (mode as usize * 7919) % c.len();
            c[i] ^= mode | 1;
        }
        if mode & 4 == 4 {
            c.truncate(c.len().saturating_sub(mode as usize % 40));
        }
        c
    } else {
        rest.to_vec()
    };
    let mut a = Vec::new();
    let streaming = StreamReader::new(&KEY, &input[..]).read_to_end(&mut a).map(|_| a);
    let mut b = input.clone();
    let whole = open_all(&KEY, &mut b).map(|n| b[..n].to_vec());
    assert_eq!(streaming.is_ok(), whole.is_ok());
    if let (Ok(x), Ok(y)) = (&streaming, &whole) {
        assert_eq!(x, y);
    }
    if let Ok(r) = StreamReaderAt::new(&KEY, &input[..], input.len() as u64) {
        let mut out = vec![0u8; r.size() as usize];
        let got = r.read_at(&mut out, 0).map(|n| out[..n].to_vec());
        assert_eq!(got.is_ok(), whole.is_ok());
        if let (Ok(x), Ok(y)) = (got, whole) {
            assert_eq!(x, y);
        }
    }
});
