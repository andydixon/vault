// SPDX-License-Identifier: GPL-3.0-or-later
//! The Fury header parser never panics, and accepts only canonical headers:
//! whatever it accepts re-serialises to exactly the bytes it consumed.
#![no_main]
use std::io::Read;
use vault::crypto::header;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if let Ok((h, mut rest)) = header::parse(data) {
        let mut tail = Vec::new();
        rest.read_to_end(&mut tail).unwrap();
        let consumed = &data[..data.len() - tail.len()];
        assert_eq!(h.marshal(), consumed, "non-canonical header accepted");
    }
});
