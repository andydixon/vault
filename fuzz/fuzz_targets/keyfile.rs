// SPDX-License-Identifier: GPL-3.0-or-later
//! PEM decoding never panics, and decoding what it encoded is the identity.
#![no_main]
use vault::keyfile::{decode_pem, encode_pem, parse_body};

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if let Some(body) = decode_pem(data) {
        let _ = parse_body(&body);
        assert_eq!(decode_pem(encode_pem(&body).as_bytes()), Some(body));
    }
});
