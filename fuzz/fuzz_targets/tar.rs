// SPDX-License-Identifier: GPL-3.0-or-later
//! Walking arbitrary tar input as absorb does never panics, and every name
//! it would store is confined.
#![no_main]
use std::io::Read;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let mut a = tar::Archive::new(data);
    let Ok(entries) = a.entries() else { return };
    for e in entries.take(64) {
        let Ok(mut e) = e else { return };
        let name = e.path_bytes().into_owned();
        if let Some(n) = std::str::from_utf8(&name).ok().and_then(vault::absorb::safe_name) {
            assert!(!n.split('/').any(|c| c == ".."));
        }
        let mut sink = Vec::new();
        let _ = e.by_ref().take(1 << 20).read_to_end(&mut sink);
    }
});
