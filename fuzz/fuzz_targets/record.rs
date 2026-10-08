// SPDX-License-Identifier: GPL-3.0-or-later
//! Record JSON parsing never panics; an accepted record re-encodes (Go's
//! JSON) to something that parses back to the same values.
#![no_main]
use vault::store::{Id, Record};

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if let Ok(r) = Record::from_json(data, Id([0; 16])) {
        let Some(j) = r.to_json() else { return };
        let r2 = Record::from_json(&j, Id([0; 16])).expect("own encoding parses");
        assert_eq!(r.name, r2.name);
        assert_eq!((r.size, r.mode, r.modified, r.added), (r2.size, r2.mode, r2.modified, r2.added));
        assert!(r.seed.same_as(&r2.seed));
    }
});
