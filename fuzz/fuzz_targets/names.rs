// SPDX-License-Identifier: GPL-3.0-or-later
//! Path validation: a valid vault name is clean, relative and confined; the
//! tar name check only ever yields valid-shaped relative names.
#![no_main]
use vault::store::VaultName;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    if let Some(n) = VaultName::new(s) {
        let n = n.as_str();
        assert_eq!(vault::util::clean(n), n);
        assert!(!n.starts_with('/') && !n.contains('\\') && !n.split('/').any(|c| c == ".." || c == "." || c.is_empty()));
        assert!(n.len() <= 1024);
    }
    if let Some(n) = vault::absorb::safe_name(s) {
        assert!(!n.is_empty() && !n.starts_with('/') && !n.split('/').any(|c| c == ".."));
    }
});
