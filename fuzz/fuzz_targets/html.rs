// SPDX-License-Identifier: GPL-3.0-or-later
//! The mirror's HTML and CSS rewriters never panic, and rewriting nothing
//! returns the input byte for byte.
#![no_main]
use vault::net::html;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = html::tokenize(data);
    assert_eq!(html::rewrite_html(data, &mut |_| None, &mut |_| None), data);
    assert_eq!(html::rewrite_css(data, false, &mut |_| None), data);
    let _ = html::rewrite_html(data, &mut |_| None, &mut |u| Some(format!("x/{}", u.len())));
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = vault::net::Url::parse(s).map(|u| u.join("../a?b#c"));
    }
});
