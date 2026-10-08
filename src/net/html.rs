// SPDX-License-Identifier: GPL-3.0-or-later

//! Link rewriting for mirrored HTML and CSS.
//!
//! HTML is scanned with a small tokenizer following the HTML5 tokenizer's
//! rules for what matters here: tag and attribute syntax (quoted, unquoted
//! and valueless attributes), comments, doctype and other `<!`/`<?`
//! markup, raw-text elements (script, style, xmp, iframe, noembed,
//! noframes), RCDATA (textarea, title) and plaintext. It records byte
//! spans, so rewriting splices new values in and leaves every other byte —
//! quote style included — untouched.
//!
//! Rewritten: the values of `href`, `src`, `action` and `poster` on start
//! tags, and CSS `url(...)` inside `<style>` elements and `style`
//! attributes. CSS files get the `url(...)` rewrite only, with the same
//! matching as the Go version's regular expression
//! `(?i)(url\(\s*["']?)([^"')\s]+)`. Character references in attribute
//! values are decoded before a URL is parsed: numeric ones and the named
//! `amp`, `lt`, `gt`, `quot`, `apos` and `nbsp`; other named references
//! are left as written.

/// Something the tokenizer found.
#[derive(Debug, PartialEq, Eq)]
pub enum Item {
    /// An attribute value on a start tag: lower-case tag and attribute
    /// names, the value's byte span, and whether it was quoted.
    Attr {
        tag: String,
        name: String,
        start: usize,
        end: usize,
        quoted: bool,
    },
    /// The raw text inside a `<style>` element.
    Style { start: usize, end: usize },
}

fn is_ws(c: u8) -> bool {
    matches!(c, b'\t' | b'\n' | b'\x0c' | b'\r' | b' ')
}

fn find(h: &[u8], from: usize, n: &[u8]) -> Option<usize> {
    if from > h.len() {
        return None;
    }
    h[from..].windows(n.len()).position(|w| w == n).map(|i| i + from)
}

/// Scans `b` and returns every attribute value and style element, in
/// document order.
pub fn tokenize(b: &[u8]) -> Vec<Item> {
    let mut items = Vec::new();
    let mut pos = 0;
    while let Some(off) = b[pos..].iter().position(|&c| c == b'<') {
        let i = pos + off;
        let next = b.get(i + 1).copied();
        pos = match next {
            Some(b'!') => {
                if b[i..].starts_with(b"<!--") {
                    let body = i + 4;
                    if b[body..].starts_with(b">") {
                        body + 1
                    } else if b[body..].starts_with(b"->") {
                        body + 2
                    } else {
                        find(b, body, b"-->").map_or(b.len(), |e| e + 3)
                    }
                } else {
                    to_gt(b, i + 2)
                }
            }
            Some(b'?') => to_gt(b, i + 2),
            Some(b'/') => match b.get(i + 2) {
                Some(c) if c.is_ascii_alphabetic() => {
                    let (_, after) = tag(b, i + 2, &mut Vec::new(), "");
                    after
                }
                Some(b'>') => i + 3,
                Some(_) => to_gt(b, i + 2),
                None => b.len(),
            },
            Some(c) if c.is_ascii_alphabetic() => {
                let (name, after) = tag(b, i + 1, &mut items, "start");
                match name.as_str() {
                    "script" | "style" | "xmp" | "iframe" | "noembed" | "noframes" | "textarea" | "title" => {
                        let end = raw_text_end(b, after, &name);
                        if name == "style" {
                            items.push(Item::Style { start: after, end });
                        }
                        end
                    }
                    "plaintext" => b.len(),
                    _ => after,
                }
            }
            _ => i + 1,
        };
        if pos >= b.len() {
            break;
        }
    }
    items
}

fn to_gt(b: &[u8], from: usize) -> usize {
    b[from.min(b.len())..]
        .iter()
        .position(|&c| c == b'>')
        .map_or(b.len(), |e| from + e + 1)
}

/// Where raw text started at `from` ends: at `</name` followed by
/// whitespace, `/` or `>` (ASCII case-insensitive), or at end of input.
fn raw_text_end(b: &[u8], from: usize, name: &str) -> usize {
    let mut p = from;
    while let Some(i) = find(b, p, b"</") {
        let n = i + 2;
        let candidate = b.get(n..n + name.len());
        if candidate.is_some_and(|c| c.eq_ignore_ascii_case(name.as_bytes())) {
            match b.get(n + name.len()) {
                Some(&c) if is_ws(c) || c == b'/' || c == b'>' => return i,
                None => return i,
                _ => {}
            }
        }
        p = i + 2;
    }
    b.len()
}

/// Parses a tag whose name starts at `from`; records start-tag attributes
/// (when `kind` is "start") and returns the lower-case name and the index
/// just past the closing `>` (or the end of input).
fn tag(b: &[u8], from: usize, items: &mut Vec<Item>, kind: &str) -> (String, usize) {
    let mut attrs = Vec::new();
    let (name, end, closed) = tag_inner(b, from, &mut attrs);
    // A tag cut off by the end of input is not a tag at all.
    if closed && kind == "start" {
        items.extend(attrs);
    }
    (name, end)
}

fn tag_inner(b: &[u8], from: usize, items: &mut Vec<Item>) -> (String, usize, bool) {
    let mut p = from;
    while p < b.len() && !is_ws(b[p]) && b[p] != b'/' && b[p] != b'>' {
        p += 1;
    }
    let name = String::from_utf8_lossy(&b[from..p]).to_ascii_lowercase();
    loop {
        while p < b.len() && (is_ws(b[p]) || b[p] == b'/') {
            p += 1;
        }
        if p >= b.len() {
            return (name, b.len(), false);
        }
        if b[p] == b'>' {
            return (name, p + 1, true);
        }
        // Attribute name: the first character may be anything (even '='),
        // then up to whitespace, '/', '>' or '='.
        let ns = p;
        p += 1;
        while p < b.len() && !is_ws(b[p]) && b[p] != b'/' && b[p] != b'>' && b[p] != b'=' {
            p += 1;
        }
        let attr = String::from_utf8_lossy(&b[ns..p]).to_ascii_lowercase();
        let mut q = p;
        while q < b.len() && is_ws(b[q]) {
            q += 1;
        }
        if q >= b.len() || b[q] != b'=' {
            p = q;
            continue;
        }
        q += 1;
        while q < b.len() && is_ws(b[q]) {
            q += 1;
        }
        if q >= b.len() {
            return (name, b.len(), false);
        }
        let (start, end, quoted, next) = match b[q] {
            quote @ (b'"' | b'\'') => {
                let s = q + 1;
                match b[s..].iter().position(|&c| c == quote) {
                    Some(e) => (s, s + e, true, s + e + 1),
                    // An unterminated value runs to the end; the tag is
                    // incomplete, so nothing is recorded.
                    None => return (name, b.len(), false),
                }
            }
            b'>' => (q, q, false, q),
            _ => {
                let mut e = q;
                while e < b.len() && !is_ws(b[e]) && b[e] != b'>' {
                    e += 1;
                }
                (q, e, false, e)
            }
        };
        items.push(Item::Attr {
            tag: name.clone(),
            name: attr,
            start,
            end,
            quoted,
        });
        p = next;
    }
}

/// Decodes character references (see the module documentation).
pub fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let (text, used) = reference(rest);
        out.push_str(&text);
        rest = &rest[used..];
    }
    out.push_str(rest);
    out
}

/// One reference at the start of `s` (which begins with '&'): its text and
/// how many bytes it used; an unknown one is passed through as "&".
fn reference(s: &str) -> (String, usize) {
    let b = s.as_bytes();
    if b.get(1) == Some(&b'#') {
        let (hex, start) = if matches!(b.get(2), Some(b'x' | b'X')) {
            (true, 3)
        } else {
            (false, 2)
        };
        let mut e = start;
        while e < b.len() && (if hex { b[e].is_ascii_hexdigit() } else { b[e].is_ascii_digit() }) {
            e += 1;
        }
        if e == start {
            return ("&".into(), 1);
        }
        let v = u32::from_str_radix(&s[start..e], if hex { 16 } else { 10 }).unwrap_or(0xfffd);
        let c = char::from_u32(v).filter(|&c| c != '\0').unwrap_or('\u{fffd}');
        let used = if b.get(e) == Some(&b';') { e + 1 } else { e };
        return (c.to_string(), used);
    }
    for (name, text, legacy) in [
        ("amp", "&", true),
        ("lt", "<", true),
        ("gt", ">", true),
        ("quot", "\"", true),
        ("apos", "'", false),
        ("nbsp", "\u{a0}", true),
    ] {
        if let Some(r) = s[1..].strip_prefix(name) {
            if r.starts_with(';') {
                return (text.into(), name.len() + 2);
            }
            if legacy {
                return (text.into(), name.len() + 1);
            }
        }
    }
    ("&".into(), 1)
}

/// Escapes a value for an attribute, as Go's `html.EscapeString`.
pub fn escape_attr(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '"' => o.push_str("&#34;"),
            '\'' => o.push_str("&#39;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            c => o.push(c),
        }
    }
    o
}

/// Rewrites `url(...)` references in CSS. `map` gets each URL (HTML-
/// unescaped, as the Go version did) and returns its replacement, or None
/// to leave it; replacements are attribute-escaped when `in_attr`. Bytes
/// that are not UTF-8 pass through unchanged.
pub fn rewrite_css(b: &[u8], in_attr: bool, map: &mut dyn FnMut(&str) -> Option<String>) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len());
    let mut last = 0;
    let mut i = 0;
    while i + 4 <= b.len() {
        if !b[i..i + 4].eq_ignore_ascii_case(b"url(") {
            i += 1;
            continue;
        }
        let mut p = i + 4;
        while p < b.len() && is_ws(b[p]) {
            p += 1;
        }
        if p < b.len() && (b[p] == b'"' || b[p] == b'\'') {
            p += 1;
        } else if in_attr {
            p += entity_quote(&b[p..]);
        }
        let start = p;
        while p < b.len() && !is_ws(b[p]) && !matches!(b[p], b'"' | b'\'' | b')') && !(in_attr && entity_quote(&b[p..]) > 0) {
            p += 1;
        }
        if p == start {
            i += 1;
            continue;
        }
        if let Some(r) = map(&unescape(&String::from_utf8_lossy(&b[start..p]))) {
            out.extend_from_slice(&b[last..start]);
            out.extend_from_slice(if in_attr { escape_attr(&r) } else { r }.as_bytes());
            last = p;
        }
        i = p;
    }
    out.extend_from_slice(&b[last..]);
    out
}

/// The length of a quote written as a character reference at the start of
/// `b` (inside an attribute value, CSS quotes arrive that way), or 0.
fn entity_quote(b: &[u8]) -> usize {
    ["&quot;", "&#34;", "&#39;", "&apos;", "&#x22;", "&#x27;"]
        .iter()
        .find(|q| b.starts_with(q.as_bytes()))
        .map_or(0, |q| q.len())
}

/// Rewrites an HTML page. `base` is called with the first `<base href>`
/// value (decoded) before any link after it, and returns what that value
/// becomes; `link` maps a decoded link to its replacement, or None to
/// leave it. Every byte outside a replaced value is kept.
pub fn rewrite_html(page: &[u8], base: &mut dyn FnMut(&str) -> Option<String>, link: &mut dyn FnMut(&str) -> Option<String>) -> Vec<u8> {
    let mut out = Vec::with_capacity(page.len());
    let mut last = 0;
    let mut seen_base = false;
    for item in tokenize(page) {
        let (start, end, replacement) = match item {
            Item::Attr {
                tag,
                name,
                start,
                end,
                quoted,
            } => {
                let raw = &page[start..end];
                let value = || unescape(&String::from_utf8_lossy(raw));
                let r = match name.as_str() {
                    "href" if tag == "base" && !seen_base => {
                        seen_base = true;
                        base(&value())
                    }
                    "href" | "src" | "action" | "poster" => link(&value()),
                    "style" => {
                        let r = rewrite_css(raw, true, link);
                        if r != raw {
                            out.extend_from_slice(&page[last..start]);
                            out.extend_from_slice(&r);
                            last = end;
                        }
                        continue;
                    }
                    _ => None,
                };
                let Some(r) = r else { continue };
                let mut v = escape_attr(&r);
                if !quoted && (v.is_empty() || v.bytes().any(|c| is_ws(c) || b"\"'=<>`".contains(&c))) {
                    v = format!("\"{v}\"");
                }
                (start, end, v.into_bytes())
            }
            Item::Style { start, end } => (start, end, rewrite_css(&page[start..end], false, link)),
        };
        out.extend_from_slice(&page[last..start]);
        out.extend_from_slice(&replacement);
        last = end;
    }
    out.extend_from_slice(&page[last..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upper(s: &str) -> Option<String> {
        Some(s.to_uppercase())
    }

    fn rw(page: &str) -> String {
        String::from_utf8(rewrite_html(page.as_bytes(), &mut |_| None, &mut upper)).unwrap()
    }

    #[test]
    fn attributes_and_quotes_preserved() {
        assert_eq!(
            rw(r#"<a href="x">x</a> <link href='y'> <img src=z alt=q>"#),
            r#"<a href="X">x</a> <link href='Y'> <img src=Z alt=q>"#
        );
        assert_eq!(rw(r#"<A HREF = "x" >"#), r#"<A HREF = "X" >"#);
        assert_eq!(rw(r#"<form action="/p?a=1&amp;b=2">"#), r#"<form action="/P?A=1&amp;B=2">"#);
        assert_eq!(
            rw(r#"<video poster="p.jpg" data-src="d">"#),
            r#"<video poster="P.JPG" data-src="d">"#
        );
        assert_eq!(rw("<p>href=\"x\"</p>"), "<p>href=\"x\"</p>", "text is not markup");
    }

    #[test]
    fn comments_scripts_rcdata_untouched() {
        let s = r#"<!-- <a href="c"> --><script>var a = '<a href="s">';</script><textarea><a href="t"></textarea><title><img src=u></title><a href="ok">"#;
        assert_eq!(rw(s), s.replace("\"ok\"", "\"OK\""));
        assert_eq!(rw("<!--><a href=a>"), "<!--><a href=A>");
        assert_eq!(rw("<!DOCTYPE html><a href=a>"), "<!DOCTYPE html><a href=A>");
        assert_eq!(rw("<script>x</SCRIPT ><a href=a>"), "<script>x</SCRIPT ><a href=A>");
        assert_eq!(rw("<script>x</scripty><a href=a>"), "<script>x</scripty><a href=a>");
        assert_eq!(rw("<plaintext><a href=a>"), "<plaintext><a href=a>");
    }

    #[test]
    fn css_in_html_and_files() {
        assert_eq!(
            rw("<style>body{background:url( 'a.png' )}</style>"),
            "<style>body{background:url( 'A.PNG' )}</style>"
        );
        assert_eq!(
            rw(r#"<div style="background: URL(&quot;b.png&quot;)">"#),
            r#"<div style="background: URL(&quot;B.PNG&quot;)">"#
        );
        let mut m = |s: &str| Some(format!("<{s}>"));
        assert_eq!(
            rewrite_css(b"a{b:url(x)} c{d:url()} url(\"y\")", false, &mut m),
            b"a{b:url(<x>)} c{d:url()} url(\"<y>\")"
        );
    }

    #[test]
    fn base_href_and_escaping() {
        let mut seen = Vec::new();
        let out = rewrite_html(
            br#"<base href="http://h/d/"><base href="x"><a href=a>"#,
            &mut |b| {
                seen.push(b.to_string());
                Some("p.html".into())
            },
            &mut upper,
        );
        assert_eq!(seen, ["http://h/d/"]);
        assert_eq!(out, br#"<base href="p.html"><base href="X"><a href=A>"#);
        let out = rewrite_html(b"<a href=a>", &mut |_| None, &mut |_| Some("a b\"&".into()));
        assert_eq!(out, br#"<a href="a b&#34;&amp;">"#);
        // Non-UTF-8 bytes around and inside values survive.
        let latin1 = b"<p>caf\xe9</p><a href=\"x\xe9\">";
        assert_eq!(rewrite_html(latin1, &mut |_| None, &mut |_| None), latin1);
        assert_eq!(unescape("a&amp;b&#47;&#x2F;&lt&unknown;&apos;&apos"), "a&b//<&unknown;'&apos");
    }

    #[test]
    fn unterminated_input() {
        for s in ["<a href=\"x", "<a href=", "<a", "<", "<!--", "<script>", "</a", "<a href='x' "] {
            assert_eq!(rw(s), s, "{s:?}");
        }
    }

    /// Random and mutated pages never panic, and an identity rewrite
    /// returns the input byte for byte.
    #[test]
    fn fuzz_identity() {
        let seeds = [
            r#"<html><head><base href="/x/"><style>a{b:url(c)}</style></head><body><a href='d'>e</a><img src=f style="g:url(h)"><!-- i --><script>j</script></body></html>"#,
            "<a href=\"x\"><b <c/> </d e='f'> <!DOCTYPE> <? pi ?> <textarea></textarea>",
        ];
        let mut rng = crate::rng::os();
        let alphabet = b"<>/!-='\" \tabcdefhrsxyzlptu()&;#";
        for i in 0..20000 {
            let mut page: Vec<u8> = seeds[i % 2].as_bytes().to_vec();
            for _ in 0..rng.below(8) {
                let at = rng.below(page.len() as u64 + 1) as usize;
                match rng.below(3) {
                    0 => page.insert(at, alphabet[rng.below(alphabet.len() as u64) as usize]),
                    1 if at < page.len() => {
                        page.remove(at);
                    }
                    _ => page.truncate(at),
                }
            }
            if i % 3 == 0 {
                page.push(0xff);
            }
            assert_eq!(rewrite_html(&page, &mut |_| None, &mut |_| None), page);
            // Rewriting everything must not panic either.
            let _ = rewrite_html(&page, &mut |b| Some(b.into()), &mut |v| Some(format!("{v}&x")));
            let _ = tokenize(&page);
        }
    }
}
