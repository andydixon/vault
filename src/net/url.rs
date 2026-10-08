// SPDX-License-Identifier: GPL-3.0-or-later

//! Just enough of Go's `net/url` to crawl and name pages exactly as the Go
//! version did: `Parse`, `ResolveReference` (RFC 3986 with dot-segment
//! removal), `String` (re-escaping like `EscapedPath`), `Hostname` and
//! `QueryEscape`. `path` is percent-decoded; `raw_query` is kept as sent.

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Url {
    pub scheme: String,
    pub opaque: String,
    /// Userinfo as written (still escaped), without the '@'.
    pub user: Option<String>,
    pub host: String,
    pub path: String,
    raw_path: String,
    pub force_query: bool,
    pub raw_query: String,
    pub fragment: String,
    raw_fragment: String,
    omit_host: bool,
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Path,
    Host,
    QueryComponent,
    Fragment,
}

fn should_escape(c: u8, mode: Mode) -> bool {
    if c.is_ascii_alphanumeric() {
        return false;
    }
    if mode == Mode::Host && b"!$&'()*+,;=:[]<>\"".contains(&c) {
        return false;
    }
    match c {
        b'-' | b'_' | b'.' | b'~' => return false,
        b'$' | b'&' | b'+' | b',' | b'/' | b':' | b';' | b'=' | b'?' | b'@' => {
            return match mode {
                Mode::Path => c == b'?',
                Mode::QueryComponent => true,
                Mode::Fragment => false,
                Mode::Host => true,
            };
        }
        _ => {}
    }
    if mode == Mode::Fragment && b"!()*".contains(&c) {
        return false;
    }
    true
}

fn escape(s: &str, mode: Mode) -> String {
    let mut o = String::with_capacity(s.len());
    for &c in s.as_bytes() {
        if c == b' ' && mode == Mode::QueryComponent {
            o.push('+');
        } else if should_escape(c, mode) {
            o.push_str(&format!("%{c:02X}"));
        } else {
            o.push(c as char);
        }
    }
    o
}

fn unhex(c: u8) -> Option<u8> {
    (c as char).to_digit(16).map(|d| d as u8)
}

fn unescape(s: &str, mode: Mode) -> Result<String, String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let (h, l) = match (b.get(i + 1).copied().and_then(unhex), b.get(i + 2).copied().and_then(unhex)) {
                    (Some(h), Some(l)) => (h, l),
                    _ => return Err(format!("invalid URL escape {:?}", &s[i..(i + 3).min(s.len())])),
                };
                if mode == Mode::Host && h < 8 && &s[i..i + 3] != "%25" {
                    return Err(format!("invalid URL escape {:?}", &s[i..i + 3]));
                }
                out.push(h << 4 | l);
                i += 3;
            }
            b'+' => {
                out.push(if mode == Mode::QueryComponent { b' ' } else { b'+' });
                i += 1;
            }
            c => {
                if mode == Mode::Host && c < 0x80 && should_escape(c, mode) {
                    return Err(format!("invalid character {:?} in host name", c as char));
                }
                out.push(c);
                i += 1;
            }
        }
    }
    // Go strings may hold any bytes; a path that decodes to invalid UTF-8
    // cannot become a vault name anyway, so it is refused here.
    String::from_utf8(out).map_err(|_| "invalid UTF-8 in URL".to_string())
}

pub fn query_escape(s: &str) -> String {
    escape(s, Mode::QueryComponent)
}

fn valid_encoded(s: &str, mode: Mode) -> bool {
    s.bytes()
        .all(|c| b"!$&'()*+,;=:@[]".contains(&c) || c == b'%' || !should_escape(c, mode))
}

fn get_scheme(raw: &str) -> Result<(&str, &str), String> {
    for (i, c) in raw.bytes().enumerate() {
        match c {
            b'a'..=b'z' | b'A'..=b'Z' => {}
            b'0'..=b'9' | b'+' | b'-' | b'.' if i > 0 => {}
            b':' if i == 0 => return Err("missing protocol scheme".into()),
            b':' => return Ok((&raw[..i], &raw[i + 1..])),
            _ => return Ok(("", raw)),
        }
    }
    Ok(("", raw))
}

fn valid_optional_port(p: &str) -> bool {
    p.is_empty() || (p.starts_with(':') && p[1..].bytes().all(|c| c.is_ascii_digit()))
}

fn parse_host(host: &str) -> Result<String, String> {
    if let Some(rest) = host.strip_prefix('[') {
        let end = rest.find(']').ok_or("missing ']' in host")?;
        let port = &rest[end + 1..];
        if !valid_optional_port(port) {
            return Err(format!("invalid port {port:?} after host"));
        }
    } else if let Some(i) = host.rfind(':') {
        let port = &host[i..];
        if !valid_optional_port(port) {
            return Err(format!("invalid port {port:?} after host"));
        }
    }
    unescape(host, Mode::Host)
}

impl Url {
    pub fn parse(raw: &str) -> Result<Url, String> {
        let (rest, frag) = match raw.find('#') {
            Some(i) => (&raw[..i], Some(&raw[i + 1..])),
            None => (raw, None),
        };
        let mut u = Url::parse_without_fragment(rest)?;
        if let Some(f) = frag {
            u.fragment = unescape(f, Mode::Fragment)?;
            u.raw_fragment = if escape(&u.fragment, Mode::Fragment) == f {
                String::new()
            } else {
                f.to_string()
            };
        }
        Ok(u)
    }

    fn parse_without_fragment(raw: &str) -> Result<Url, String> {
        if raw.bytes().any(|c| c < 0x20 || c == 0x7f) {
            return Err("net/url: invalid control character in URL".into());
        }
        let mut u = Url::default();
        if raw.is_empty() {
            return Ok(u);
        }
        let (scheme, mut rest) = get_scheme(raw)?;
        u.scheme = scheme.to_ascii_lowercase();
        if rest.ends_with('?') && rest.matches('?').count() == 1 {
            u.force_query = true;
            rest = &rest[..rest.len() - 1];
        } else if let Some(i) = rest.find('?') {
            u.raw_query = rest[i + 1..].to_string();
            rest = &rest[..i];
        }
        if !rest.starts_with('/') {
            if !u.scheme.is_empty() {
                u.opaque = rest.to_string();
                return Ok(u);
            }
            let seg = rest.split('/').next().unwrap_or("");
            if seg.contains(':') {
                return Err("first path segment in URL cannot contain colon".into());
            }
        }
        if (!u.scheme.is_empty() || !rest.starts_with("///")) && rest.starts_with("//") {
            let auth_and_rest = &rest[2..];
            let (authority, r) = match auth_and_rest.find('/') {
                Some(i) => (&auth_and_rest[..i], &auth_and_rest[i..]),
                None => (auth_and_rest, ""),
            };
            rest = r;
            let host = match authority.rfind('@') {
                Some(i) => {
                    let ui = &authority[..i];
                    if !ui.bytes().all(|c| c.is_ascii_alphanumeric() || b"-._:~!$&'()*+,;=%@".contains(&c)) {
                        return Err("net/url: invalid userinfo".into());
                    }
                    u.user = Some(ui.to_string());
                    &authority[i + 1..]
                }
                None => authority,
            };
            u.host = parse_host(host)?;
        } else if !u.scheme.is_empty() && rest.starts_with('/') {
            u.omit_host = true;
        }
        if !rest.is_empty() {
            u.set_path(rest)?;
        }
        Ok(u)
    }

    fn set_path(&mut self, p: &str) -> Result<(), String> {
        self.path = unescape(p, Mode::Path)?;
        self.raw_path = if escape(&self.path, Mode::Path) == p {
            String::new()
        } else {
            p.to_string()
        };
        Ok(())
    }

    pub fn escaped_path(&self) -> String {
        if !self.raw_path.is_empty()
            && valid_encoded(&self.raw_path, Mode::Path)
            && unescape(&self.raw_path, Mode::Path).ok().as_deref() == Some(&self.path)
        {
            return self.raw_path.clone();
        }
        if self.path == "*" {
            return "*".into();
        }
        escape(&self.path, Mode::Path)
    }

    fn escaped_fragment(&self) -> String {
        if !self.raw_fragment.is_empty()
            && valid_encoded(&self.raw_fragment, Mode::Fragment)
            && unescape(&self.raw_fragment, Mode::Fragment).ok().as_deref() == Some(&self.fragment)
        {
            return self.raw_fragment.clone();
        }
        escape(&self.fragment, Mode::Fragment)
    }

    /// `ref` resolved against `self`, as Go's `URL.Parse`.
    pub fn join(&self, reference: &str) -> Result<Url, String> {
        Ok(self.resolve(&Url::parse(reference)?))
    }

    /// Go's `ResolveReference`.
    pub fn resolve(&self, r: &Url) -> Url {
        let mut u = r.clone();
        if r.scheme.is_empty() {
            u.scheme = self.scheme.clone();
        }
        if !r.scheme.is_empty() || !r.host.is_empty() || r.user.is_some() {
            let p = resolve_path(&r.escaped_path(), "");
            let _ = u.set_path(&p);
            return u;
        }
        if !r.opaque.is_empty() {
            u.user = None;
            u.host.clear();
            u.path.clear();
            return u;
        }
        if r.path.is_empty() && !r.force_query && r.raw_query.is_empty() {
            u.raw_query = self.raw_query.clone();
            if r.fragment.is_empty() {
                u.fragment = self.fragment.clone();
                u.raw_fragment = self.raw_fragment.clone();
            }
        }
        if r.path.is_empty() && !self.opaque.is_empty() {
            u.opaque = self.opaque.clone();
            u.user = None;
            u.host.clear();
            u.path.clear();
            return u;
        }
        u.host = self.host.clone();
        u.user = self.user.clone();
        let p = resolve_path(&self.escaped_path(), &r.escaped_path());
        let _ = u.set_path(&p);
        u
    }

    pub fn clear_fragment(&mut self) {
        self.fragment.clear();
        self.raw_fragment.clear();
    }

    /// The host without any port, IPv6 brackets removed.
    pub fn hostname(&self) -> &str {
        let h = &self.host;
        if let Some(rest) = h.strip_prefix('[') {
            return rest.find(']').map_or(rest, |i| &rest[..i]);
        }
        match h.rfind(':') {
            Some(i) if valid_optional_port(&h[i..]) => &h[..i],
            _ => h,
        }
    }

    /// The port, or the scheme's default.
    pub fn port_or_default(&self) -> &str {
        let h = &self.host;
        let after = if h.starts_with('[') {
            h.find(']').map_or("", |i| &h[i + 1..])
        } else {
            h.rfind(':').map_or("", |i| &h[i..])
        };
        match after.strip_prefix(':') {
            Some(p) if !p.is_empty() => p,
            _ if self.scheme == "https" => "443",
            _ => "80",
        }
    }
}

impl std::fmt::Display for Url {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut b = String::new();
        if !self.scheme.is_empty() {
            b.push_str(&self.scheme);
            b.push(':');
        }
        if !self.opaque.is_empty() {
            b.push_str(&self.opaque);
        } else {
            if (!self.scheme.is_empty() || !self.host.is_empty() || self.user.is_some())
                && !(self.omit_host && self.host.is_empty() && self.user.is_none())
            {
                if !self.host.is_empty() || !self.path.is_empty() || self.user.is_some() {
                    b.push_str("//");
                }
                if let Some(ui) = &self.user {
                    b.push_str(ui);
                    b.push('@');
                }
                b.push_str(&escape(&self.host, Mode::Host));
            }
            let p = self.escaped_path();
            if !p.is_empty() && !p.starts_with('/') && !self.host.is_empty() {
                b.push('/');
            }
            if b.is_empty() && p.split('/').next().unwrap_or("").contains(':') {
                b.push_str("./");
            }
            b.push_str(&p);
        }
        if self.force_query || !self.raw_query.is_empty() {
            b.push('?');
            b.push_str(&self.raw_query);
        }
        if !self.fragment.is_empty() {
            b.push('#');
            b.push_str(&self.escaped_fragment());
        }
        f.write_str(&b)
    }
}

/// Go's `resolvePath`: merge and remove dot segments.
fn resolve_path(base: &str, r: &str) -> String {
    let full = if r.is_empty() {
        base.to_string()
    } else if !r.starts_with('/') {
        let i = base.rfind('/').map_or(0, |i| i + 1);
        format!("{}{}", &base[..i], r)
    } else {
        r.to_string()
    };
    if full.is_empty() {
        return String::new();
    }
    let mut dst = String::from("/");
    let mut first = true;
    let mut last = "";
    for elem in full.split('/') {
        last = elem;
        if elem == "." {
            first = false;
            continue;
        }
        if elem == ".." {
            let s = dst[1..].to_string();
            dst = String::from("/");
            match s.rfind('/') {
                None => first = true,
                Some(i) => dst.push_str(&s[..i]),
            }
        } else {
            if !first {
                dst.push('/');
            }
            dst.push_str(elem);
            first = false;
        }
    }
    if last == "." || last == ".." {
        dst.push('/');
    }
    if dst.len() > 1 && dst.as_bytes()[1] == b'/' {
        dst.remove(0);
    }
    dst
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::Value;

    pub(crate) fn vectors() -> Value {
        serde_json::from_str(include_str!("../../tests/vectors/net.json")).unwrap()
    }

    fn check(v: &Value, got: Result<Url, String>, ctx: &str) {
        if v["err"].as_bool().unwrap() {
            assert!(got.is_err(), "{ctx}: accepted, Go refused: {:?}", got.map(|u| u.to_string()));
            return;
        }
        let u = got.unwrap_or_else(|e| panic!("{ctx}: refused ({e}), Go accepted"));
        let s = |k: &str| v[k].as_str().unwrap_or("").to_string();
        assert_eq!(u.to_string(), s("string"), "{ctx} String");
        assert_eq!(u.scheme, s("scheme"), "{ctx} Scheme");
        assert_eq!(u.host, s("host"), "{ctx} Host");
        assert_eq!(u.hostname(), s("hostname"), "{ctx} Hostname");
        assert_eq!(u.path, s("path"), "{ctx} Path");
        assert_eq!(u.raw_query, s("raw_query"), "{ctx} RawQuery");
        assert_eq!(u.fragment, s("fragment"), "{ctx} Fragment");
        assert_eq!(super::super::local_path(&u), s("local_path"), "{ctx} localPath");
        assert_eq!(super::super::key(&u), s("key"), "{ctx} key");
    }

    #[test]
    fn parse_matches_go() {
        for v in vectors()["parse"].as_array().unwrap() {
            let input = v["input"].as_str().unwrap();
            check(v, Url::parse(input), &format!("Parse({input:?})"));
        }
    }

    #[test]
    fn resolve_matches_go() {
        for v in vectors()["resolve"].as_array().unwrap() {
            let (b, r) = (v["base"].as_str().unwrap(), v["ref"].as_str().unwrap());
            let base = Url::parse(b).unwrap();
            check(&v["result"], base.join(r), &format!("{b:?}.Parse({r:?})"));
        }
    }

    #[test]
    fn query_escape_matches_go() {
        for (k, want) in vectors()["query_escape"].as_object().unwrap() {
            assert_eq!(query_escape(k), want.as_str().unwrap());
        }
    }
}
