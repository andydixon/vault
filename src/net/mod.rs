// SPDX-License-Identifier: GPL-3.0-or-later

//! Network import: `add URL` and `mirror`.
//!
//! Every request goes through one explicit client: TLS certificates are
//! always verified against the platform's roots, redirects are followed by
//! hand (http and https only, at most [`Limits::max_redirects`], and for
//! `mirror` only within the starting host), and every body is counted
//! after decompression against a byte budget — `Content-Length` is never
//! trusted. Proxies follow Go's `ProxyFromEnvironment`: `HTTPS_PROXY` for
//! https, `HTTP_PROXY` for http (ignored under CGI, when `REQUEST_METHOD`
//! is set), `NO_PROXY` exclusions, and never for localhost or loopback.
//!
//! Defaults (all overridable from the command line, the byte budget never
//! above the 1 TiB file limit):
//!
//! | limit                  | `add URL` | `mirror`        |
//! |------------------------|-----------|-----------------|
//! | connect                | 30 s      | 30 s            |
//! | response headers       | 60 s      | 60 s            |
//! | whole request          | 2 h       | 5 min each      |
//! | bytes                  | 16 GiB    | 4 GiB in total  |
//! | redirects per request  | 10        | 10              |
//! | pages                  | —         | 10 000          |
//! | HTML/CSS held to rewrite | —       | 16 MiB per page |
//!
//! Downloads that are not rewritten are streamed to a private (0600)
//! temporary file, because the vault needs a file's size before storing
//! it; that file holds plaintext until it is removed, on every path, once
//! stored. HTML and CSS for rewriting are held in memory instead.

pub mod html;
pub mod url;

#[cfg(test)]
mod tests;

use crate::error::{Error, Result};
use crate::store::{Catalogue, FILE_LIMIT, Store, VaultName};
use crate::util::Instant;
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::Duration;
pub use url::Url;

pub const CHROME_UA: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";

#[derive(Clone, Debug)]
pub struct Limits {
    pub connect: Duration,
    /// Until the response headers have arrived.
    pub response: Duration,
    /// End to end, body included, for each request.
    pub request: Duration,
    /// Body bytes: per download for `add`, in total for `mirror`.
    pub max_bytes: u64,
    pub max_redirects: u32,
    pub max_pages: u64,
    /// Largest HTML or CSS document held in memory for rewriting.
    pub max_text: u64,
}

impl Limits {
    pub fn add_defaults() -> Limits {
        Limits {
            connect: Duration::from_secs(30),
            response: Duration::from_secs(60),
            request: Duration::from_secs(2 * 3600),
            max_bytes: 16 << 30,
            max_redirects: 10,
            max_pages: 1,
            max_text: 16 << 20,
        }
    }

    pub fn mirror_defaults() -> Limits {
        Limits {
            request: Duration::from_secs(300),
            max_bytes: 4 << 30,
            max_pages: 10_000,
            ..Limits::add_defaults()
        }
    }
}

pub fn is_url(s: &str) -> bool {
    s.starts_with("https://") || s.starts_with("http://")
}

/// Why a fetch failed: the byte budget ends a mirror, anything else only
/// skips one resource.
enum FetchError {
    Budget(u64),
    Other(String),
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchError::Budget(n) => write!(f, "download exceeds {n} bytes"),
            FetchError::Other(m) => f.write_str(m),
        }
    }
}

impl From<String> for FetchError {
    fn from(s: String) -> Self {
        FetchError::Other(s)
    }
}

type Response = ureq::http::Response<ureq::Body>;

struct Client {
    limits: Limits,
    agents: HashMap<Option<String>, ureq::Agent>,
}

impl Client {
    fn new(limits: &Limits) -> Client {
        Client {
            limits: limits.clone(),
            agents: HashMap::new(),
        }
    }

    fn agent(&mut self, proxy: Option<String>) -> std::result::Result<&ureq::Agent, String> {
        if !self.agents.contains_key(&proxy) {
            let p = match &proxy {
                Some(p) => Some(ureq::Proxy::new(p).map_err(|e| format!("invalid proxy {p:?}: {e}"))?),
                None => None,
            };
            let tls = ureq::tls::TlsConfig::builder()
                .root_certs(ureq::tls::RootCerts::PlatformVerifier)
                .build();
            let l = &self.limits;
            let cfg = ureq::Agent::config_builder()
                .tls_config(tls)
                .proxy(p)
                .max_redirects(0)
                .http_status_as_error(false)
                .user_agent(CHROME_UA)
                .timeout_connect(Some(l.connect))
                .timeout_recv_response(Some(l.response))
                .timeout_global(Some(l.request))
                .build();
            self.agents.insert(proxy.clone(), cfg.into());
        }
        Ok(&self.agents[&proxy])
    }

    /// GETs `u`, following redirects; with `host`, every hop must stay on
    /// it. Returns the final URL and its response, whatever the status.
    fn get(&mut self, u: &Url, host: Option<&str>) -> std::result::Result<(Url, Response), String> {
        let mut cur = u.clone();
        for hop in 0..=self.limits.max_redirects {
            if cur.scheme != "http" && cur.scheme != "https" {
                return Err(format!("unsupported protocol scheme {:?}", cur.scheme));
            }
            let agent = self.agent(proxy_for(&cur))?;
            let resp = agent.get(cur.to_string()).call().map_err(|e| e.to_string())?;
            let code = resp.status().as_u16();
            let location = resp.headers().get("location").and_then(|v| v.to_str().ok()).map(str::to_string);
            match (code, location) {
                (301 | 302 | 303 | 307 | 308, Some(loc)) => {
                    if hop == self.limits.max_redirects {
                        return Err(format!("stopped after {} redirects", self.limits.max_redirects));
                    }
                    cur = cur.join(&loc).map_err(|e| format!("bad redirect location {loc:?}: {e}"))?;
                    if host.is_some_and(|h| cur.host.to_lowercase() != h) {
                        return Err(format!("redirected to another host: {cur}"));
                    }
                }
                _ => return Ok((cur, resp)),
            }
        }
        unreachable!("the loop returns on its last hop")
    }
}

fn status_error(resp: &Response) -> Option<String> {
    let s = resp.status();
    (s.as_u16() != 200).then(|| {
        format!("{} {}", s.as_u16(), s.canonical_reason().unwrap_or(""))
            .trim_end()
            .to_string()
    })
}

/// Copies at most `budget` decoded body bytes to `dst`; returns the count.
fn copy_body(resp: &mut Response, dst: &mut dyn Write, budget: u64) -> std::result::Result<u64, FetchError> {
    let mut r = resp.body_mut().with_config().limit(u64::MAX).reader();
    let mut buf = vec![0u8; 64 << 10];
    let mut n = 0u64;
    loop {
        let k = match r.read(&mut buf) {
            Ok(0) => return Ok(n),
            Ok(k) => k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(FetchError::Other(crate::util::io_reason(&e))),
        };
        n += k as u64;
        if n > budget {
            return Err(FetchError::Budget(budget));
        }
        dst.write_all(&buf[..k])
            .map_err(|e| FetchError::Other(crate::util::io_reason(&e)))?;
    }
}

/// A private temporary file, removed when dropped.
struct TempFile {
    file: Option<std::fs::File>,
    path: PathBuf,
}

impl TempFile {
    fn new(prefix: &str) -> Result<TempFile> {
        let dir = std::env::temp_dir();
        let (file, path) = crate::platform::fs::create_temp(&dir, prefix).map_err(|e| Error::io("create temporary file in", &dir, &e))?;
        Ok(TempFile { file: Some(file), path })
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        drop(self.file.take());
        let _ = std::fs::remove_file(&self.path);
    }
}

fn vault_name(dest: &str, name: &str) -> Result<VaultName> {
    let joined = crate::util::join(&[dest, name]);
    VaultName::new(&joined).ok_or_else(|| Error::new(format!("invalid vault path {joined:?}")))
}

/// Downloads `url` and stores it beneath `dest`, named after the last
/// element of the final (post-redirect) URL's path, or its host name.
pub fn add_url(
    store: &Store,
    cat: &mut Catalogue,
    url: &str,
    dest: &str,
    limits: &Limits,
    report: &mut dyn FnMut(&VaultName, bool),
) -> Result<()> {
    let u = Url::parse(url).map_err(|e| Error::new(format!("{url}: {e}")))?;
    let mut client = Client::new(limits);
    let (fin, mut resp) = client.get(&u, None).map_err(|e| Error::new(format!("{url}: {e}")))?;
    if let Some(e) = status_error(&resp) {
        crate::bail!("{url}: {e}");
    }
    let mut name = crate::util::base(&fin.path);
    if name == "/" || name == "." {
        name = fin.hostname().to_string();
    }
    let vn = vault_name(dest, &name)?;
    let mut tmp = TempFile::new("vault-download-")?;
    let f = tmp.file.as_mut().expect("open");
    copy_body(&mut resp, f, limits.max_bytes.min(FILE_LIMIT)).map_err(|e| Error::new(format!("{url}: {e}")))?;
    if let Some(t) = resp
        .headers()
        .get("last-modified")
        .and_then(|v| v.to_str().ok())
        .and_then(parse_http_time)
    {
        let t = Instant { secs: t, nanos: 0 }.to_system();
        let _ = f.set_times(std::fs::FileTimes::new().set_accessed(t).set_modified(t));
    }
    drop(tmp.file.take());
    let (added, _) = store.add_file(cat, &tmp.path, &vn)?;
    report(&vn, added.replaced);
    Ok(())
}

pub enum MirrorOutcome {
    Complete { stored: u64 },
    Partial { stored: u64, skipped: u64 },
}

/// Where `u` lives inside a mirror, relative to its root (Go's localPath).
pub(crate) fn local_path(u: &Url) -> String {
    let mut p = u.path.strip_prefix('/').unwrap_or(&u.path).to_string();
    if p.is_empty() || p.ends_with('/') {
        p.push_str("index.html");
    }
    if !u.raw_query.is_empty() {
        p.push('_');
        p.push_str(&url::query_escape(&u.raw_query));
    }
    p
}

/// A page's identity, independent of its fragment (Go's key).
pub(crate) fn key(u: &Url) -> String {
    let mut c = u.clone();
    c.clear_fragment();
    c.to_string()
}

/// The link from the file `from` to the file `to`, both relative to the
/// same root (Go's relative).
pub(crate) fn relative(from: &str, to: &str) -> String {
    let dir = crate::util::clean(from.rsplit_once('/').map_or(".", |(d, _)| if d.is_empty() { "/" } else { d }));
    let mut f: Vec<&str> = dir.split('/').collect();
    let mut t: Vec<&str> = to.split('/').collect();
    if f[0] == "." {
        f.clear();
    }
    while !f.is_empty() && t.len() > 1 && f[0] == t[0] {
        f.remove(0);
        t.remove(0);
    }
    format!("{}{}", "../".repeat(f.len()), t.join("/"))
}

struct Crawl<'a> {
    store: &'a Store,
    client: Client,
    host: String,
    root: String,
    seen: HashSet<String>,
    queue: VecDeque<Url>,
    owners: HashMap<String, String>,
    budget: u64,
    max_pages: u64,
    limit_hit: bool,
    max_text: u64,
}

/// Crawls the site at `url`, one request at a time, staying on its host,
/// and stores every page and asset beneath `dest/HOST`. Links in HTML and
/// CSS that point into the mirror are rewritten to relative paths. A
/// resource that fails is reported and skipped.
pub fn mirror(
    store: &Store,
    cat: &mut Catalogue,
    url: &str,
    dest: &str,
    limits: &Limits,
    report: &mut dyn FnMut(&VaultName, bool),
) -> Result<MirrorOutcome> {
    let mut start = Url::parse(url).map_err(|e| Error::new(format!("{url}: {e}")))?;
    if start.scheme != "http" && start.scheme != "https" {
        crate::bail!("mirror needs an http:// or https:// URL");
    }
    if start.path.is_empty() && start.raw_query.is_empty() {
        // The same page as a link to "/" would name.
        start = start.join("/").expect("valid reference");
    }
    let host = start.host.to_lowercase();
    let mut c = Crawl {
        store,
        client: Client::new(limits),
        root: crate::util::join(&[dest, &host]),
        host,
        seen: HashSet::new(),
        queue: VecDeque::new(),
        owners: HashMap::new(),
        budget: limits.max_bytes.min(FILE_LIMIT),
        max_pages: limits.max_pages,
        limit_hit: false,
        max_text: limits.max_text,
    };
    c.enqueue(start);
    let (mut stored, mut skipped) = (0u64, 0u64);
    while let Some(u) = c.queue.pop_front() {
        match c.one(cat, &u, report) {
            Ok(()) => stored += 1,
            Err(FetchError::Budget(n)) => {
                eprintln!("skipping {u}: the mirror's {n}-byte budget is used up");
                skipped += 1 + c.queue.len() as u64;
                c.queue.clear();
            }
            Err(FetchError::Other(e)) => {
                eprintln!("skipping {u}: {e}");
                skipped += 1;
            }
        }
    }
    if c.limit_hit {
        eprintln!("mirror: page limit of {} reached; further links were not followed", c.max_pages);
        skipped += 1;
    }
    Ok(if skipped == 0 {
        MirrorOutcome::Complete { stored }
    } else {
        MirrorOutcome::Partial { stored, skipped }
    })
}

impl Crawl<'_> {
    fn enqueue(&mut self, u: Url) {
        let k = key(&u);
        if self.seen.contains(&k) {
            return;
        }
        if self.seen.len() as u64 >= self.max_pages {
            self.limit_hit = true;
            return;
        }
        self.seen.insert(k);
        self.queue.push_back(u);
    }

    fn one(&mut self, cat: &mut Catalogue, u: &Url, report: &mut dyn FnMut(&VaultName, bool)) -> std::result::Result<(), FetchError> {
        let local = local_path(u);
        let k = key(u);
        match self.owners.get(&local) {
            Some(owner) if *owner != k => return Err(format!("its local name {local} is already used by {owner}").into()),
            _ => {
                self.owners.insert(local.clone(), k);
            }
        }
        let name = vault_name(&self.root, &local).map_err(|e| e.msg)?;
        let (fin, mut resp) = self.client.get(u, Some(&self.host))?;
        if let Some(e) = status_error(&resp) {
            return Err(e.into());
        }
        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_lowercase();
        let (is_html, is_css) = (ct.starts_with("text/html"), ct.starts_with("text/css"));
        let added = if is_html || is_css {
            let mut body = Vec::new();
            let cap = self.budget.min(self.max_text);
            let n = copy_body(&mut resp, &mut body, cap).map_err(|e| match e {
                FetchError::Budget(_) if cap < self.budget => {
                    FetchError::Other(format!("larger than the {}-byte limit for pages to rewrite", self.max_text))
                }
                e => e,
            })?;
            self.budget -= n;
            let body = self.rewrite(&body, is_html, &fin, &local);
            self.store
                .add_reader(cat, &mut &body[..], body.len() as u64, 0o600, Instant::now(), &name)
                .map_err(|e| FetchError::Other(e.msg))?
        } else {
            let mut tmp = TempFile::new("vault-mirror-").map_err(|e| FetchError::Other(e.msg))?;
            let n = copy_body(&mut resp, tmp.file.as_mut().expect("open"), self.budget)?;
            self.budget -= n;
            drop(tmp.file.take());
            self.store.add_file(cat, &tmp.path, &name).map_err(|e| FetchError::Other(e.msg))?.0
        };
        report(&name, added.replaced);
        Ok(())
    }

    /// Rewrites links that point into the mirror, queueing their targets.
    fn rewrite(&mut self, body: &[u8], is_html: bool, page: &Url, local: &str) -> Vec<u8> {
        let base = std::cell::RefCell::new(page.clone());
        let found = std::cell::RefCell::new(Vec::new());
        let host = self.host.clone();
        let mut link = |v: &str| -> Option<String> {
            let mut l = base.borrow().join(v).ok()?;
            if (l.scheme != "http" && l.scheme != "https") || l.host.to_lowercase() != host {
                return None;
            }
            let frag = l.fragment.clone();
            l.clear_fragment();
            if l.path.is_empty() && l.raw_query.is_empty() {
                l = l.join("/").ok()?;
            }
            let mut r = relative(local, &local_path(&l));
            found.borrow_mut().push(l);
            if !frag.is_empty() {
                r.push('#');
                r.push_str(&frag);
            }
            Some(r)
        };
        let out = if is_html {
            let mut on_base = |v: &str| -> Option<String> {
                let b = base.borrow().join(v).ok()?;
                let same = (b.scheme == "http" || b.scheme == "https") && b.host.to_lowercase() == host;
                *base.borrow_mut() = b;
                // Point the copy's base at the page itself, so the relative
                // links written here resolve as intended.
                same.then(|| relative(local, local))
            };
            html::rewrite_html(body, &mut on_base, &mut link)
        } else {
            html::rewrite_css(body, false, &mut link)
        };
        for l in found.into_inner() {
            self.enqueue(l);
        }
        out
    }
}

/// Go's `ProxyFromEnvironment`: the proxy URL for `u`, if any.
fn proxy_for(u: &Url) -> Option<String> {
    let env = |names: &[&str]| names.iter().find_map(|n| std::env::var(n).ok().filter(|v| !v.is_empty()));
    let proxy = if u.scheme == "https" {
        env(&["HTTPS_PROXY", "https_proxy"])
    } else if std::env::var_os("REQUEST_METHOD").is_some() {
        None
    } else {
        env(&["HTTP_PROXY", "http_proxy"])
    }?;
    if !use_proxy(u, env(&["NO_PROXY", "no_proxy"]).as_deref().unwrap_or("")) {
        return None;
    }
    Some(if proxy.contains("://") { proxy } else { format!("http://{proxy}") })
}

/// Whether `u` should go through a proxy given `no_proxy` (Go's
/// httpproxy semantics).
fn use_proxy(u: &Url, no_proxy: &str) -> bool {
    let host = u.hostname().to_lowercase();
    let port = u.port_or_default();
    if host == "localhost" {
        return false;
    }
    let ip: Option<std::net::IpAddr> = host.parse().ok();
    if ip.is_some_and(|ip| ip.is_loopback()) {
        return false;
    }
    for entry in no_proxy.split(',').map(|e| e.trim().to_lowercase()).filter(|e| !e.is_empty()) {
        if entry == "*" {
            return false;
        }
        if let Some((net, bits)) = entry.split_once('/') {
            if let (Ok(net), Ok(bits), Some(ip)) = (net.parse::<std::net::IpAddr>(), bits.parse::<u32>(), ip)
                && in_cidr(ip, net, bits)
            {
                return false;
            }
            continue;
        }
        if let Ok(eip) = entry.trim_start_matches('[').trim_end_matches(']').parse::<std::net::IpAddr>() {
            if ip == Some(eip) {
                return false;
            }
            continue;
        }
        let (mut phost, pport) = match entry.rsplit_once(':') {
            Some((h, p)) if !h.is_empty() && p.bytes().all(|c| c.is_ascii_digit()) => (h.to_string(), Some(p)),
            _ => (entry.clone(), None),
        };
        if let Some(rest) = phost.strip_prefix("*.") {
            phost = format!(".{rest}");
        }
        let match_host = !phost.starts_with('.');
        if match_host {
            phost.insert(0, '.');
        }
        if (host.ends_with(&phost) || (match_host && host == phost[1..])) && pport.is_none_or(|p| p == port) {
            return false;
        }
    }
    true
}

fn in_cidr(ip: std::net::IpAddr, net: std::net::IpAddr, bits: u32) -> bool {
    let (a, b, width): (u128, u128, u32) = match (ip, net) {
        (std::net::IpAddr::V4(a), std::net::IpAddr::V4(b)) => (u32::from(a) as u128, u32::from(b) as u128, 32),
        (std::net::IpAddr::V6(a), std::net::IpAddr::V6(b)) => (u128::from(a), u128::from(b), 128),
        _ => return false,
    };
    if bits > width {
        return false;
    }
    let shift = width - bits;
    shift >= width || (a >> shift) == (b >> shift)
}

/// Go's `http.ParseTime`: RFC 1123 with "GMT", RFC 850, or ANSI C, as Unix
/// seconds.
fn parse_http_time(s: &str) -> Option<i64> {
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    const DAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    const LONG: [&str; 7] = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
    let month = |m: &str| MONTHS.iter().position(|x| *x == m).map(|i| i as i64 + 1);
    let num = |t: &str, n: usize| {
        (t.len() == n && t.bytes().all(|c| c.is_ascii_digit()))
            .then(|| t.parse::<i64>().ok())
            .flatten()
    };
    let clock = |t: &str| -> Option<i64> {
        let p: Vec<&str> = t.split(':').collect();
        let (h, m, s) = (num(p.first()?, 2)?, num(p.get(1)?, 2)?, num(p.get(2)?, 2)?);
        (p.len() == 3 && h < 24 && m < 60 && s < 60).then_some(h * 3600 + m * 60 + s)
    };
    let date = |y: i64, mo: i64, d: i64| -> Option<i64> {
        let dim = [
            31,
            if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 { 29 } else { 28 },
            31,
            30,
            31,
            30,
            31,
            31,
            30,
            31,
            30,
            31,
        ];
        (d >= 1 && d <= dim[(mo - 1) as usize]).then(|| days_from_civil(y, mo, d) * 86400)
    };
    // Mon, 02 Jan 2006 15:04:05 GMT
    if let Some(rest) = s.get(..5).filter(|d| DAYS.contains(&&d[..3]) && &d[3..] == ", ").map(|_| &s[5..]) {
        let p: Vec<&str> = rest.split(' ').collect();
        if p.len() == 5 && p[4] == "GMT" {
            return Some(date(num(p[2], 4)?, month(p[1])?, num(p[0], 2)?)? + clock(p[3])?);
        }
        return None;
    }
    // Monday, 02-Jan-06 15:04:05 MST
    if let Some((day, rest)) = s.split_once(", ") {
        if !LONG.contains(&day) {
            return None;
        }
        let p: Vec<&str> = rest.split(' ').collect();
        if p.len() != 3 || !(3..=5).contains(&p[2].len()) || !p[2].bytes().all(|c| c.is_ascii_uppercase()) {
            return None;
        }
        let d: Vec<&str> = p[0].split('-').collect();
        if d.len() != 3 {
            return None;
        }
        let yy = num(d[2], 2)?;
        return Some(date(if yy >= 69 { 1900 + yy } else { 2000 + yy }, month(d[1])?, num(d[0], 2)?)? + clock(p[1])?);
    }
    // Mon Jan _2 15:04:05 2006
    let (head, rest) = (s.get(..8)?, s.get(8..)?);
    if !DAYS.contains(&&head[..3]) || &head[3..4] != " " || &head[7..8] != " " {
        return None;
    }
    let mo = month(&head[4..7])?;
    let day = if let Some(r) = rest.strip_prefix(' ') {
        (r, num(r.get(..1)?, 1)?)
    } else {
        (rest, num(rest.get(..2)?, 2)?)
    };
    let (r, d) = (day.0, day.1);
    let after = &r[if rest.starts_with(' ') { 1 } else { 2 }..];
    let p: Vec<&str> = after.strip_prefix(' ')?.split(' ').collect();
    if p.len() != 2 {
        return None;
    }
    Some(date(num(p[1], 4)?, mo, d)? + clock(p[0])?)
}

/// Days since 1970-01-01 of a proleptic Gregorian date.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * ((m + 9) % 12) + 2) / 5 + d - 1;
    era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468
}
