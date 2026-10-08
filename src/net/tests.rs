// SPDX-License-Identifier: GPL-3.0-or-later

//! Network tests against local HTTP fixtures; nothing leaves 127.0.0.1.

use super::*;
use crate::crypto::kem::{Identity, SUITE_ID};
use crate::pipeline::Pool;
use std::io::BufRead;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

/// What a fixture handler sends back for a request.
enum Reply {
    /// Status line text, headers, body; Content-Length is added.
    Full(&'static str, Vec<(String, String)>, Vec<u8>),
    /// Raw bytes, then the connection closes.
    Raw(Vec<u8>),
    /// Headers then a stall.
    Stall,
}

struct Server {
    addr: String,
}

impl Server {
    /// Serves `handler(path, user_agent)` on 127.0.0.1, one thread per
    /// connection, for the life of the test process.
    fn start(handler: impl Fn(&str, &str) -> Reply + Send + Sync + 'static) -> Server {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let handler = Arc::new(handler);
        std::thread::spawn(move || {
            for c in l.incoming().flatten() {
                let h = Arc::clone(&handler);
                std::thread::spawn(move || serve(c, &*h));
            }
        });
        Server { addr }
    }

    fn url(&self, p: &str) -> String {
        format!("http://{}{p}", self.addr)
    }
}

fn serve(mut c: TcpStream, h: &dyn Fn(&str, &str) -> Reply) {
    let mut r = std::io::BufReader::new(c.try_clone().unwrap());
    let mut line = String::new();
    if r.read_line(&mut line).is_err() {
        return;
    }
    let path = line.split(' ').nth(1).unwrap_or("/").to_string();
    let mut ua = String::new();
    loop {
        let mut l = String::new();
        if r.read_line(&mut l).unwrap_or(0) == 0 || l == "\r\n" {
            break;
        }
        if let Some(v) = l.strip_prefix("user-agent: ").or_else(|| l.strip_prefix("User-Agent: ")) {
            ua = v.trim().to_string();
        }
    }
    let out = match h(&path, &ua) {
        Reply::Full(status, headers, body) => {
            let mut o = format!("HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: {}\r\n", body.len());
            for (k, v) in headers {
                o.push_str(&format!("{k}: {v}\r\n"));
            }
            o.push_str("\r\n");
            [o.into_bytes(), body].concat()
        }
        Reply::Raw(b) => b,
        Reply::Stall => {
            let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nabc");
            std::thread::sleep(Duration::from_secs(5));
            return;
        }
    };
    let _ = c.write_all(&out);
}

fn ok(ct: &str, body: &str) -> Reply {
    let headers = if ct.is_empty() {
        vec![]
    } else {
        vec![("Content-Type".to_string(), ct.to_string())]
    };
    Reply::Full("200 OK", headers, body.as_bytes().to_vec())
}

fn not_found() -> Reply {
    Reply::Full("404 Not Found", vec![], b"no".to_vec())
}

fn redirect(to: &str) -> Reply {
    Reply::Full("302 Found", vec![("Location".into(), to.into())], vec![])
}

struct Vault {
    dir: PathBuf,
    store: Store,
}

impl Drop for Vault {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn vault() -> Vault {
    let r: [u8; 8] = crate::rng::os().array();
    let dir = std::env::temp_dir().join(format!("vault-net-{}-{}", std::process::id(), crate::store::hex(&r)));
    std::fs::create_dir_all(&dir).unwrap();
    let root = dir.join("store");
    let pool = Arc::new(Pool::new(2));
    Store::init(&root, 0, Arc::clone(&pool)).unwrap();
    let store = Store::open(&root, Identity::from_suite_seed(SUITE_ID, &[1; 32]).unwrap(), pool).unwrap();
    Vault { dir, store }
}

impl Vault {
    fn get(&self, name: &str) -> Vec<u8> {
        let cat = self.store.catalogue().unwrap();
        let rec = cat
            .current(name)
            .unwrap_or_else(|| panic!("{name} not stored; have {:?}", cat.names().collect::<Vec<_>>()));
        let out = format!("out-{}", rec.id.hex());
        self.store
            .extract(rec, &crate::platform::fs::Dir::open(&self.dir).unwrap(), std::ffi::OsStr::new(&out))
            .unwrap();
        std::fs::read(self.dir.join(out)).unwrap()
    }

    fn names(&self) -> Vec<String> {
        self.store.catalogue().unwrap().names().map(String::from).collect()
    }
}

fn mirror_with(v: &Vault, url: &str, limits: &Limits) -> MirrorOutcome {
    let mut cat = v.store.catalogue().unwrap();
    mirror(&v.store, &mut cat, url, "m", limits, &mut |_, _| {}).unwrap()
}

/// Staged downloads leave no name behind on Unix (unlinked at creation),
/// and are removed on drop elsewhere — so counting files in the shared
/// temp directory, which other tests use concurrently, is never needed.
#[test]
fn temp_files_leave_nothing_behind() {
    let mut t = TempFile::new("vault-test-").unwrap();
    let path = t.path.clone();
    t.file().write_all(b"plaintext").unwrap();
    #[cfg(unix)]
    assert!(!path.exists(), "the name should be gone at once");
    drop(t);
    assert!(!path.exists());
}

#[test]
fn add_url_names_and_user_agent() {
    let srv = Server::start(|p, ua| {
        if ua != CHROME_UA {
            return Reply::Full("403 Forbidden", vec![], b"bad agent".to_vec());
        }
        match p {
            "/files/page.html" => Reply::Full(
                "200 OK",
                vec![("Last-Modified".into(), "Tue, 15 Nov 1994 08:12:31 GMT".into())],
                b"body".to_vec(),
            ),
            "/old" => redirect("/files/new.txt"),
            "/files/new.txt" => ok("", "moved"),
            "/" => ok("", "root"),
            _ => not_found(),
        }
    });
    let v = vault();
    let mut cat = v.store.catalogue().unwrap();
    let mut reported = Vec::new();
    let lim = Limits::add_defaults();
    add_url(&v.store, &mut cat, &srv.url("/files/page.html"), "web", &lim, &mut |n, r| {
        reported.push((n.to_string(), r))
    })
    .unwrap();
    add_url(&v.store, &mut cat, &srv.url("/old"), "web", &lim, &mut |n, r| {
        reported.push((n.to_string(), r))
    })
    .unwrap();
    add_url(&v.store, &mut cat, &srv.url(""), "", &lim, &mut |n, r| {
        reported.push((n.to_string(), r))
    })
    .unwrap();
    assert_eq!(
        reported,
        [
            ("web/page.html".into(), false),
            ("web/new.txt".into(), false),
            ("127.0.0.1".into(), false)
        ]
    );
    assert_eq!(v.get("web/page.html"), b"body");
    assert_eq!(v.get("web/new.txt"), b"moved", "named after the final URL");
    assert_eq!(
        v.store.catalogue().unwrap().current("web/page.html").unwrap().modified.secs,
        784887151
    );
    let e = add_url(&v.store, &mut cat, &srv.url("/missing"), "", &lim, &mut |_, _| {}).unwrap_err();
    assert!(e.msg.ends_with("404 Not Found"), "{e}");
}

#[test]
fn add_url_limits() {
    let gz = {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        e.write_all(&vec![b'a'; 1 << 20]).unwrap();
        e.finish().unwrap()
    };
    let srv = Server::start(move |p, _| match p {
        "/stall" => Reply::Stall,
        "/long" => Reply::Raw(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabcdefgh".to_vec()),
        "/short" => Reply::Raw(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\nabc".to_vec()),
        "/bomb" => Reply::Full("200 OK", vec![("Content-Encoding".into(), "gzip".into())], gz.clone()),
        "/loop" => redirect("/loop"),
        "/big" => ok("", &"x".repeat(5000)),
        _ => not_found(),
    });
    let v = vault();
    let mut cat = v.store.catalogue().unwrap();
    let small = Limits {
        request: Duration::from_secs(2),
        max_bytes: 4096,
        ..Limits::add_defaults()
    };
    let mut try_add = |p: &str| add_url(&v.store, &mut cat, &srv.url(p), "", &small, &mut |_, _| {});
    let e = try_add("/stall").unwrap_err();
    assert!(e.msg.contains("timeout") || e.msg.contains("timed out"), "{e}");
    // A server sending more than it declared is cut at its Content-Length.
    try_add("/long").unwrap();
    assert!(try_add("/short").is_err(), "a body shorter than declared is an error");
    let e = try_add("/bomb").unwrap_err();
    assert!(e.msg.contains("exceeds 4096 bytes"), "decoded bytes count: {e}");
    let e = try_add("/loop").unwrap_err();
    assert!(e.msg.contains("stopped after 10 redirects"), "{e}");
    assert!(try_add("/big").unwrap_err().msg.contains("exceeds"));
    assert_eq!(v.get("long"), b"abc");
    assert_eq!(v.names(), ["long"], "nothing else stored");
}

/// A redirect to /%2e%2e must not name the download "..", which would
/// replace the folder's parent entry.
#[test]
fn add_url_dot_names_fall_back_to_host() {
    let srv = Server::start(|p, _| match p {
        "/up" => redirect("/%2e%2e"),
        "/.." | "/%2e%2e" => ok("", "dots"),
        _ => not_found(),
    });
    let v = vault();
    let mut cat = v.store.catalogue().unwrap();
    let mut got = Vec::new();
    add_url(&v.store, &mut cat, &srv.url("/up"), "a/b", &Limits::add_defaults(), &mut |n, _| {
        got.push(n.to_string())
    })
    .unwrap();
    assert_eq!(got, ["a/b/127.0.0.1"]);
}

/// Bytes received before a failure still count against the mirror budget.
#[test]
fn mirror_charges_failed_downloads() {
    let server = Server::start(|p, _| match p {
        "/" => ok("text/html", r#"<a href="/1">1</a><a href="/2">2</a>"#),
        "/1" => {
            let mut b = b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\nConnection: close\r\n\r\n".to_vec();
            b.extend_from_slice(&[b'y'; 2000]);
            Reply::Raw(b)
        }
        "/2" => ok("", &"z".repeat(1000)),
        _ => not_found(),
    });
    let v = vault();
    let lim = Limits {
        max_bytes: 2500,
        ..Limits::mirror_defaults()
    };
    match mirror_with(&v, &server.url("/"), &lim) {
        MirrorOutcome::Partial { stored: 1, skipped: 2 } => {}
        MirrorOutcome::Partial { stored, skipped } => panic!("stored {stored}, skipped {skipped}"),
        MirrorOutcome::Complete { .. } => panic!("truncated body not charged"),
    }
}

/// Links that decode to "." or ".." segments never escape the mirror's
/// folder, and rewritten links are escaped.
#[test]
fn mirror_refuses_escaping_paths() {
    let srv = Arc::new(std::sync::OnceLock::<String>::new());
    let s2 = Arc::clone(&srv);
    let server = Server::start(move |p, _| {
        let h = s2.get().unwrap().trim_start_matches("http:").to_string();
        match p {
            "/" => ok(
                "text/html",
                &format!(r#"<a href="/%2e%2e/x">a</a><a href="{h}/..%2f..%2fq">b</a><a href="/a%3Fb">c</a><a href="/c:d">d</a>"#),
            ),
            "/a%3Fb" | "/c:d" => ok("", "fine"),
            _ => ok("", "should never be stored"),
        }
    });
    srv.set(server.url("")).unwrap();
    let v = vault();
    let out = mirror_with(&v, &server.url("/"), &Limits::mirror_defaults());
    assert!(matches!(out, MirrorOutcome::Partial { stored: 3, skipped: 2 }), "{:?}", v.names());
    let h = &server.addr;
    for n in v.names() {
        assert!(n.starts_with(&format!("m/{h}/")), "stored outside the mirror: {n}");
    }
    let index = String::from_utf8(v.get(&format!("m/{h}/index.html"))).unwrap();
    assert!(index.contains(r#"href="a%3Fb""#), "{index}");
    assert!(index.contains(r#"href="./c:d""#), "{index}");
    assert!(index.contains(r#"href="/%2e%2e/x""#), "unsafe links are left as they were: {index}");
}

/// A deeply nested page full of links to the root cannot make the rewrite
/// balloon: past four times the rewrite limit, the page is skipped.
#[test]
fn mirror_bounds_rewrite_growth() {
    let deep = format!("/{}p.html", "d/".repeat(40));
    let page = format!("<style>{}</style>", "a{b:url(/)}".repeat(80));
    let server = Server::start(move |p, _| match p {
        "/" => ok("text/html", "root"),
        _ => ok("text/html", &page),
    });
    let v = vault();
    let lim = Limits {
        max_text: 1000,
        ..Limits::mirror_defaults()
    };
    assert!(matches!(
        mirror_with(&v, &server.url(&deep), &lim),
        MirrorOutcome::Partial { stored: 0, skipped: 1 }
    ));
}

/// Go's TestMirror: links in HTML and CSS become relative, off-host links
/// stay, everything lands under host/.
#[test]
fn mirror_like_go() {
    let srv = Arc::new(std::sync::OnceLock::<String>::new());
    let s2 = Arc::clone(&srv);
    let server = Server::start(move |p, ua| {
        if ua != CHROME_UA {
            return Reply::Full("403 Forbidden", vec![], vec![]);
        }
        let base = s2.get().unwrap();
        match p {
            "/" => ok(
                "text/html",
                &format!(r#"<a href="{base}/sub/p.html#x">p</a> <a href="https://elsewhere.example/">e</a> <link href='/s.css'>"#),
            ),
            "/sub/p.html" => ok("text/html", r#"<a href="/">home</a> <img src="../img/a.png">"#),
            "/s.css" => ok("text/css", "body{background:url(/img/a.png)}"),
            "/img/a.png" => ok("", "png"),
            _ => not_found(),
        }
    });
    srv.set(server.url("")).unwrap();
    let v = vault();
    let out = mirror_with(&v, &server.url(""), &Limits::mirror_defaults());
    assert!(matches!(out, MirrorOutcome::Complete { stored: 4 }));
    let h = &server.addr;
    for (name, want) in [
        (
            format!("m/{h}/index.html"),
            r#"<a href="sub/p.html#x">p</a> <a href="https://elsewhere.example/">e</a> <link href='s.css'>"#,
        ),
        (
            format!("m/{h}/sub/p.html"),
            r#"<a href="../index.html">home</a> <img src="../img/a.png">"#,
        ),
        (format!("m/{h}/s.css"), "body{background:url(img/a.png)}"),
        (format!("m/{h}/img/a.png"), "png"),
    ] {
        assert_eq!(String::from_utf8(v.get(&name)).unwrap(), want, "{name}");
    }
}

#[test]
fn mirror_policies() {
    let srv = Arc::new(std::sync::OnceLock::<String>::new());
    let s2 = Arc::clone(&srv);
    let server = Server::start(move |p, _| {
        let other = s2.get().unwrap().replace("127.0.0.1", "localhost");
        match p {
            "/" => ok(
                "text/html",
                r#"<head><base href="/d/"></head><a href=a.html>a</a> <a href="/away">x</a> <a href="/a_b%253Dc">c</a> <a href="/a?b=c">q</a>
<script>var s = '<a href="/never">';</script><!-- <a href="/never2"> --><div style="background:url('/i.png')"><style>p{background:url("/j.png")}</style>"#,
            ),
            "/d/a.html" => ok("text/html", "<p>a</p>"),
            "/away" => redirect(&format!("{other}/elsewhere")),
            "/a_b%253Dc" => ok("", "literal"),
            "/a?b=c" => ok("", "query"),
            "/i.png" | "/j.png" => ok("", "img"),
            _ => not_found(),
        }
    });
    srv.set(server.url("")).unwrap();
    let v = vault();
    let out = mirror_with(&v, &server.url("/"), &Limits::mirror_defaults());
    // /away (off-host redirect) and one of the colliding names are skipped.
    match out {
        MirrorOutcome::Partial { skipped: 2, stored: 5 } => {}
        MirrorOutcome::Partial { stored, skipped } => panic!("stored {stored}, skipped {skipped}: {:?}", v.names()),
        MirrorOutcome::Complete { stored } => panic!("complete, stored {stored}"),
    }
    let h = &server.addr;
    let index = String::from_utf8(v.get(&format!("m/{h}/index.html"))).unwrap();
    assert!(index.contains(r#"<base href="index.html">"#), "{index}");
    assert!(index.contains("<a href=d/a.html>"), "base href honoured, unquoted kept: {index}");
    assert!(
        index.contains(r#"'<a href="/never">'"#) && index.contains(r#"<!-- <a href="/never2"> -->"#),
        "{index}"
    );
    assert!(index.contains("url('i.png')") && index.contains(r#"url("j.png")"#), "{index}");
    let names = v.names();
    assert!(names.contains(&format!("m/{h}/d/a.html")));
    assert!(!names.iter().any(|n| n.contains("never") || n.contains("elsewhere")), "{names:?}");
    let collided = [format!("m/{h}/a_b%3Dc")];
    assert_eq!(
        names.iter().filter(|n| collided.contains(n)).count(),
        1,
        "one of two URLs owns the name"
    );
    let kept = String::from_utf8(v.get(&collided[0])).unwrap();
    assert!(kept == "literal" || kept == "query");
}

#[test]
fn mirror_budgets() {
    let server = Server::start(|p, _| match p {
        "/" => ok("text/html", r#"<a href="/1">1</a><a href="/2">2</a><a href="/3">3</a>"#),
        "/1" | "/2" | "/3" => ok("", &"z".repeat(1000)),
        _ => not_found(),
    });
    let v = vault();
    let pages = Limits {
        max_pages: 2,
        ..Limits::mirror_defaults()
    };
    match mirror_with(&v, &server.url("/"), &pages) {
        MirrorOutcome::Partial { stored: 2, .. } => {}
        _ => panic!("page limit not applied"),
    }
    let v = vault();
    let bytes = Limits {
        max_bytes: 1500,
        ..Limits::mirror_defaults()
    };
    match mirror_with(&v, &server.url("/"), &bytes) {
        MirrorOutcome::Partial { stored: 2, skipped: 2 } => {}
        MirrorOutcome::Partial { stored, skipped } => panic!("byte budget: stored {stored}, skipped {skipped}"),
        MirrorOutcome::Complete { .. } => panic!("byte budget not applied"),
    }
    let v = vault();
    let text = Limits {
        max_text: 10,
        ..Limits::mirror_defaults()
    };
    assert!(matches!(
        mirror_with(&v, &server.url("/"), &text),
        MirrorOutcome::Partial { stored: 0, skipped: 1 }
    ));
}

#[test]
fn relative_matches_go() {
    for r in url::tests::vectors()["relative"].as_array().unwrap() {
        let r = r.as_array().unwrap();
        assert_eq!(
            relative(r[0].as_str().unwrap(), r[1].as_str().unwrap()),
            r[2].as_str().unwrap(),
            "{r:?}"
        );
    }
}

#[test]
fn http_time_matches_go() {
    for (s, want) in url::tests::vectors()["http_time"].as_object().unwrap() {
        assert_eq!(parse_http_time(s), want.as_i64(), "{s:?}");
    }
}

#[test]
fn proxy_rules() {
    let u = |s: &str| Url::parse(s).unwrap();
    assert!(!use_proxy(&u("http://localhost:8080/"), ""));
    assert!(!use_proxy(&u("http://127.0.0.1/"), ""));
    assert!(!use_proxy(&u("http://[::1]/"), ""));
    assert!(!use_proxy(&u("http://[::ffff:127.0.0.1]/"), ""));
    assert_eq!(
        u("http://user:secret@h/x").redacted(),
        "http://h/x",
        "credentials stay out of messages"
    );
    assert!(use_proxy(&u("http://example.com/"), "other.com"));
    assert!(!use_proxy(&u("http://example.com/"), "example.com"));
    assert!(!use_proxy(&u("http://a.example.com/"), "example.com"));
    assert!(use_proxy(&u("http://example.com/"), ".example.com"));
    assert!(!use_proxy(&u("http://a.example.com/"), "*.example.com"));
    assert!(!use_proxy(&u("http://x.com/"), "*"));
    assert!(use_proxy(&u("http://x.com:81/"), "x.com:80"));
    assert!(!use_proxy(&u("http://x.com/"), "x.com:80"));
    assert!(!use_proxy(&u("https://10.1.2.3/"), "10.0.0.0/8"));
    assert!(use_proxy(&u("https://11.1.2.3/"), "10.0.0.0/8, 192.168.1.1"));
    assert!(!use_proxy(&u("https://192.168.1.1/"), "10.0.0.0/8, 192.168.1.1"));
}
