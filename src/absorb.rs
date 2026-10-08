// SPDX-License-Identifier: GPL-3.0-or-later

//! `vault absorb`: add every regular file of a tar archive (optionally
//! gzipped, possibly in several gzip members) read from a stream, each
//! streamed straight into the vault so no plaintext touches the disk.
//! Other entry types, and names that would escape the destination folder,
//! are reported and skipped, as in the Go version.

use crate::error::{Error, Kind, Result};
use crate::store::{Catalogue, Store, VaultName};
use crate::util::{Instant, clean, join};
use std::io::{BufRead, Read};

pub fn absorb(
    store: &Store,
    cat: &mut Catalogue,
    mut input: impl BufRead,
    dest: &str,
    report: &mut dyn FnMut(&VaultName, bool),
) -> Result<()> {
    let gz = input
        .fill_buf()
        .map_err(|e| Error::new(format!("reading archive: {}", crate::util::io_reason(&e))))?
        .starts_with(&[0x1f, 0x8b]);
    let r: Box<dyn Read> = if gz {
        Box::new(flate2::bufread::MultiGzDecoder::new(input))
    } else {
        Box::new(input)
    };
    let mut archive = tar::Archive::new(r);
    let entries = archive
        .entries()
        .map_err(|e| Error::new(format!("reading archive: {}", crate::util::io_reason(&e))))?;
    let mut n = 0u64;
    for entry in entries {
        let mut entry = entry.map_err(|e| Error::new(format!("reading archive: {}", crate::util::io_reason(&e))))?;
        let raw = entry.path_bytes().into_owned();
        let shown = String::from_utf8_lossy(&raw).into_owned();
        let kind = entry.header().entry_type();
        if !kind.is_file() {
            if !kind.is_dir() {
                eprintln!("skipping {shown}: not a regular file");
            }
            continue;
        }
        let Ok(text) = std::str::from_utf8(&raw) else {
            crate::bail!("invalid vault path {shown:?}");
        };
        let Some(rel) = safe_name(text) else {
            eprintln!("skipping {shown}: unsafe name");
            continue;
        };
        let name = join(&[dest, &rel]);
        let name = VaultName::new(&name).ok_or_else(|| Error::new(format!("invalid vault path {name:?}")))?;
        // The entry's size, with a PAX "size" override applied, as Go's
        // hdr.Size; the fixed header field alone would truncate files that
        // Go's archive/tar writes for sizes past 8 GiB.
        let size = entry.size();
        if is_gnu_sparse(&mut entry) {
            eprintln!("skipping {shown}: sparse files are not supported");
            continue;
        }
        let mode = entry.header().mode().unwrap_or(0) & 0o777;
        let mtime = mtime(&mut entry)?;
        match store.add_reader(cat, &mut entry, size, mode, mtime, &name) {
            Ok(a) => report(&name, a.replaced),
            Err(e) if e.kind == Kind::SourceShort => crate::bail!("{shown}: archive ends early"),
            Err(e) => return Err(e),
        }
        n += 1;
    }
    if n == 0 {
        crate::bail!("no files in archive");
    }
    Ok(())
}

/// Go's check: the name, cleaned as if rooted, must equal the name with a
/// leading "./" or "/" removed and cleaned, and contain no backslash.
pub fn safe_name(name: &str) -> Option<String> {
    let rooted = clean(&format!("/{name}"));
    let n = rooted.strip_prefix('/').unwrap_or(&rooted).to_string();
    let plain = name.strip_prefix("./").unwrap_or(name);
    let plain = plain.strip_prefix('/').unwrap_or(plain);
    if name.contains('\\') || n.is_empty() || n != clean(plain) {
        return None;
    }
    Some(n)
}

/// A PAX-format GNU sparse file, whose data is an encoded map, not the
/// file's bytes.
fn is_gnu_sparse<R: Read>(entry: &mut tar::Entry<R>) -> bool {
    if entry.header().entry_type() == tar::EntryType::GNUSparse {
        return true;
    }
    match entry.pax_extensions() {
        Ok(Some(exts)) => exts.flatten().any(|e| e.key_bytes().starts_with(b"GNU.sparse.")),
        _ => false,
    }
}

/// The entry's modification time: the PAX `mtime` (with its fraction) if
/// present, else the header's whole seconds.
fn mtime<R: Read>(entry: &mut tar::Entry<R>) -> Result<Instant> {
    if let Ok(Some(exts)) = entry.pax_extensions() {
        for ext in exts.flatten() {
            if ext.key_bytes() == b"mtime"
                && let Some(t) = std::str::from_utf8(ext.value_bytes()).ok().and_then(parse_pax_time)
            {
                return Ok(t);
            }
        }
    }
    let secs = entry
        .header()
        .mtime()
        .map_err(|e| Error::new(format!("reading archive: {}", crate::util::io_reason(&e))))?;
    Ok(Instant {
        secs: secs.min(i64::MAX as u64) as i64,
        nanos: 0,
    })
}

/// A PAX time: optional sign, decimal seconds, optional fraction.
fn parse_pax_time(s: &str) -> Option<Instant> {
    let (neg, s) = match s.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, s),
    };
    let (whole, frac) = s.split_once('.').unwrap_or((s, ""));
    if whole.is_empty() || !whole.bytes().all(|c| c.is_ascii_digit()) || !frac.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let secs: i64 = whole.parse().ok()?;
    let mut nanos: u32 = format!("{:0<9}", &frac[..frac.len().min(9)]).parse().ok()?;
    let mut secs = if neg { -secs } else { secs };
    if neg && nanos > 0 {
        secs -= 1;
        nanos = 1_000_000_000 - nanos;
    }
    Some(Instant { secs, nanos })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kem::{Identity, SUITE_ID};
    use crate::pipeline::Pool;
    use crate::testutil::TempDir;
    use std::sync::Arc;

    fn store(tag: &str) -> (TempDir, Store) {
        let d = TempDir::new(tag);
        let root = d.0.join("v");
        Store::init(&root, 0, Arc::new(Pool::new(2))).unwrap();
        let s = Store::open(
            &root,
            Identity::from_suite_seed(SUITE_ID, &[1; 32]).unwrap(),
            Arc::new(Pool::new(2)),
        )
        .unwrap();
        (d, s)
    }

    fn header(name: &str, kind: tar::EntryType, size: u64, mode: u32, mtime: u64) -> tar::Header {
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(kind);
        h.set_size(size);
        h.set_mode(mode);
        h.set_mtime(mtime);
        // Raw bytes, so unsafe names reach the reader unaltered.
        let n = name.as_bytes();
        h.as_old_mut().name[..n.len()].copy_from_slice(n);
        h.set_cksum();
        h
    }

    #[test]
    fn absorbs_regular_files_only() {
        let (d, s) = store("absorb");
        let mut tw = tar::Builder::new(Vec::new());
        for (name, kind, body) in [
            ("./d/", tar::EntryType::Directory, &b""[..]),
            ("./d/a.txt", tar::EntryType::Regular, b"hello"),
            ("../escape", tar::EntryType::Regular, b"nope!"),
            ("/abs", tar::EntryType::Regular, b"abs"),
            ("a\\b", tar::EntryType::Regular, b"bs"),
            ("./d/link", tar::EntryType::Symlink, b""),
        ] {
            let h = header(name, kind, body.len() as u64, 0o600, 1577934245);
            tw.append(&h, body).unwrap();
        }
        let tarball = tw.into_inner().unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut gz, &tarball).unwrap();
        let gz = gz.finish().unwrap();
        let mut cat = s.catalogue().unwrap();
        let mut added = Vec::new();
        absorb(&s, &mut cat, &gz[..], "in", &mut |n, _| added.push(n.to_string())).unwrap();
        assert_eq!(added, ["in/d/a.txt", "in/abs"]);
        let r = cat.current("in/d/a.txt").unwrap();
        assert_eq!(
            (r.mode, r.modified),
            (
                0o600,
                Instant {
                    secs: 1577934245,
                    nanos: 0
                }
            )
        );
        let dir = crate::platform::fs::Dir::open(&d.0).unwrap();
        s.extract(r, &dir, std::ffi::OsStr::new("out")).unwrap();
        assert_eq!(std::fs::read(d.0.join("out")).unwrap(), b"hello");
        // Plain tar works too, and an archive with nothing to add fails.
        absorb(&s, &mut cat, &tarball[..], "", &mut |_, _| {}).unwrap();
        let mut empty = tar::Builder::new(Vec::new());
        empty
            .append(&header("dir/", tar::EntryType::Directory, 0, 0o755, 0), &b""[..])
            .unwrap();
        let e = absorb(&s, &mut cat, &empty.into_inner().unwrap()[..], "", &mut |_, _| {}).unwrap_err();
        assert_eq!(e.msg, "no files in archive");
    }

    #[test]
    fn truncated_and_malicious_archives() {
        let (_d, s) = store("absorb-bad");
        let mut tw = tar::Builder::new(Vec::new());
        tw.append(&header("big", tar::EntryType::Regular, 100_000, 0o600, 0), &vec![7u8; 100_000][..])
            .unwrap();
        let t = tw.into_inner().unwrap();
        let before = s.catalogue().unwrap().len();
        let mut cat = s.catalogue().unwrap();
        let e = absorb(&s, &mut cat, &t[..60_000], "", &mut |_, _| {}).unwrap_err();
        assert!(e.msg.contains("archive ends early") || e.msg.starts_with("reading archive"), "{e}");
        assert_eq!(s.catalogue().unwrap().len(), before, "a truncated entry stored something");
        for junk in [
            &b"not a tar archive at all, but long enough to fill a header block"[..],
            &[0x1f, 0x8b, 0, 0][..],
            &[0u8; 1024][..],
        ] {
            assert!(absorb(&s, &mut cat, junk, "", &mut |_, _| {}).is_err());
        }
        // A corrupted gzip stream fails rather than storing a partial file.
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut gz, &t).unwrap();
        let mut g = gz.finish().unwrap();
        let mid = g.len() / 2;
        g[mid] ^= 0xff;
        assert!(absorb(&s, &mut cat, &g[..], "", &mut |_, _| {}).is_err());
        assert_eq!(s.catalogue().unwrap().len(), before);
    }

    /// A PAX "size" record overrides the header's size field, as Go writes
    /// for files over 8 GiB; the whole body must be stored.
    #[test]
    fn pax_size_override() {
        let (d, s) = store("absorb-pax");
        let mut t = Vec::new();
        let rec = |k: &str, v: &str| {
            let body = format!(" {k}={v}\n");
            let mut n = body.len() + 1;
            while format!("{n}{body}").len() != n {
                n += 1;
            }
            format!("{n}{body}")
        };
        let pax = rec("size", "11");
        let mut h = header("PaxHeaders/big", tar::EntryType::XHeader, pax.len() as u64, 0o644, 0);
        h.set_cksum();
        t.extend_from_slice(h.as_bytes());
        let mut p = pax.into_bytes();
        p.resize(p.len().div_ceil(512) * 512, 0);
        t.extend_from_slice(&p);
        let h = header("big.bin", tar::EntryType::Regular, 0, 0o644, 0);
        t.extend_from_slice(h.as_bytes());
        let mut body = b"hello world".to_vec();
        body.resize(512, 0);
        t.extend_from_slice(&body);
        t.extend_from_slice(&[0u8; 1024]);
        let mut cat = s.catalogue().unwrap();
        absorb(&s, &mut cat, &t[..], "", &mut |_, _| {}).unwrap();
        let r = cat.current("big.bin").unwrap();
        assert_eq!(r.size, 11);
        let dir = crate::platform::fs::Dir::open(&d.0).unwrap();
        s.extract(r, &dir, std::ffi::OsStr::new("o")).unwrap();
        assert_eq!(std::fs::read(d.0.join("o")).unwrap(), b"hello world");
    }

    #[test]
    fn names_and_times() {
        // As in Go, only names that would climb out are refused; others are
        // cleaned.
        for (n, want) in [
            ("./a/b", Some("a/b")),
            ("a/../b", Some("b")),
            ("../x", None),
            ("a/../../x", None),
            ("/x", Some("x")),
            ("a//b", Some("a/b")),
            ("a\\b", None),
            ("", None),
            (".", None),
            ("a/", Some("a")),
        ] {
            assert_eq!(safe_name(n).as_deref(), want, "{n:?}");
        }
        assert_eq!(
            parse_pax_time("1577934245.5"),
            Some(Instant {
                secs: 1577934245,
                nanos: 500_000_000
            })
        );
        assert_eq!(
            parse_pax_time("-1.25"),
            Some(Instant {
                secs: -2,
                nanos: 750_000_000
            })
        );
        assert_eq!(parse_pax_time("x"), None);
    }
}
