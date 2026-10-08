// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::crypto::kem::SUITE_ID;
use std::sync::atomic::Ordering;

pub(crate) struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> TempDir {
        let r: [u8; 8] = crate::rng::os().array();
        let p = std::env::temp_dir().join(format!("vault-store-{tag}-{}-{}", std::process::id(), hex(&r)));
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        // Read-only test directories must be writable again to delete.
        #[cfg(unix)]
        for e in walk(&self.0) {
            use std::os::unix::fs::PermissionsExt;
            if e.is_dir() {
                let _ = std::fs::set_permissions(&e, std::fs::Permissions::from_mode(0o700));
            }
        }
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn walk(p: &Path) -> Vec<PathBuf> {
    let mut out = vec![p.to_path_buf()];
    if let Ok(rd) = std::fs::read_dir(p) {
        for e in rd.flatten() {
            let path = e.path();
            if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                out.extend(walk(&path));
            } else {
                out.push(path);
            }
        }
    }
    out
}

fn files(p: &Path) -> Vec<PathBuf> {
    let mut v: Vec<_> = walk(p).into_iter().filter(|p| p.is_file()).collect();
    v.sort();
    v
}

pub(crate) fn identity(n: u8) -> Identity {
    Identity::from_suite_seed(SUITE_ID, &[n; 32]).unwrap()
}

pub(crate) fn pool() -> Arc<Pool> {
    Arc::new(Pool::new(4))
}

/// A fresh vault (filler kept small but present) and a store on it.
fn vault(tag: &str) -> (TempDir, Store) {
    let d = TempDir::new(tag);
    let root = d.0.join("store");
    Store::init(&root, 0, pool()).unwrap();
    let s = Store::open(&root, identity(1), pool()).unwrap();
    (d, s)
}

fn name(n: &str) -> VaultName {
    VaultName::new(n).unwrap()
}

fn add_bytes(s: &Store, cat: &mut Catalogue, n: &str, body: &[u8]) -> Added {
    s.add_reader(cat, &mut &body[..], body.len() as u64, 0o640, Instant::now(), &name(n))
        .unwrap()
}

fn get_bytes(s: &Store, rec: &Record, dir: &Path, out: &str) -> Result<Vec<u8>> {
    let d = pfs::Dir::open(dir).unwrap();
    s.extract(rec, &d, OsStr::new(out))?;
    Ok(std::fs::read(dir.join(out)).unwrap())
}

fn objects(s: &Store) -> Vec<PathBuf> {
    files(&s.root().join(OBJECTS))
}

#[test]
fn lifecycle() {
    let (d, s) = vault("life");
    let mut cat = s.catalogue().unwrap();
    assert!(cat.is_empty(), "filler must be invisible");
    let want = vec![b'x'; 70000];
    assert!(!add_bytes(&s, &mut cat, "a/b", &want).replaced);
    assert!(add_bytes(&s, &mut cat, "a/b", &want).replaced);
    add_bytes(&s, &mut cat, "c", b"see");
    let cat2 = s.catalogue().unwrap();
    assert_eq!(cat2.names().collect::<Vec<_>>(), ["a/b", "c"]);
    assert_eq!(cat2.records("a/b").len(), 1, "replace removed the old record");
    let r = cat2.current("a/b").unwrap();
    assert_eq!((r.size, r.mode), (70000, 0o640));
    assert_eq!(get_bytes(&s, r, &d.0, "out").unwrap(), want);
    let e = get_bytes(&s, r, &d.0, "out").unwrap_err();
    assert!(e.msg.ends_with("already exists"), "{e}");

    // Swapping one object for another is detected, and nothing appears.
    let (dr, cr) = (cat2.current("a/b").unwrap(), cat2.current("c").unwrap());
    std::fs::copy(s.path(OBJECTS, &cr.seed.object_id(0)), s.path(OBJECTS, &dr.seed.object_id(0))).unwrap();
    let e = get_bytes(&s, dr, &d.0, "swapped").unwrap_err();
    assert!(e.msg.contains("does not match"), "{e}");
    assert!(!d.0.join("swapped").exists());
    assert_eq!(std::fs::read_dir(&d.0).unwrap().count(), 2, "temporary file left behind");
}

#[test]
fn decoy_isolation_and_filler() {
    let (_d, real) = vault("decoy");
    let decoy = Store::open(real.root(), identity(2), pool()).unwrap();
    for (s, n) in [(&real, "secret"), (&decoy, "shopping")] {
        let mut cat = s.catalogue().unwrap();
        assert!(cat.is_empty());
        add_bytes(s, &mut cat, n, b"data");
    }
    for (s, n) in [(&real, "secret"), (&decoy, "shopping")] {
        let cat = s.catalogue().unwrap();
        assert_eq!(cat.names().collect::<Vec<_>>(), [n]);
    }
    let records = files(&real.root().join(RECORDS));
    assert!(
        records.len() as u64 >= FILLER_MIN + 2,
        "only {} records; filler missing",
        records.len()
    );
    // Records are all one size, and every object is within the bucket range.
    let sizes: HashSet<u64> = records.iter().map(|p| p.metadata().unwrap().len()).collect();
    assert_eq!(sizes.len(), 1, "records differ in size: {sizes:?}");
}

#[test]
fn filler_target() {
    let d = TempDir::new("filler");
    let root = d.0.join("v");
    Store::init(&root, 24 << 20, pool()).unwrap();
    assert!(Store::init(&root, 0, pool()).is_err(), "init twice");
    let objs = files(&root.join(OBJECTS));
    let total: u64 = objs.iter().map(|p| p.metadata().unwrap().len()).sum();
    let largest = objs.iter().map(|p| p.metadata().unwrap().len()).max().unwrap();
    assert!(total >= 24 << 20, "filler objects total {total}");
    assert!(largest <= CHUNK_SIZE + CHUNK_SIZE / 64, "largest object {largest}");
    for i in 0..256 {
        for dir in [RECORDS, OBJECTS] {
            let p = root.join(dir).join(format!("{i:02x}"));
            assert_eq!(p.metadata().unwrap().modified().unwrap(), std::time::UNIX_EPOCH, "{}", p.display());
        }
    }
    for f in files(&root.join(RECORDS)).iter().chain(&objs) {
        assert_eq!(f.metadata().unwrap().modified().unwrap(), std::time::UNIX_EPOCH);
        assert!(f.parent().unwrap().file_name().unwrap().to_str().unwrap() == &f.file_name().unwrap().to_str().unwrap()[..2]);
    }
    assert_eq!(std::fs::read(root.join(MARKER_NAME)).unwrap(), MARKER_CONTENT);
}

#[test]
fn chunks_and_reordering() {
    let (d, s) = vault("chunks");
    let before = objects(&s).len();
    let mut want = vec![0u8; 2 * CHUNK_DATA as usize + 100];
    crate::rng::os().fill(&mut want);
    let mut cat = s.catalogue().unwrap();
    add_bytes(&s, &mut cat, "big", &want);
    let r = cat.current("big").unwrap();
    let sizes: Vec<u64> = (0..object_count(r.size))
        .map(|i| s.path(OBJECTS, &r.seed.object_id(i)).metadata().unwrap().len())
        .collect();
    assert!(sizes.len() == 3 && sizes[0] == sizes[1] && sizes[2] < sizes[0], "{sizes:?}");
    assert_eq!(objects(&s).len() - before, 3);
    assert_eq!(get_bytes(&s, r, &d.0, "out").unwrap(), want);
    let (a, b) = (s.path(OBJECTS, &r.seed.object_id(0)), s.path(OBJECTS, &r.seed.object_id(1)));
    let (ad, bd) = (std::fs::read(&a).unwrap(), std::fs::read(&b).unwrap());
    std::fs::write(&a, &bd).unwrap();
    std::fs::write(&b, &ad).unwrap();
    assert!(get_bytes(&s, r, &d.0, "swapped").is_err());
    assert!(!d.0.join("swapped").exists());
    s.remove_all(&mut cat, &["big".to_string()], &mut |_| {}).unwrap();
    assert_eq!(objects(&s).len(), before, "rm freed the objects");
}

#[test]
fn boundaries_round_trip() {
    let (d, s) = vault("bounds");
    let mut cat = s.catalogue().unwrap();
    let c = CHUNK_DATA as usize;
    for (i, n) in [0, 1, 65535 - 16, 65536 - 16, 65536 - 15, 65536, c - 1, c, c + 1]
        .into_iter()
        .enumerate()
    {
        let body: Vec<u8> = (0..n).map(|j| (j * 31 + i) as u8).collect();
        add_bytes(&s, &mut cat, &format!("f{i}"), &body);
        let r = cat.current(&format!("f{i}")).unwrap();
        assert_eq!(get_bytes(&s, r, &d.0, &format!("o{i}")).unwrap(), body, "size {n}");
        // Each object is padded: one bucket per object, all within range.
        for k in 0..object_count(n as u64) {
            let len = s.path(OBJECTS, &r.seed.object_id(k)).metadata().unwrap().len();
            assert!(
                len > MIN_PADDING && len <= CHUNK_SIZE + (32 << 10),
                "object of {len} bytes for size {n}"
            );
        }
    }
}

#[test]
fn remove_tree_and_copy_move() {
    let (d, s) = vault("tree");
    let before = objects(&s).len();
    let mut cat = s.catalogue().unwrap();
    let mut big = vec![0u8; CHUNK_DATA as usize + 1];
    crate::rng::os().fill(&mut big);
    for (n, b) in [("a/x", &big[..]), ("a/b/y", b"y"), ("ab/z", b"z"), ("b/w", b"w")] {
        add_bytes(&s, &mut cat, n, b);
    }
    assert_eq!(objects(&s).len() - before, 5);
    assert_eq!(cat.under("a"), ["a/b/y", "a/x"]);
    // cp -r a c, then rm -r a: the copies keep the shared objects.
    let pairs: Vec<(String, VaultName)> = cat
        .under("a")
        .into_iter()
        .map(|n| (n.clone(), name(&format!("c{}", &n[1..]))))
        .collect();
    let mut copied = Vec::new();
    s.copy_all(&mut cat, &pairs, false, &mut |f, t| copied.push((f.to_string(), t.to_string())))
        .unwrap();
    assert_eq!(copied.len(), 2);
    assert_eq!(objects(&s).len() - before, 5, "copies share objects");
    let mut done = Vec::new();
    let names = cat.under("a");
    s.remove_all(&mut cat, &names, &mut |n| done.push(n.to_string())).unwrap();
    assert_eq!(done, ["a/b/y", "a/x"]);
    assert_eq!(objects(&s).len() - before, 5, "objects still used by the copies stay");
    let fresh = s.catalogue().unwrap();
    assert_eq!(fresh.names().collect::<Vec<_>>(), ["ab/z", "b/w", "c/b/y", "c/x"]);
    assert_eq!(get_bytes(&s, fresh.current("c/x").unwrap(), &d.0, "x").unwrap(), big);
    // mv keeps one copy of each object; rm of the last name frees them.
    let mut cat = fresh;
    s.copy_all(&mut cat, &[("c/x".into(), name("moved"))], true, &mut |_, _| {})
        .unwrap();
    assert!(!cat.contains("c/x") && cat.contains("moved"));
    let names: Vec<String> = cat.names().map(String::from).collect();
    s.remove_all(&mut cat, &names, &mut |_| {}).unwrap();
    assert_eq!(objects(&s).len(), before, "space freed");
}

/// The Go oracle's fixture vault opens: real files decrypt to the same
/// bytes and metadata, the decoy sees only its file, the foreign record is
/// skipped silently.
#[test]
fn reads_go_vault() {
    let d = TempDir::new("govault");
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/mini-vault");
    let root = d.0.join("v");
    for p in walk(&src) {
        let rel = p.strip_prefix(&src).unwrap();
        if p.is_dir() {
            std::fs::create_dir_all(root.join(rel)).unwrap();
        } else {
            std::fs::copy(&p, root.join(rel)).unwrap();
        }
    }
    for dir in [RECORDS, OBJECTS] {
        for i in 0..256 {
            std::fs::create_dir_all(root.join(dir).join(format!("{i:02x}"))).unwrap();
        }
    }
    let key = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/key-with-decoy.pem");
    let real = crate::keyfile::unlock(&key, b"oracle-real passphrase").unwrap();
    let s = Store::open(&root, real, pool()).unwrap();
    let cat = s.catalogue().unwrap();
    assert_eq!(cat.names().collect::<Vec<_>>(), ["dir/empty", "dir/ünïcode.bin", "hello.txt"]);
    let boundary: Vec<u8> = (0..(MIN_PADDING as usize - ID_SIZE)).map(|i| (i * 7) as u8).collect();
    for (n, body, mode, secs, nanos) in [
        ("hello.txt", &b"hello"[..], 0o644, 1700000000, 123456789),
        ("dir/empty", b"", 0o600, 1600000000, 0),
        ("dir/ünïcode.bin", &boundary[..], 0o755, 1500000000, 999999999),
    ] {
        let r = cat.current(n).unwrap();
        assert_eq!((r.mode, r.modified), (mode, Instant { secs, nanos }), "{n}");
        let out = format!("out-{}", r.id.hex());
        assert_eq!(get_bytes(&s, r, &d.0, &out).unwrap(), body);
        let m = d.0.join(&out).metadata().unwrap();
        assert_eq!(m.modified().unwrap(), Instant { secs, nanos }.to_system());
        #[cfg(unix)]
        assert_eq!(std::os::unix::fs::PermissionsExt::mode(&m.permissions()) & 0o777, mode);
    }
    let decoy = crate::keyfile::unlock(&key, b"oracle-decoy passphrase").unwrap();
    let cat = Store::open(&root, decoy, pool()).unwrap().catalogue().unwrap();
    assert_eq!(cat.names().collect::<Vec<_>>(), ["shopping.txt"]);
}

/// With identical synthetic randomness, one worker and eight produce
/// byte-identical objects.
#[test]
fn sequential_and_parallel_identical() {
    let mut outputs = Vec::new();
    for workers in [1, 8] {
        let d = TempDir::new("det");
        let root = d.0.join("v");
        Store::init(&root, 0, pool()).unwrap();
        let s = Store::open_with(&root, identity(3), Arc::new(Pool::new(workers)), Entropy::Seeded([7; 32]));
        let before: HashSet<PathBuf> = objects(&s).into_iter().collect();
        let body: Vec<u8> = (0..3 * CHUNK_DATA as usize + 12345).map(|i| (i % 251) as u8).collect();
        let mut cat = s.catalogue().unwrap();
        add_bytes(&s, &mut cat, "f", &body);
        let new: Vec<(String, Vec<u8>)> = objects(&s)
            .into_iter()
            .filter(|p| !before.contains(p))
            .map(|p| (p.file_name().unwrap().to_string_lossy().into_owned(), std::fs::read(&p).unwrap()))
            .collect();
        assert_eq!(new.len(), 4);
        outputs.push(new);
    }
    assert!(outputs[0] == outputs[1], "sequential and parallel output differ");
}

/// A failure while writing objects stores nothing and leaves no objects.
#[cfg(unix)]
#[test]
fn object_write_failure_rolls_back() {
    use std::os::unix::fs::PermissionsExt;
    let d = TempDir::new("fail");
    let root = d.0.join("v");
    Store::init(&root, 0, pool()).unwrap();
    let entropy = Entropy::Seeded([9; 32]);
    let s = Store::open_with(&root, identity(4), pool(), entropy.clone());
    let seed = ObjectSeed::random(&mut entropy.rng(b"seed"));
    let blocked = s.path(OBJECTS, &seed.object_id(2));
    let shard = blocked.parent().unwrap().to_path_buf();
    if seed.object_id(0).shard() == seed.object_id(2).shard() || seed.object_id(1).shard() == seed.object_id(2).shard() {
        return; // the fixed seed puts two objects in one shard; nothing to test
    }
    std::fs::set_permissions(&shard, std::fs::Permissions::from_mode(0o500)).unwrap();
    if std::fs::write(shard.join("probe"), b"").is_ok() {
        return; // running as root: permissions do not bite
    }
    let before = objects(&s);
    let mut cat = s.catalogue().unwrap();
    let body = vec![1u8; 3 * CHUNK_DATA as usize];
    assert!(
        s.add_reader(&mut cat, &mut &body[..], body.len() as u64, 0o600, Instant::now(), &name("f"))
            .is_err()
    );
    std::fs::set_permissions(&shard, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(objects(&s), before, "objects of a failed add were left behind");
    assert!(s.catalogue().unwrap().is_empty());
    assert!(
        walk(&root)
            .iter()
            .all(|p| !p.file_name().unwrap().to_string_lossy().starts_with(".pending-"))
    );
}

/// A short source stores nothing; a longer one than declared is refused.
#[test]
fn short_and_long_sources() {
    let (d, s) = vault("short");
    let before = objects(&s);
    let mut cat = s.catalogue().unwrap();
    let e = s
        .add_reader(&mut cat, &mut &b"abc"[..], 10, 0o600, Instant::now(), &name("f"))
        .unwrap_err();
    assert_eq!(e.kind, Kind::SourceShort);
    assert_eq!(objects(&s), before);
    let p = d.0.join("src");
    std::fs::write(&p, b"0123456789").unwrap();
    s.add_file(&mut cat, &p, &name("ok")).unwrap();
    assert!(s.catalogue().unwrap().contains("ok"));
}

/// A record whose sync fails after it is in place keeps its objects.
#[test]
fn failure_after_publish_keeps_objects() {
    let (d, s) = vault("afterpub");
    let mut cat = s.catalogue().unwrap();
    s.inner.fail_after_publish.store(true, Ordering::SeqCst);
    let e = s
        .add_reader(&mut cat, &mut &b"precious"[..], 8, 0o600, Instant::now(), &name("f"))
        .unwrap_err();
    assert_eq!(e.kind, Kind::AfterPublish);
    s.inner.fail_after_publish.store(false, Ordering::SeqCst);
    let cat = s.catalogue().unwrap();
    assert_eq!(get_bytes(&s, cat.current("f").unwrap(), &d.0, "out").unwrap(), b"precious");
}

/// Tampered, truncated, extended and foreign objects never publish output.
#[test]
fn damaged_objects_never_publish() {
    let (d, s) = vault("damage");
    let mut cat = s.catalogue().unwrap();
    let body: Vec<u8> = (0..100_000).map(|i| i as u8).collect();
    add_bytes(&s, &mut cat, "f", &body);
    let r = cat.current("f").unwrap();
    let obj = s.path(OBJECTS, &r.seed.object_id(0));
    let orig = std::fs::read(&obj).unwrap();
    let foreign = {
        let mut v = Vec::new();
        fury::encrypt_to(&mut v, &identity(9).recipient(), &[0u8; 1 << 17], &mut crate::rng::os());
        v
    };
    // Same key and ID, but padding to the wrong bucket.
    let short_pad = {
        let mut p = r.seed.object_id(0).0.to_vec();
        p.extend_from_slice(&body);
        let mut v = Vec::new();
        fury::encrypt_to(&mut v, &s.inner.recipient, &p, &mut crate::rng::os());
        v
    };
    let damaged: Vec<(&str, Vec<u8>)> = vec![
        ("flipped", {
            let mut v = orig.clone();
            let n = v.len() - 100;
            v[n] ^= 1;
            v
        }),
        ("truncated", orig[..orig.len() - 1].to_vec()),
        ("missing final chunk", orig[..orig.len() - 1000].to_vec()),
        ("trailing", [&orig[..], b"x"].concat()),
        ("empty", Vec::new()),
        ("foreign", foreign),
        ("short padding", short_pad),
    ];
    for (what, bytes) in damaged {
        std::fs::write(&obj, &bytes).unwrap();
        let out = format!("out-{}", what.replace(' ', "-"));
        assert!(get_bytes(&s, r, &d.0, &out).is_err(), "{what} accepted");
        assert!(!d.0.join(&out).exists(), "{what} published output");
    }
    assert_eq!(std::fs::read_dir(&d.0).unwrap().count(), 1, "temporary files left behind");
    std::fs::remove_file(&obj).unwrap();
    assert!(get_bytes(&s, r, &d.0, "missing").is_err());
}

#[cfg(unix)]
#[test]
fn extraction_never_replaces_symlinks() {
    let (d, s) = vault("symlink");
    let mut cat = s.catalogue().unwrap();
    add_bytes(&s, &mut cat, "f", b"data");
    let r = cat.current("f").unwrap();
    std::os::unix::fs::symlink(d.0.join("target"), d.0.join("dangling")).unwrap();
    assert!(get_bytes(&s, r, &d.0, "dangling").is_err());
    assert!(!d.0.join("target").exists(), "followed a dangling symlink");
    std::fs::write(d.0.join("exists"), b"keep").unwrap();
    assert!(get_bytes(&s, r, &d.0, "exists").is_err());
    assert_eq!(std::fs::read(d.0.join("exists")).unwrap(), b"keep");
}

#[test]
fn oversized_record_names() {
    let (_d, s) = vault("names");
    let mut cat = s.catalogue().unwrap();
    // 1024 bytes is the limit; '<' is escaped six-fold in JSON, as in Go.
    let long = "a".repeat(NAME_LIMIT);
    add_bytes(&s, &mut cat, &long, b"x");
    let escaped = "<".repeat(NAME_LIMIT);
    let e = s
        .add_reader(&mut cat, &mut &b"x"[..], 1, 0o600, Instant::now(), &name(&escaped))
        .unwrap_err();
    assert_eq!(e.msg, "catalogue record too large");
    assert!(VaultName::new(&"a".repeat(NAME_LIMIT + 1)).is_none());
    assert_eq!(s.catalogue().unwrap().names().collect::<Vec<_>>(), [long.as_str()]);
}

#[test]
fn duplicate_records_recover() {
    let (_d, s) = vault("dups");
    let mut cat = s.catalogue().unwrap();
    add_bytes(&s, &mut cat, "f", b"old");
    // An interrupted replace leaves two records for one name.
    let old = cat.current("f").unwrap();
    let mut dup = old.copy_as(name("f"), Id::random(&mut crate::rng::os()));
    dup.added = Instant {
        secs: old.added.secs + 10,
        nanos: 0,
    };
    s.inner.write_record(&dup).unwrap();
    let cat = s.catalogue().unwrap();
    assert_eq!(cat.records("f").len(), 2);
    assert_eq!(cat.current("f").unwrap().added, dup.added, "newest first");
    let mut cat = cat;
    add_bytes(&s, &mut cat, "f", b"new");
    assert_eq!(s.catalogue().unwrap().records("f").len(), 1, "next write cleans up");
}
