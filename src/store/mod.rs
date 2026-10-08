// SPDX-License-Identifier: GPL-3.0-or-later

//! The on-disk vault, compatible with the Go version:
//!
//! ```text
//! DIR/.vault              "VAULT 2\n"
//! DIR/records/<xx>/<id>   one encrypted 4096-byte catalogue record per file
//! DIR/objects/<xx>/<id>   a file's body, in one or more encrypted objects
//! ```
//!
//! `<xx>` is the first byte of `<id>` in hex; all 256 shards exist from
//! `init`. Record IDs are random; a file's object IDs are
//! HMAC-SHA-256(seed, index)[:16] for a secret seed in its record, so
//! nothing on disk links a file's objects. An object's plaintext is its own
//! ID, up to 4 MiB − 16 bytes of the file, and random padding up to a
//! power-of-two bucket of 64 KiB to 4 MiB. Every ciphertext's and shard's
//! modification time is pinned to the epoch.
//!
//! Ordering keeps the store consistent across crashes: objects are durable
//! before the record that names them; a new record is durable before an old
//! one it replaces is removed; a record's removal is durable before the
//! objects only it used are deleted; copies share objects.

pub mod types;

use crate::crypto::fury;
use crate::crypto::kem::{Identity, Recipient};
use crate::error::{Error, Kind, Result};
use crate::pipeline::{Buffers, Lease, OBJECT_BUFFERS, Pool, Ticket};
use crate::platform::fs as pfs;
use crate::rng::Entropy;
use crate::secret::SecretVec;
use crate::util::Instant;
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::ffi::OsStr;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
pub use types::*;

pub const MARKER_NAME: &str = ".vault";
pub const MARKER_CONTENT: &[u8] = b"VAULT 2\n";
pub const RECORDS: &str = "records";
pub const OBJECTS: &str = "objects";
const FILLER_MIN: u64 = 8;
const FILLER_MAX: u64 = 32;
/// Ciphertext payload capacity for one object, plus one byte to detect
/// over-long objects.
const OBJECT_BUF: usize = CHUNK_SIZE as usize + 64 * crate::crypto::stream::TAG_SIZE + 1;

struct Inner {
    root: PathBuf,
    id: Identity,
    recipient: Recipient,
    no_sync: bool,
    entropy: Entropy,
    /// Test hook: make record writes fail just after their rename.
    #[cfg(test)]
    fail_after_publish: std::sync::atomic::AtomicBool,
}

pub struct Store {
    inner: Arc<Inner>,
    pool: Arc<Pool>,
    buffers: OnceLock<Buffers>,
}

/// Every record this identity can open, by name, newest first.
#[derive(Default)]
pub struct Catalogue {
    by_name: BTreeMap<String, Vec<Record>>,
}

impl Catalogue {
    pub fn current(&self, name: &str) -> Option<&Record> {
        self.by_name.get(name).and_then(|v| v.first())
    }

    pub fn contains(&self, name: &str) -> bool {
        self.current(name).is_some()
    }

    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }

    /// Every name, sorted.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.by_name.keys().map(String::as_str)
    }

    /// Each name with its current record, sorted by name.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Record)> {
        self.by_name.iter().filter_map(|(n, v)| v.first().map(|r| (n.as_str(), r)))
    }

    /// The names at or beneath the folder `prefix`, sorted.
    pub fn under(&self, prefix: &str) -> Vec<String> {
        self.by_name
            .keys()
            .filter(|n| *n == prefix || (n.len() > prefix.len() && n.starts_with(prefix) && n.as_bytes()[prefix.len()] == b'/'))
            .cloned()
            .collect()
    }

    fn records(&self, name: &str) -> &[Record] {
        self.by_name.get(name).map_or(&[], Vec::as_slice)
    }

    fn insert(&mut self, r: Record) {
        let v = self.by_name.entry(r.name.as_str().to_string()).or_default();
        v.push(r);
        v.sort_by(|a, b| b.added.cmp(&a.added).then(a.id.cmp(&b.id)));
    }
}

/// What `add` did, for the message and for migrate's source check.
#[derive(Debug)]
pub struct Added {
    pub replaced: bool,
}

fn after_publish(e: &Error) -> bool {
    e.kind == Kind::AfterPublish
}

impl Store {
    /// Creates a vault at `root` holding at least `filler` bytes of filler.
    pub fn init(root: &Path, filler: u64, pool: Arc<Pool>) -> Result<()> {
        if root.join(MARKER_NAME).symlink_metadata().is_ok() {
            crate::bail!("{} is already a vault", root.display());
        }
        // Every shard exists from the start, so the tree's shape says nothing.
        for dir in [RECORDS, OBJECTS] {
            for i in 0..256 {
                let p = root.join(dir).join(format!("{i:02x}"));
                pfs::create_private_dir_all(&p).map_err(|e| Error::io("mkdir", &p, &e))?;
            }
        }
        write_filler(root, filler, Arc::clone(&pool), Entropy::Os)?;
        for dir in [RECORDS, OBJECTS] {
            for i in 0..256 {
                let p = root.join(dir).join(format!("{i:02x}"));
                pfs::set_epoch(&p).map_err(|e| Error::io("chtimes", &p, &e))?;
            }
            let p = root.join(dir);
            pfs::set_epoch(&p).map_err(|e| Error::io("chtimes", &p, &e))?;
        }
        let marker = root.join(MARKER_NAME);
        let mut f = pfs::create_new_private(&marker).map_err(|e| Error::io("open", &marker, &e))?;
        f.write_all(MARKER_CONTENT)
            .and_then(|_| f.sync_all())
            .map_err(|e| Error::io("write", &marker, &e))?;
        pfs::sync_dir(root).map_err(|e| Error::io("sync", root, &e))?;
        Ok(())
    }

    pub fn open(root: &Path, id: Identity, pool: Arc<Pool>) -> Result<Store> {
        match std::fs::read(root.join(MARKER_NAME)) {
            Ok(m) if m == MARKER_CONTENT => {}
            _ => crate::bail!("{} is not a vault; run vault init", root.display()),
        }
        Ok(Store::new(root, id, pool, false, Entropy::Os))
    }

    fn new(root: &Path, id: Identity, pool: Arc<Pool>, no_sync: bool, entropy: Entropy) -> Store {
        let recipient = id.recipient();
        let inner = Inner {
            root: root.to_path_buf(),
            id,
            recipient,
            no_sync,
            entropy,
            #[cfg(test)]
            fail_after_publish: Default::default(),
        };
        Store {
            inner: Arc::new(inner),
            pool,
            buffers: OnceLock::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn open_with(root: &Path, id: Identity, pool: Arc<Pool>, entropy: Entropy) -> Store {
        Store::new(root, id, pool, false, entropy)
    }

    pub fn root(&self) -> &Path {
        &self.inner.root
    }

    pub fn path(&self, dir: &str, id: &Id) -> PathBuf {
        self.inner.path(dir, id)
    }

    fn buffers(&self) -> &Buffers {
        self.buffers.get_or_init(|| Buffers::new(OBJECT_BUFFERS, OBJECT_BUF))
    }

    /// Decrypts every record this identity can open. Records sealed to a
    /// different key are skipped silently: they are simply not ours.
    /// Unreadable ones of ours are reported and skipped.
    pub fn catalogue(&self) -> Result<Catalogue> {
        let dir = self.inner.root.join(RECORDS);
        let mut ids = Vec::new();
        for shard in sorted_dir(&dir)? {
            if !shard.1 {
                continue;
            }
            let sp = dir.join(&shard.0);
            for (name, _) in sorted_dir(&sp)? {
                if let Some(id) = name.to_str().and_then(Id::parse) {
                    if id.shard() == shard.0.to_string_lossy() {
                        ids.push(id);
                    }
                }
            }
        }
        let mut cat = Catalogue::default();
        let window = self.pool.workers() * 2;
        let mut pending: VecDeque<(Id, Ticket<std::result::Result<Record, ReadRecordError>>)> = VecDeque::new();
        let collect = |id: Id, r: std::result::Result<std::result::Result<Record, ReadRecordError>, String>, cat: &mut Catalogue| match r {
            Ok(Ok(rec)) => cat.insert(rec),
            Ok(Err(ReadRecordError::Foreign)) => {}
            Ok(Err(ReadRecordError::Other(e))) | Err(e) => eprintln!("vault: skipping unreadable record {}: {e}", id.hex()),
        };
        for id in ids {
            if pending.len() == window {
                let (i, t) = pending.pop_front().expect("non-empty");
                collect(i, t.wait(), &mut cat);
            }
            let inner = Arc::clone(&self.inner);
            pending.push_back((id, self.pool.submit(move || inner.read_record(id))));
        }
        for (i, t) in pending {
            collect(i, t.wait(), &mut cat);
        }
        Ok(cat)
    }

    /// Stores the regular file at `src` as `name`, replacing any file of
    /// that name. Fails, storing nothing, if the file changes while read.
    pub fn add_file(&self, cat: &mut Catalogue, src: &Path, name: &VaultName) -> Result<(Added, SourceStamp)> {
        let mut f = std::fs::File::open(src).map_err(|e| Error::io("open", src, &e))?;
        let meta = f.metadata().map_err(|e| Error::io("stat", src, &e))?;
        if !meta.is_file() || meta.len() > FILE_LIMIT {
            crate::bail!("{}: not a regular file of at most 1 TiB", src.display());
        }
        let stamp = SourceStamp::of(&meta);
        let changed = || Error::new(format!("{} changed while being added", src.display())).with_kind(Kind::SourceShort);
        let probe = f.try_clone().map_err(|e| Error::io("open", src, &e))?;
        // Before the record is written: the file must still be the one read.
        let mut unchanged = || match probe.metadata() {
            Ok(m) if SourceStamp::of(&m) == stamp => Ok(()),
            _ => Err(changed()),
        };
        let mut guard = EndCheck {
            inner: &mut f,
            size: meta.len(),
            read: 0,
        };
        let mtime = Instant::from_system(meta.modified().unwrap_or(std::time::UNIX_EPOCH));
        match self.add_checked(cat, &mut guard, meta.len(), mode_of(&meta), mtime, name, &mut unchanged) {
            Ok(a) => Ok((a, stamp)),
            Err(e) if e.kind == Kind::SourceShort => Err(changed()),
            Err(e) => Err(e),
        }
    }

    /// Stores `size` bytes from `src` as `name`. A source that ends early,
    /// or (for an [`EndCheck`]) runs on past `size`, stores nothing.
    pub fn add_reader(
        &self,
        cat: &mut Catalogue,
        src: &mut dyn Read,
        size: u64,
        mode: u32,
        mtime: Instant,
        name: &VaultName,
    ) -> Result<Added> {
        self.add_checked(cat, src, size, mode, mtime, name, &mut || Ok(()))
    }

    #[allow(clippy::too_many_arguments)]
    fn add_checked(
        &self,
        cat: &mut Catalogue,
        src: &mut dyn Read,
        size: u64,
        mode: u32,
        mtime: Instant,
        name: &VaultName,
        before_commit: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Added> {
        if size > FILE_LIMIT {
            crate::bail!("{name}: larger than 1 TiB");
        }
        let seed = ObjectSeed::random(&mut self.inner.entropy.rng(b"seed"));
        if let Err(e) = self.write_objects(src, &seed, size).and_then(|_| before_commit()) {
            let _ = self.drop_objects(&seed, size);
            return Err(e);
        }
        let mut idr = self.inner.entropy.rng(seed.object_id(u64::MAX).0.as_slice());
        let rec = Record {
            name: name.clone(),
            seed,
            size,
            mode: mode & 0o777,
            modified: mtime,
            added: Instant::now(),
            id: Id::random(&mut idr),
        };
        if let Err(e) = self.inner.write_record(&rec) {
            // A record already under its name keeps its objects, even if a
            // later sync failed.
            if !after_publish(&e) {
                let _ = self.drop_objects(&rec.seed, size);
            }
            return Err(e);
        }
        let replaced = cat.contains(name.as_str());
        self.remove(cat, name.as_str())?;
        cat.insert(rec);
        Ok(Added { replaced })
    }

    /// Reads `size` bytes into objects derived from `seed`. The caller's
    /// thread reads the source in order; encryption, writing and syncing of
    /// up to eight objects overlap on the worker pool.
    fn write_objects(&self, src: &mut dyn Read, seed: &ObjectSeed, size: u64) -> Result<()> {
        let mut pending: VecDeque<Ticket<Result<()>>> = VecDeque::new();
        let mut first_err: Option<Error> = None;
        let mut remaining = size;
        for i in 0..object_count(size) {
            if pending.len() == OBJECT_BUFFERS {
                if let Err(e) = pending.pop_front().expect("non-empty").wait().map_err(Error::new).and_then(|r| r) {
                    first_err = Some(e);
                    break;
                }
            }
            let id = seed.object_id(i);
            let part = remaining.min(CHUNK_DATA) as usize;
            remaining -= part as u64;
            let mut lease = self.buffers().take();
            let buf = lease.buf();
            buf.extend_within_capacity(&id.0);
            buf.resize_within_capacity(ID_SIZE + part);
            match crate::crypto::stream::read_full(src, &mut buf.expose_mut()[ID_SIZE..]) {
                Ok(n) if n == part => {}
                Ok(_) => {
                    first_err = Some(Error::new("source ended early").with_kind(Kind::SourceShort));
                    break;
                }
                Err(e) => {
                    first_err = Some(if e.kind() == std::io::ErrorKind::UnexpectedEof {
                        Error::new("source ended early").with_kind(Kind::SourceShort)
                    } else {
                        Error::from(e)
                    });
                    break;
                }
            }
            let inner = Arc::clone(&self.inner);
            pending.push_back(self.pool.submit(move || inner.write_object(id, lease)));
        }
        // Wait for everything in flight, keeping the first error.
        for t in pending {
            if let Err(e) = t.wait().map_err(Error::new).and_then(|r| r) {
                first_err.get_or_insert(e);
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Deletes every record for `name` and the objects no other name uses.
    fn remove(&self, cat: &mut Catalogue, name: &str) -> Result<()> {
        let in_use: HashSet<Id> = cat
            .iter_all()
            .filter(|(n, _)| *n != name)
            .map(|(_, r)| r.seed.object_id(0))
            .collect();
        let records = cat.by_name.remove(name).unwrap_or_default();
        let mut iter = records.into_iter();
        while let Some(r) = iter.next() {
            if let Err(e) = self.inner.remove_record(&r.id) {
                // Put back what is still there.
                let mut keep: Vec<Record> = vec![r];
                keep.extend(iter);
                for k in keep {
                    cat.insert(k);
                }
                return Err(e);
            }
            if !in_use.contains(&r.seed.object_id(0)) {
                self.drop_objects(&r.seed, r.size)?;
            }
        }
        Ok(())
    }

    /// Deletes every record for `names` and the objects they alone hold,
    /// calling `done` after each name.
    pub fn remove_all(&self, cat: &mut Catalogue, names: &[String], done: &mut dyn FnMut(&str)) -> Result<()> {
        let gone: HashSet<&str> = names.iter().map(String::as_str).collect();
        let in_use: HashSet<Id> = cat
            .iter_all()
            .filter(|(n, _)| !gone.contains(n))
            .map(|(_, r)| r.seed.object_id(0))
            .collect();
        for name in names {
            for r in cat.records(name) {
                self.inner.remove_record(&r.id)?;
                if !in_use.contains(&r.seed.object_id(0)) {
                    self.drop_objects(&r.seed, r.size)?;
                }
            }
            cat.by_name.remove(name);
            done(name);
        }
        Ok(())
    }

    /// Stores each pair's first name again under its second, sharing its
    /// objects; with `mv`, then deletes the first names. New records come
    /// first, so an interruption leaves a file under both names, not none.
    pub fn copy_all(&self, cat: &mut Catalogue, pairs: &[(String, VaultName)], mv: bool, done: &mut dyn FnMut(&str, &str)) -> Result<()> {
        let mut old = Vec::new();
        for (from, to) in pairs {
            let src = cat.current(from).ok_or_else(|| Error::new(format!("{from}: not in the vault")))?;
            let mut idr = self.inner.entropy.rng(to.as_str().as_bytes());
            let mut r = src.copy_as(to.clone(), Id::random(&mut idr));
            if !mv {
                r.added = Instant::now();
            }
            self.inner.write_record(&r)?;
            cat.by_name.remove(to.as_str());
            cat.insert(r);
            old.push(from.clone());
            done(from, to.as_str());
        }
        if mv { self.remove_all(cat, &old, &mut |_| {}) } else { Ok(()) }
    }

    /// Deletes the objects of a file of `size` bytes, skipping any gone.
    fn drop_objects(&self, seed: &ObjectSeed, size: u64) -> Result<()> {
        for i in 0..object_count(size) {
            match self.inner.remove_file(OBJECTS, &seed.object_id(i), false) {
                Err(e) if e.kind == Kind::NotFound => {}
                r => r?,
            }
        }
        Ok(())
    }

    /// Decrypts `rec` into `dir/name`. Nothing appears under `name` until
    /// every object — ID prefix, data, padding, final tag and end of file —
    /// has authenticated, and an existing `name` (even a dangling symlink,
    /// even one created meanwhile) is never replaced.
    pub fn extract(&self, rec: &Record, dir: &pfs::Dir, name: &OsStr) -> Result<()> {
        let out = dir.path().join(name);
        if out.symlink_metadata().is_ok() {
            crate::bail!("{} already exists", out.display());
        }
        let (mut f, tmp) = dir
            .create_temp(".vault-get-")
            .map_err(|e| Error::io("create temporary file in", dir.path(), &e))?;
        let r = self.extract_into(rec, &mut f).and_then(|_| {
            f.set_times(
                std::fs::FileTimes::new()
                    .set_accessed(rec.modified.to_system())
                    .set_modified(rec.modified.to_system()),
            )
            .map_err(|e| Error::io("chtimes", &out, &e))?;
            pfs::set_mode(&f, rec.mode).map_err(|e| Error::io("chmod", &out, &e))?;
            f.sync_all().map_err(|e| Error::io("sync", &out, &e))
        });
        drop(f);
        let r = r.and_then(|_| {
            dir.publish(&tmp, name).map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    Error::new(format!("{} already exists", out.display()))
                } else {
                    Error::io("rename", &out, &e)
                }
            })
        });
        if let Err(e) = r {
            let _ = dir.remove(&tmp);
            return Err(e);
        }
        dir.sync().map_err(|e| Error::io("sync", dir.path(), &e))?;
        Ok(())
    }

    fn extract_into(&self, rec: &Record, out: &mut std::fs::File) -> Result<()> {
        let mut pending: VecDeque<(u64, Ticket<Result<Lease>>)> = VecDeque::new();
        let count = object_count(rec.size);
        let mut write = |i: u64, t: Ticket<Result<Lease>>| -> Result<()> {
            let mut lease = t.wait().map_err(Error::new)??;
            let part = rec.part(i) as usize;
            out.write_all(&lease.buf().expose()[ID_SIZE..ID_SIZE + part]).map_err(Error::from)
        };
        let mut result = Ok(());
        for i in 0..count {
            if pending.len() == OBJECT_BUFFERS {
                let (j, t) = pending.pop_front().expect("non-empty");
                if let Err(e) = write(j, t) {
                    result = Err(e);
                    break;
                }
            }
            let lease = self.buffers().take();
            let inner = Arc::clone(&self.inner);
            let id = rec.seed.object_id(i);
            let part = rec.part(i);
            pending.push_back((i, self.pool.submit(move || inner.read_object(id, part, lease))));
        }
        for (j, t) in pending {
            if result.is_ok() {
                result = write(j, t);
            } else {
                drop(t.wait());
            }
        }
        result
    }
}

impl Catalogue {
    /// Every record, duplicates included.
    fn iter_all(&self) -> impl Iterator<Item = (&str, &Record)> {
        self.by_name.iter().flat_map(|(n, v)| v.iter().map(move |r| (n.as_str(), r)))
    }
}

enum ReadRecordError {
    Foreign,
    Other(String),
}

impl Inner {
    fn path(&self, dir: &str, id: &Id) -> PathBuf {
        self.root.join(dir).join(id.shard()).join(id.hex())
    }

    /// Encrypts `plaintext` to `dir/<id>` through a temporary file, so a
    /// partial ciphertext never appears under a real ID. An error after the
    /// rename is marked [`Kind::AfterPublish`].
    fn write_ciphertext(&self, dir: &str, id: &Id, plaintext: &[u8]) -> Result<()> {
        let dst = self.path(dir, id);
        let shard = dst.parent().expect("sharded path").to_path_buf();
        let (mut f, tmp) = pfs::create_temp(&shard, ".pending-").map_err(|e| Error::io("open", &shard, &e))?;
        let mut ct = Vec::with_capacity(plaintext.len() + 32 << 10);
        fury::encrypt_to(&mut ct, &self.recipient, plaintext, &mut self.entropy.rng(&id.0));
        let r = (|| -> Result<()> {
            f.write_all(&ct).map_err(|e| Error::io("write", &tmp, &e))?;
            if !self.no_sync {
                f.sync_all().map_err(|e| Error::io("sync", &tmp, &e))?;
            }
            drop(f);
            pfs::set_epoch(&tmp).map_err(|e| Error::io("chtimes", &tmp, &e))?;
            std::fs::rename(&tmp, &dst).map_err(|e| Error::io("rename", &dst, &e))
        })();
        if let Err(e) = r {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        let after = |e: Error| e.with_kind(Kind::AfterPublish);
        #[cfg(test)]
        if dir == RECORDS && self.fail_after_publish.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(after(Error::new("injected sync failure")));
        }
        pfs::set_epoch(&shard).map_err(|e| after(Error::io("chtimes", &shard, &e)))?;
        if !self.no_sync {
            pfs::sync_dir(&shard).map_err(|e| after(Error::io("sync", &shard, &e)))?;
        }
        Ok(())
    }

    fn write_object(&self, id: Id, mut lease: Lease) -> Result<()> {
        let buf = lease.buf();
        let used = buf.len();
        let padded = padded_size(used as u64) as usize;
        buf.resize_within_capacity(padded);
        self.entropy
            .rng(&[b"pad".as_slice(), &id.0].concat())
            .fill(&mut buf.expose_mut()[used..]);
        self.write_ciphertext(OBJECTS, &id, buf.expose())
    }

    fn write_record(&self, r: &Record) -> Result<()> {
        let json = r.to_json().ok_or("record time outside the years 0 to 9999")?;
        if json.len() > RECORD_SIZE - 4 {
            crate::bail!("catalogue record too large");
        }
        let mut plain = SecretVec::zeroed(RECORD_SIZE);
        let p = plain.expose_mut();
        p[..4].copy_from_slice(&(json.len() as u32).to_be_bytes());
        p[4..4 + json.len()].copy_from_slice(&json);
        self.entropy
            .rng(&[b"recpad".as_slice(), &r.id.0].concat())
            .fill(&mut p[4 + json.len()..]);
        self.write_ciphertext(RECORDS, &r.id, plain.expose())
    }

    fn read_record(&self, id: Id) -> std::result::Result<Record, ReadRecordError> {
        let p = self.path(RECORDS, &id);
        let f = std::fs::File::open(&p).map_err(|e| ReadRecordError::Other(crate::util::io_msg("open", &p, &e)))?;
        let plain = match fury::decrypt_bounded(std::io::BufReader::new(f), &self.id, RECORD_SIZE) {
            Ok(p) => p,
            Err(fury::Error::NoIdentityMatch) => return Err(ReadRecordError::Foreign),
            Err(fury::Error::TooLarge) => return Err(ReadRecordError::Other("wrong record size".into())),
            Err(e) => return Err(ReadRecordError::Other(e.to_string())),
        };
        let b = plain.expose();
        if b.len() != RECORD_SIZE {
            return Err(ReadRecordError::Other("wrong record size".into()));
        }
        let n = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize;
        if n > RECORD_SIZE - 4 {
            return Err(ReadRecordError::Other("malformed record".into()));
        }
        Record::from_json(&b[4..4 + n], id).map_err(ReadRecordError::Other)
    }

    /// Decrypts object `id` and checks it leads with its own ID and holds
    /// `part` bytes padded to their bucket. Returns the plaintext buffer.
    fn read_object(&self, id: Id, part: u64, mut lease: Lease) -> Result<Lease> {
        let p = self.path(OBJECTS, &id);
        let f = std::fs::File::open(&p).map_err(|e| Error::io("open", &p, &e))?;
        let padded = padded_size(ID_SIZE as u64 + part) as usize;
        match fury::decrypt_bounded_into(std::io::BufReader::new(f), &self.id, padded, lease.buf()) {
            Ok(()) => {}
            Err(fury::Error::TooLarge) => crate::bail!("object size does not match its catalogue record"),
            Err(e) => return Err(Error::new(e.to_string())),
        }
        let b = lease.buf().expose();
        if b.len() < ID_SIZE || b[..ID_SIZE] != id.0 {
            crate::bail!("object does not match its catalogue record");
        }
        if b.len() != padded {
            crate::bail!("object size does not match its catalogue record");
        }
        Ok(lease)
    }

    /// Removes `dir/<id>` and re-pins its shard's time. For records the
    /// shard is synced, so the removal is durable before any object goes.
    /// A missing file is reported with [`Kind::NotFound`].
    fn remove_file(&self, dir: &str, id: &Id, sync: bool) -> Result<()> {
        let p = self.path(dir, id);
        match std::fs::remove_file(&p) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::io("remove", &p, &e).with_kind(Kind::NotFound));
            }
            Err(e) => return Err(Error::io("remove", &p, &e)),
        }
        let shard = p.parent().expect("sharded");
        pfs::set_epoch(shard).map_err(|e| Error::io("chtimes", shard, &e))?;
        if sync && !self.no_sync {
            pfs::sync_dir(shard).map_err(|e| Error::io("sync", shard, &e))?;
        }
        Ok(())
    }

    fn remove_record(&self, id: &Id) -> Result<()> {
        self.remove_file(RECORDS, id, true).map_err(|e| e.with_kind(Kind::Other))
    }
}

/// Entries of `dir`, sorted by name, each with whether it is a directory
/// (not following symlinks), as Go's `os.ReadDir`.
fn sorted_dir(dir: &Path) -> Result<Vec<(std::ffi::OsString, bool)>> {
    let mut v = Vec::new();
    for e in std::fs::read_dir(dir).map_err(|e| Error::io("open", dir, &e))? {
        let e = e.map_err(|e| Error::io("readdir", dir, &e))?;
        let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
        v.push((e.file_name(), is_dir));
    }
    v.sort();
    Ok(v)
}

fn mode_of(m: &std::fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        m.permissions().mode() & 0o777
    }
    #[cfg(not(unix))]
    {
        // Go reports 0o444 for read-only files and 0o666 otherwise.
        if m.permissions().readonly() { 0o444 } else { 0o666 }
    }
}

/// Identity of a source file as read, so migrate deletes only that file.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SourceStamp {
    dev: u64,
    ino: u64,
    size: u64,
    mtime: Option<std::time::SystemTime>,
}

impl SourceStamp {
    pub fn of(m: &std::fs::Metadata) -> SourceStamp {
        #[cfg(unix)]
        let (dev, ino) = {
            use std::os::unix::fs::MetadataExt;
            (m.dev(), m.ino())
        };
        #[cfg(not(unix))]
        let (dev, ino) = (0, 0);
        SourceStamp {
            dev,
            ino,
            size: m.len(),
            mtime: m.modified().ok(),
        }
    }
}

/// Reads exactly `size` bytes from a file, then insists on end of file, so
/// a file that grew while being added is caught.
struct EndCheck<'a, R: Read> {
    inner: &'a mut R,
    size: u64,
    read: u64,
}

impl<R: Read> Read for EndCheck<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let want = (self.size - self.read).min(buf.len() as u64) as usize;
        let n = if want == 0 { 0 } else { self.inner.read(&mut buf[..want])? };
        self.read += n as u64;
        if self.read == self.size && (n > 0 || want == 0) {
            let mut b = [0u8; 1];
            loop {
                match self.inner.read(&mut b) {
                    Ok(0) => break,
                    Ok(_) => return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "source grew")),
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(n)
    }
}

/// Writes random entries sealed to a throwaway key, through the same code
/// as `add`: from 8 to 32 entries of log-uniformly random sizes, or more
/// until they total `target` bytes. Every vault therefore holds entries
/// nobody can open, so a file hidden from a decoy passphrase looks like
/// filler. Filler needs no per-file durability.
fn write_filler(root: &Path, target: u64, pool: Arc<Pool>, entropy: Entropy) -> Result<()> {
    let mut rng = entropy.rng(b"filler");
    let throwaway = Identity::generate(&mut rng);
    let s = Store::new(root, throwaway, pool, true, entropy);
    let upper = (target / 8).max(CHUNK_SIZE).min(1 << 30) as f64;
    let count = FILLER_MIN + rng.below(FILLER_MAX - FILLER_MIN + 1);
    let mut cat = Catalogue::default();
    let (mut i, mut total) = (0u64, 0u64);
    while i < count || total < target {
        let size = (1024.0 * (rng.f64() * (upper / 1024.0).ln()).exp()) as u64;
        let name = VaultName::new(&hex(&rng.array::<8>())).expect("hex is a valid name");
        let mut src = RandomReader(s.inner.entropy.rng(&rng.array::<16>()));
        s.add_reader(&mut cat, &mut src, size, 0o600, Instant::now(), &name)?;
        total += size;
        i += 1;
    }
    Ok(())
}

struct RandomReader(crate::rng::Rng);

impl Read for RandomReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.fill(buf);
        Ok(buf.len())
    }
}

#[cfg(test)]
mod tests;
