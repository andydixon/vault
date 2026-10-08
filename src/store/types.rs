// SPDX-License-Identifier: GPL-3.0-or-later

//! Validated values that reach paths, the catalogue and extraction.
//! Each is constructed only through a checking constructor, so raw
//! untrusted strings cannot be used where one of these is expected.

use crate::secret::SecretArray;
use crate::util::Instant;
use hmac::{KeyInit, Mac};
use zeroize::Zeroizing;

pub const NAME_LIMIT: usize = 1024;
pub const FILE_LIMIT: u64 = 1 << 40;
pub const ID_SIZE: usize = 16;
pub const SEED_SIZE: usize = 32;
pub const RECORD_SIZE: usize = 4096;
pub const MIN_PADDING: u64 = 64 << 10;
/// The largest bucket, and so the largest object plaintext.
pub const CHUNK_SIZE: u64 = MIN_PADDING << 6;
/// File bytes per object: an object's plaintext starts with its 16-byte ID.
pub const CHUNK_DATA: u64 = CHUNK_SIZE - ID_SIZE as u64;

/// A name inside the vault: non-empty UTF-8 of at most 1024 bytes, already
/// clean in the sense of Go's `path.Clean`, relative, not `.`/`..` or under
/// `..`, without backslashes or control characters.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct VaultName(String);

impl VaultName {
    pub fn new(name: &str) -> Option<VaultName> {
        valid_name(name).then(|| VaultName(name.to_string()))
    }

    pub fn from_bytes(b: &[u8]) -> Option<VaultName> {
        VaultName::new(std::str::from_utf8(b).ok()?)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Path components, each a plain non-empty segment.
    pub fn components(&self) -> impl Iterator<Item = &str> {
        self.0.split('/')
    }
}

impl std::fmt::Display for VaultName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= NAME_LIMIT
        && crate::util::clean(name) == name
        && !name.starts_with('/')
        && name != "."
        && name != ".."
        && !name.starts_with("../")
        && !name.contains('\\')
        && !name.chars().any(char::is_control)
}

/// A 16-byte object or record ID, shown and stored as lowercase hex.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Id(pub [u8; ID_SIZE]);

impl Id {
    pub fn random(rng: &mut crate::rng::Rng) -> Id {
        Id(rng.array())
    }

    /// Only exact lowercase hex of the right length, as Go's `validHex`.
    pub fn parse(s: &str) -> Option<Id> {
        let b = parse_hex(s)?;
        Some(Id(b.try_into().ok()?))
    }

    pub fn hex(&self) -> String {
        hex(&self.0)
    }

    pub fn shard(&self) -> String {
        format!("{:02x}", self.0[0])
    }
}

pub fn hex(b: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push(D[(x >> 4) as usize] as char);
        s.push(D[(x & 15) as usize] as char);
    }
    s
}

pub fn parse_hex(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if b.len() % 2 != 0 {
        return None;
    }
    let v = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    b.chunks(2).map(|p| Some(v(p[0])? << 4 | v(p[1])?)).collect()
}

/// The secret per-file seed whose HMAC derives the file's object IDs.
pub struct ObjectSeed(SecretArray<SEED_SIZE>);

impl ObjectSeed {
    pub fn random(rng: &mut crate::rng::Rng) -> ObjectSeed {
        let mut s = SecretArray::zero();
        rng.fill(s.expose_mut());
        ObjectSeed(s)
    }

    pub fn parse(s: &str) -> Option<ObjectSeed> {
        let b = Zeroizing::new(parse_hex(s)?);
        SecretArray::from_slice(&b).map(ObjectSeed)
    }

    pub fn hex(&self) -> Zeroizing<String> {
        Zeroizing::new(hex(self.0.expose()))
    }

    /// An explicit copy, for a record copied under another name.
    pub fn duplicate(&self) -> ObjectSeed {
        ObjectSeed(SecretArray::from_slice(self.0.expose()).expect("same size"))
    }

    pub fn same_as(&self, other: &ObjectSeed) -> bool {
        crate::secret::subtle_eq::ct_eq(self.0.expose(), other.0.expose())
    }

    /// The `i`th object's ID: HMAC-SHA-256(seed, big-endian i)[:16].
    pub fn object_id(&self, i: u64) -> Id {
        let mut m = <hmac::Hmac<sha2::Sha256> as KeyInit>::new_from_slice(self.0.expose()).expect("any key size");
        m.update(&(i as i64).to_be_bytes());
        let out = m.finalize().into_bytes();
        let mut id = [0u8; ID_SIZE];
        id.copy_from_slice(&out[..ID_SIZE]);
        Id(id)
    }
}

/// How many objects hold a file of `size` bytes: at least one.
pub fn object_count(size: u64) -> u64 {
    size.div_ceil(CHUNK_DATA).max(1)
}

/// `size` rounded up to the next power-of-two bucket of at least 64 KiB.
pub fn padded_size(size: u64) -> u64 {
    let mut p = MIN_PADDING;
    while p < size {
        p *= 2;
    }
    p
}

/// A decrypted, validated catalogue record. Only the store constructs
/// these, from authenticated plaintext or from its own writes.
pub struct Record {
    pub name: VaultName,
    pub seed: ObjectSeed,
    pub size: u64,
    pub mode: u32,
    pub modified: Instant,
    pub added: Instant,
    /// The record file's ID; not stored inside the record.
    pub id: Id,
}

impl Record {
    /// The bytes of object `i` that are file data, after its ID prefix.
    pub fn part(&self, i: u64) -> u64 {
        let before = i * CHUNK_DATA;
        (self.size - before).min(CHUNK_DATA)
    }

    /// A copy under another name, sharing the objects.
    pub fn copy_as(&self, name: VaultName, id: Id) -> Record {
        Record {
            name,
            seed: self.seed.duplicate(),
            size: self.size,
            mode: self.mode,
            modified: self.modified,
            added: self.added,
            id,
        }
    }

    /// The record's JSON exactly as Go's `encoding/json` writes it, or None
    /// if a timestamp is outside what Go can encode.
    pub fn to_json(&self) -> Option<Zeroizing<Vec<u8>>> {
        let mut o = Zeroizing::new(Vec::with_capacity(256));
        o.extend_from_slice(b"{\"name\":");
        go_json_string(&mut o, &self.name.0);
        o.extend_from_slice(b",\"seed\":\"");
        o.extend_from_slice(self.seed.hex().as_bytes());
        o.extend_from_slice(format!("\",\"size\":{},\"mode\":{},\"modified\":\"", self.size, self.mode).as_bytes());
        o.extend_from_slice(self.modified.to_rfc3339()?.as_bytes());
        o.extend_from_slice(b"\",\"added\":\"");
        o.extend_from_slice(self.added.to_rfc3339()?.as_bytes());
        o.extend_from_slice(b"\"}");
        Some(o)
    }

    /// Parses and validates record JSON. Stricter than Go in one way: field
    /// names must match exactly and every field must be present, as Go
    /// always writes them.
    pub fn from_json(b: &[u8], id: Id) -> Result<Record, String> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            name: String,
            seed: Zeroizing<String>,
            size: i64,
            mode: u32,
            modified: String,
            added: String,
        }
        let r: Raw = serde_json::from_slice(b).map_err(|e| e.to_string())?;
        let malformed = || "malformed record".to_string();
        let name = VaultName::new(&r.name).ok_or_else(malformed)?;
        let seed = ObjectSeed::parse(&r.seed).ok_or_else(malformed)?;
        if r.size < 0 || r.size as u64 > FILE_LIMIT {
            return Err(malformed());
        }
        let modified = Instant::parse_rfc3339(&r.modified).ok_or_else(|| format!("parsing time {:?}", r.modified))?;
        let added = Instant::parse_rfc3339(&r.added).ok_or_else(|| format!("parsing time {:?}", r.added))?;
        Ok(Record {
            name,
            seed,
            size: r.size as u64,
            mode: r.mode,
            modified,
            added,
            id,
        })
    }
}

/// Go's JSON string encoding with HTML escaping (its default).
fn go_json_string(o: &mut Vec<u8>, s: &str) {
    o.push(b'"');
    for c in s.chars() {
        match c {
            '"' => o.extend_from_slice(b"\\\""),
            '\\' => o.extend_from_slice(b"\\\\"),
            '\n' => o.extend_from_slice(b"\\n"),
            '\r' => o.extend_from_slice(b"\\r"),
            '\t' => o.extend_from_slice(b"\\t"),
            '\u{8}' => o.extend_from_slice(b"\\b"),
            '\u{c}' => o.extend_from_slice(b"\\f"),
            '<' | '>' | '&' | '\u{2028}' | '\u{2029}' => o.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes()),
            c if (c as u32) < 0x20 => o.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes()),
            c => {
                let mut b = [0u8; 4];
                o.extend_from_slice(c.encode_utf8(&mut b).as_bytes());
            }
        }
    }
    o.push(b'"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn v() -> Value {
        serde_json::from_str(include_str!("../../tests/vectors/store.json")).unwrap()
    }

    #[test]
    fn names_match_go() {
        for (h, want) in v()["valid_name_hex"].as_object().unwrap() {
            let b = parse_hex(h).unwrap();
            assert_eq!(
                VaultName::from_bytes(&b).is_some(),
                want.as_bool().unwrap(),
                "{:?}",
                String::from_utf8_lossy(&b)
            );
        }
    }

    #[test]
    fn object_ids_and_sizes_match_go() {
        let v = v();
        let o = &v["object_ids"];
        let seed = ObjectSeed::parse(o["seed"].as_str().unwrap()).unwrap();
        for (i, id) in o["ids"].as_array().unwrap().iter().enumerate() {
            assert_eq!(seed.object_id(i as u64).hex(), id.as_str().unwrap());
        }
        assert_eq!(
            seed.object_id(o["big_index_value"].as_u64().unwrap()).hex(),
            o["big_index"].as_str().unwrap()
        );
        for (n, want) in v["padded_size"].as_object().unwrap() {
            assert_eq!(padded_size(n.parse().unwrap()), want.as_u64().unwrap(), "paddedSize({n})");
        }
        for (n, want) in v["object_count"].as_object().unwrap() {
            assert_eq!(object_count(n.parse().unwrap()), want.as_u64().unwrap(), "objectCount({n})");
        }
    }

    #[test]
    fn record_json_matches_go() {
        for r in v()["records"].as_array().unwrap() {
            let json = r["json"].as_str().unwrap().as_bytes();
            let n = r["name"].as_str().unwrap();
            // The name's escaping, whether or not it is a valid vault name.
            let mut enc = Vec::new();
            go_json_string(&mut enc, n);
            let text = r["json"].as_str().unwrap();
            assert_eq!(
                &enc[..],
                text["{\"name\":".len()..text.find(",\"seed\"").unwrap()].as_bytes(),
                "escaping of {n:?}"
            );
            if VaultName::new(n).is_none() {
                assert!(Record::from_json(json, Id([0; 16])).is_err());
                continue;
            }
            let rec = Record::from_json(json, Id([0; 16])).unwrap();
            assert_eq!(rec.name.as_str(), r["name"].as_str().unwrap());
            // Go's UnixNano wraps outside about 1678-2262; so does this.
            let ns = |i: Instant| i.secs.wrapping_mul(1_000_000_000).wrapping_add(i.nanos as i64);
            assert_eq!(ns(rec.modified), r["modified_unix_nano"].as_i64().unwrap());
            assert_eq!(ns(rec.added), r["added_unix_nano"].as_i64().unwrap());
            assert_eq!(&rec.to_json().unwrap()[..], json, "byte-identical encoding");
        }
    }

    #[test]
    fn record_json_rejects_bad_records() {
        let good = br#"{"name":"a","seed":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","size":1,"mode":420,"modified":"2020-01-01T00:00:00Z","added":"2020-01-01T00:00:00Z"}"#;
        assert!(Record::from_json(good, Id([0; 16])).is_ok());
        let s = std::str::from_utf8(good).unwrap();
        for bad in [
            s.replace("\"a\"", "\"../a\""),
            s.replace("\"a\"", "\"\""),
            s.replace("0001", "0X01"),
            s.replace("0001", "0A01"),
            s.replace("1e1f", "1e"),
            s.replace("\"size\":1", "\"size\":-1"),
            s.replace("\"size\":1", "\"size\":1099511627777"),
            s.replace("\"size\":1", "\"size\":1.5"),
            s.replace("\"mode\":420", "\"mode\":-1"),
            s.replace("}", ",\"extra\":1}"),
            s.replace("\"name\"", "\"Name\""),
            s.replace("2020-01-01T00:00:00Z\",\"added", "yesterday\",\"added"),
            s.replace(",\"mode\":420", ""),
            format!("{s}trailing"),
        ] {
            assert!(Record::from_json(bad.as_bytes(), Id([0; 16])).is_err(), "{bad}");
        }
    }

    #[test]
    fn hex_is_strict() {
        assert!(Id::parse("00112233445566778899aabbccddeeff").is_some());
        assert!(Id::parse("00112233445566778899AABBCCDDEEFF").is_none());
        assert!(Id::parse("00112233445566778899aabbccddeef").is_none());
        assert!(Id::parse("00112233445566778899aabbccddeeff00").is_none());
    }
}
