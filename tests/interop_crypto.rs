// SPDX-License-Identifier: GPL-3.0-or-later

//! Rust-to-Go: files the Rust implementation encrypts must open in the
//! frozen Go oracle, and files it corrupts must not.

mod common;

use vault::crypto::{fury, kem};

fn pattern(n: usize, salt: u8) -> Vec<u8> {
    (0..n).map(|i| (i.wrapping_mul(7) as u8) ^ salt).collect()
}

#[test]
fn go_decrypts_rust_files() {
    if !common::have_go() {
        return common::skip("go not installed");
    }
    let dir = tempfile_dir();
    let id = kem::Identity::from_suite_seed(kem::SUITE_ID, &pattern(32, 1)).unwrap();
    for size in [0usize, 1, 16, 65535, 65536, 65537, 131072, 300_001] {
        let mut out = Vec::new();
        fury::encrypt_to(&mut out, &id.recipient(), &pattern(size, 0x5a), &mut vault::rng::os());
        std::fs::write(dir.join(format!("pattern-{size}.fury")), &out).unwrap();
        if size == 65537 {
            let mut bad = out.clone();
            bad.truncate(bad.len() - 1);
            std::fs::write(dir.join("bad-truncated.fury"), &bad).unwrap();
            let mut bad = out.clone();
            bad.push(0);
            std::fs::write(dir.join("bad-trailing.fury"), &bad).unwrap();
            let mut bad = out;
            let mid = bad.len() / 2;
            bad[mid] ^= 4;
            std::fs::write(dir.join("bad-flipped.fury"), &bad).unwrap();
        }
    }
    let o = common::go_test("./internal/pqcrypt", "TestOracleDecrypt", &[("VAULT_ORACLE_DECRYPT", &dir)]);
    let log = String::from_utf8_lossy(&o.stdout);
    assert!(
        o.status.success(),
        "go oracle rejected Rust output:\n{log}{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert_eq!(log.matches(".fury ok").count(), 8, "{log}");
    std::fs::remove_dir_all(dir).unwrap();
}

fn tempfile_dir() -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "vault-interop-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}
