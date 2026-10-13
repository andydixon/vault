// SPDX-License-Identifier: GPL-3.0-or-later
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

pub fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Whether the Go toolchain is available for oracle-backed tests. When it
/// is not, those tests print SKIPPED and return; CI installs Go so they
/// always run there (VAULT_REQUIRE_ORACLE=1 turns a skip into a failure).
pub fn have_go() -> bool {
    let ok = Command::new("go").arg("version").output().is_ok_and(|o| o.status.success());
    if !ok && std::env::var_os("VAULT_REQUIRE_ORACLE").is_some() {
        panic!("VAULT_REQUIRE_ORACLE is set but go is not available");
    }
    ok
}

pub fn skip(why: &str) {
    eprintln!("SKIPPED: {why}");
}

/// Builds the Go oracle CLI once per test process ($VAULT_GO_ORACLE wins).
pub fn go_oracle() -> Option<PathBuf> {
    static BIN: OnceLock<Option<PathBuf>> = OnceLock::new();
    BIN.get_or_init(|| {
        if let Some(p) = std::env::var_os("VAULT_GO_ORACLE") {
            return Some(PathBuf::from(p));
        }
        if !have_go() {
            return None;
        }
        let out = root()
            .join("target")
            .join(format!("vault-go-oracle{}", std::env::consts::EXE_SUFFIX));
        let st = Command::new("go")
            .args(["build", "-o"])
            .arg(&out)
            .arg(".")
            .current_dir(root().join("oracle/go"))
            .env("CGO_ENABLED", "0")
            .status()
            .expect("run go build");
        assert!(st.success(), "building the Go oracle failed");
        Some(out)
    })
    .clone()
}

pub fn go_test(pkg: &str, test: &str, env: &[(&str, &Path)]) -> std::process::Output {
    let mut c = Command::new("go");
    c.args(["test", "-count=1", "-v", "-run", &format!("^{test}$"), pkg])
        .current_dir(root().join("oracle/go"));
    for (k, v) in env {
        c.env(k, v);
    }
    c.output().expect("run go test")
}
