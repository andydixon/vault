// SPDX-License-Identifier: GPL-3.0-or-later

//! Shared helpers for unit tests.

use crate::store::hex;
use std::path::{Path, PathBuf};

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

pub fn walk(p: &Path) -> Vec<PathBuf> {
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
