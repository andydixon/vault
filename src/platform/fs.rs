// SPDX-License-Identifier: GPL-3.0-or-later

//! Filesystem primitives with the guarantees the store and extraction need.
//!
//! - [`publish`] moves a finished temporary file to its final name without
//!   ever replacing anything there, symlinks (dangling or not) included:
//!   `renameat2(RENAME_NOREPLACE)` on Linux, `renameatx_np(RENAME_EXCL)` on
//!   macOS, `link`+`unlink` on other Unix systems and when a Linux
//!   filesystem lacks RENAME_NOREPLACE, and `MoveFileExW` without
//!   `MOVEFILE_REPLACE_EXISTING` on Windows. There is no check-then-rename
//!   fallback: if no atomic primitive works, publishing fails.
//! - [`Dir`] creates and publishes files relative to an open directory. On
//!   Unix every path component below the chosen destination is opened with
//!   `O_NOFOLLOW|O_DIRECTORY`, so a symlink planted inside the destination
//!   cannot redirect extraction elsewhere. Windows has no `openat`; there
//!   each component is checked not to be a symlink or junction before use,
//!   which narrows but does not close the race (see SECURITY.md).
//! - [`sync_dir`] makes a directory's entries durable where the OS allows
//!   it (Unix). Windows offers no directory fsync through these APIs; NTFS
//!   journals metadata, and that is the durability on offer there.

use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

pub fn create_private_dir_all(p: &Path) -> io::Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    b.mode(0o700);
    b.create(p)
}

pub fn create_private_dir(p: &Path) -> io::Result<()> {
    let mut b = std::fs::DirBuilder::new();
    #[cfg(unix)]
    b.mode(0o700);
    b.create(p)
}

/// Creates a new file readable only by its owner; fails if `p` exists.
pub fn create_new_private(p: &Path) -> io::Result<File> {
    let mut o = OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    o.mode(0o600);
    o.open(p)
}

pub fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

/// Sets a path's access and modification times to the Unix epoch,
/// following symlinks, as Go's `os.Chtimes(p, epoch, epoch)`.
pub fn set_epoch(p: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use rustix::fs::{AtFlags, CWD, Timespec, Timestamps, utimensat};
        let z = Timespec { tv_sec: 0, tv_nsec: 0 };
        utimensat(
            CWD,
            p,
            &Timestamps {
                last_access: z,
                last_modification: z,
            },
            AtFlags::empty(),
        )?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let f = open_for_times(p)?;
        f.set_times(
            std::fs::FileTimes::new()
                .set_accessed(std::time::UNIX_EPOCH)
                .set_modified(std::time::UNIX_EPOCH),
        )
    }
}

#[cfg(windows)]
fn open_for_times(p: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_BACKUP_SEMANTICS, FILE_WRITE_ATTRIBUTES};
    OpenOptions::new()
        .access_mode(FILE_WRITE_ATTRIBUTES)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(p)
}

#[cfg(not(any(unix, windows)))]
fn open_for_times(p: &Path) -> io::Result<File> {
    OpenOptions::new().write(true).open(p)
}

fn random_suffix() -> String {
    let b: [u8; 8] = crate::rng::os().array();
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Creates `dir/<prefix><random>` exclusively, mode 0600.
pub fn create_temp(dir: &Path, prefix: &str) -> io::Result<(File, PathBuf)> {
    loop {
        let p = dir.join(format!("{prefix}{}", random_suffix()));
        match create_new_private(&p) {
            Ok(f) => return Ok((f, p)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
}

fn exists_error(dst: &Path) -> io::Error {
    io::Error::new(io::ErrorKind::AlreadyExists, format!("{} already exists", dst.display()))
}

/// Renames `tmp` to `dst` only if `dst` does not exist (in any form). On
/// failure `tmp` is left for the caller to remove.
pub fn publish(tmp: &Path, dst: &Path) -> io::Result<()> {
    let r = publish_inner(tmp, dst);
    match r {
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Err(exists_error(dst)),
        r => r,
    }
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn publish_inner(tmp: &Path, dst: &Path) -> io::Result<()> {
    use rustix::fs::{CWD, RenameFlags, renameat_with};
    match renameat_with(CWD, tmp, CWD, dst, RenameFlags::NOREPLACE) {
        Ok(()) => Ok(()),
        Err(e) if e == rustix::io::Errno::INVAL || e == rustix::io::Errno::NOSYS || e == rustix::io::Errno::NOTSUP => {
            link_publish(tmp, dst)
        }
        Err(e) => Err(e.into()),
    }
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "android", target_vendor = "apple"))))]
fn publish_inner(tmp: &Path, dst: &Path) -> io::Result<()> {
    link_publish(tmp, dst)
}

#[cfg(not(any(unix, windows)))]
fn publish_inner(tmp: &Path, dst: &Path) -> io::Result<()> {
    link_publish(tmp, dst)
}

/// `link` never replaces an existing name, so link-then-unlink is an
/// atomic no-clobber publish wherever hard links work.
#[cfg(not(windows))]
fn link_publish(tmp: &Path, dst: &Path) -> io::Result<()> {
    std::fs::hard_link(tmp, dst)?;
    // The data is safely at dst; a failure to drop the temporary name is
    // reported but dst stays.
    std::fs::remove_file(tmp)
}

#[cfg(windows)]
fn publish_inner(tmp: &Path, dst: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_WRITE_THROUGH, MoveFileExW};
    let w = |p: &Path| -> Vec<u16> { p.as_os_str().encode_wide().chain(Some(0)).collect() };
    let (a, b) = (w(tmp), w(dst));
    // SAFETY: both arguments are NUL-terminated UTF-16 strings that outlive
    // the call; MoveFileExW does not retain them.
    let ok = unsafe { MoveFileExW(a.as_ptr(), b.as_ptr(), MOVEFILE_WRITE_THROUGH) };
    if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

/// Sets permission bits as Go's `File.Chmod` does: all of `mode & 0o777`
/// on Unix, only the read-only attribute on Windows.
pub fn set_mode(f: &File, mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        f.set_permissions(std::fs::Permissions::from_mode(mode & 0o777))
    }
    #[cfg(not(unix))]
    {
        let mut p = f.metadata()?.permissions();
        p.set_readonly(mode & 0o200 == 0);
        f.set_permissions(p)
    }
}

/// A destination directory that files are created and published inside
/// without following symlinks below it.
pub struct Dir {
    path: PathBuf,
    #[cfg(unix)]
    fd: rustix::fd::OwnedFd,
}

impl Dir {
    /// Opens the chosen destination itself; a symlink here is followed,
    /// because the user named it. An empty path is the current directory
    /// (and names inside it are shown without a "./").
    pub fn open(path: &Path) -> io::Result<Dir> {
        let real = if path.as_os_str().is_empty() { Path::new(".") } else { path };
        #[cfg(unix)]
        {
            use rustix::fs::{CWD, Mode, OFlags, openat};
            let fd = openat(CWD, real, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC, Mode::empty())?;
            Ok(Dir {
                path: path.to_path_buf(),
                fd,
            })
        }
        #[cfg(not(unix))]
        {
            if !std::fs::metadata(real)?.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::NotADirectory,
                    format!("{} is not a directory", path.display()),
                ));
            }
            Ok(Dir { path: path.to_path_buf() })
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Opens (creating with mode 0700 if missing) the subdirectory `name`,
    /// refusing a symlink or anything that is not a directory.
    pub fn subdir(&self, name: &OsStr) -> io::Result<Dir> {
        check_component(name)?;
        let path = self.path.join(name);
        #[cfg(unix)]
        {
            use rustix::fs::{Mode, OFlags, mkdirat, openat};
            let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
            let open = || openat(&self.fd, name, flags, Mode::empty());
            let fd = match open() {
                Ok(fd) => fd,
                Err(rustix::io::Errno::NOENT) => {
                    match mkdirat(&self.fd, name, Mode::from_raw_mode(0o700)) {
                        Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                        Err(e) => return Err(e.into()),
                    }
                    open().map_err(|e| refuse(e, &path))?
                }
                Err(e) => return Err(refuse(e, &path)),
            };
            Ok(Dir { path, fd })
        }
        #[cfg(not(unix))]
        {
            match std::fs::symlink_metadata(&path) {
                Ok(m) if m.is_dir() && !m.file_type().is_symlink() && !is_reparse(&m) => {}
                Ok(_) => {
                    return Err(io::Error::other(format!("{} is not a directory, or is a link", path.display())));
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => match create_private_dir(&path) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => return self.subdir(name),
                    Err(e) => return Err(e),
                },
                Err(e) => return Err(e),
            }
            Ok(Dir { path })
        }
    }

    /// Creates a private temporary file in this directory.
    pub fn create_temp(&self, prefix: &str) -> io::Result<(File, std::ffi::OsString)> {
        loop {
            let name: std::ffi::OsString = format!("{prefix}{}", random_suffix()).into();
            #[cfg(unix)]
            let r = {
                use rustix::fs::{Mode, OFlags, openat};
                openat(
                    &self.fd,
                    &name,
                    OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::from_raw_mode(0o600),
                )
                .map(File::from)
                .map_err(io::Error::from)
            };
            #[cfg(not(unix))]
            let r = create_new_private(&self.path.join(&name));
            match r {
                Ok(f) => return Ok((f, name)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
    }

    /// Publishes `tmp` as `name` in this directory, never replacing
    /// anything already there.
    pub fn publish(&self, tmp: &OsStr, name: &OsStr) -> io::Result<()> {
        check_component(name)?;
        let dst = self.path.join(name);
        #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
        {
            use rustix::fs::{RenameFlags, renameat_with};
            match renameat_with(&self.fd, tmp, &self.fd, name, RenameFlags::NOREPLACE) {
                Ok(()) => return Ok(()),
                Err(rustix::io::Errno::EXIST) => return Err(exists_error(&dst)),
                Err(e) if e == rustix::io::Errno::INVAL || e == rustix::io::Errno::NOSYS || e == rustix::io::Errno::NOTSUP => {}
                Err(e) => return Err(e.into()),
            }
        }
        #[cfg(unix)]
        {
            use rustix::fs::{AtFlags, linkat, unlinkat};
            match linkat(&self.fd, tmp, &self.fd, name, AtFlags::empty()) {
                Ok(()) => {}
                Err(rustix::io::Errno::EXIST) => return Err(exists_error(&dst)),
                Err(e) => return Err(e.into()),
            }
            unlinkat(&self.fd, tmp, AtFlags::empty())?;
            Ok(())
        }
        #[cfg(not(unix))]
        {
            publish(&self.path.join(tmp), &dst)
        }
    }

    pub fn remove(&self, name: &OsStr) -> io::Result<()> {
        #[cfg(unix)]
        {
            rustix::fs::unlinkat(&self.fd, name, rustix::fs::AtFlags::empty())?;
            Ok(())
        }
        #[cfg(not(unix))]
        {
            std::fs::remove_file(self.path.join(name))
        }
    }

    pub fn sync(&self) -> io::Result<()> {
        #[cfg(unix)]
        {
            rustix::fs::fsync(&self.fd)?;
        }
        Ok(())
    }
}

#[cfg(unix)]
fn refuse(e: rustix::io::Errno, path: &Path) -> io::Error {
    if e == rustix::io::Errno::LOOP || e == rustix::io::Errno::NOTDIR {
        io::Error::other(format!(
            "{} is not a directory, or is a symlink; refusing to extract through it",
            path.display()
        ))
    } else {
        e.into()
    }
}

#[cfg(windows)]
fn is_reparse(m: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    m.file_attributes() & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(any(unix, windows)))]
fn is_reparse(_: &std::fs::Metadata) -> bool {
    false
}

/// A single, plain path component: no separators, not "." or "..".
fn check_component(name: &OsStr) -> io::Result<()> {
    let ok = !name.is_empty()
        && name != "."
        && name != ".."
        && Path::new(name).components().count() == 1
        && matches!(Path::new(name).components().next(), Some(std::path::Component::Normal(_)));
    if ok {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid path component {:?}", name),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("vault-fs-{tag}-{}-{}", std::process::id(), random_suffix()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn publish_never_replaces() {
        let d = tmpdir("pub");
        let (_, t1) = create_temp(&d, ".t-").unwrap();
        std::fs::write(&t1, b"one").unwrap();
        publish(&t1, &d.join("out")).unwrap();
        let (_, t2) = create_temp(&d, ".t-").unwrap();
        std::fs::write(&t2, b"two").unwrap();
        let e = publish(&t2, &d.join("out")).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(d.join("out")).unwrap(), b"one");
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(d.join("nowhere"), d.join("dangling")).unwrap();
            assert_eq!(publish(&t2, &d.join("dangling")).unwrap_err().kind(), io::ErrorKind::AlreadyExists);
            assert!(!d.join("nowhere").exists(), "followed a dangling symlink");
        }
        std::fs::remove_dir_all(d).unwrap();
    }

    /// Many threads race to publish the same name: exactly one wins and
    /// every loser's file is left for it to clean up.
    #[test]
    fn concurrent_publishers() {
        let d = tmpdir("race");
        let wins = std::sync::atomic::AtomicUsize::new(0);
        std::thread::scope(|s| {
            for i in 0..16 {
                let (d, wins) = (&d, &wins);
                s.spawn(move || {
                    let dir = Dir::open(d).unwrap();
                    let (mut f, t) = dir.create_temp(".t-").unwrap();
                    std::io::Write::write_all(&mut f, format!("{i}").as_bytes()).unwrap();
                    match dir.publish(&t, OsStr::new("same")) {
                        Ok(()) => {
                            wins.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        }
                        Err(e) => {
                            assert_eq!(e.kind(), io::ErrorKind::AlreadyExists);
                            dir.remove(&t).unwrap();
                        }
                    }
                });
            }
        });
        assert_eq!(wins.into_inner(), 1);
        assert_eq!(std::fs::read_dir(&d).unwrap().count(), 1);
        std::fs::remove_dir_all(d).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn subdir_refuses_symlinks() {
        let d = tmpdir("conf");
        let outside = tmpdir("outside");
        std::os::unix::fs::symlink(&outside, d.join("evil")).unwrap();
        let dir = Dir::open(&d).unwrap();
        assert!(dir.subdir(OsStr::new("evil")).is_err());
        assert!(dir.subdir(OsStr::new("..")).is_err());
        assert!(dir.subdir(OsStr::new("a/b")).is_err());
        let sub = dir.subdir(OsStr::new("ok")).unwrap();
        assert!(sub.path().ends_with("ok"));
        std::fs::write(d.join("file"), b"").unwrap();
        assert!(dir.subdir(OsStr::new("file")).is_err());
        assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
        std::fs::remove_dir_all(d).unwrap();
        std::fs::remove_dir_all(outside).unwrap();
    }

    #[test]
    fn epoch_times() {
        let d = tmpdir("epoch");
        let f = d.join("f");
        std::fs::write(&f, b"x").unwrap();
        set_epoch(&f).unwrap();
        set_epoch(&d).unwrap();
        for p in [&f, &d] {
            assert_eq!(std::fs::metadata(p).unwrap().modified().unwrap(), std::time::UNIX_EPOCH);
        }
        std::fs::remove_dir_all(d).unwrap();
    }
}
