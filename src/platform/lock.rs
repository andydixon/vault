// SPDX-License-Identifier: GPL-3.0-or-later

//! The vault lock on `DIR/.lock`, interoperable with the Go version on the
//! same store:
//!
//! - Unix: classic POSIX record locks (`fcntl(F_SETLK/F_SETLKW)` over the
//!   whole file), exactly what Go uses. Not `flock(2)`, which does not
//!   exclude `fcntl` locks on Linux, and not OFD locks. The kernel drops
//!   them when the process dies. POSIX record locks belong to the process,
//!   so this process must hold the lock file open only once.
//! - Windows: `LockFileEx` on byte 0, as Go does; released on death.
//! - Elsewhere: an exclusive `O_EXCL` lock file. A crash leaves it behind;
//!   after a minute of waiting the error names it for manual removal.
//!
//! Readers take the lock shared, writers exclusive. If it is held in a
//! conflicting mode, `waiting` is called once and the call blocks.

use std::fs::File;
use std::io;
use std::path::Path;

pub const LOCK_NAME: &str = ".lock";

/// A held lock; dropping it releases the lock.
pub struct Lock {
    _file: Option<File>,
    #[cfg(not(any(unix, windows)))]
    remove: Option<std::path::PathBuf>,
}

impl Drop for Lock {
    fn drop(&mut self) {
        #[cfg(not(any(unix, windows)))]
        if let Some(p) = self.remove.take() {
            let _ = std::fs::remove_file(p);
        }
    }
}

#[cfg(unix)]
pub fn acquire(path: &Path, exclusive: bool, waiting: &mut dyn FnMut()) -> io::Result<Lock> {
    use rustix::fs::{FlockOperation, fcntl_lock};
    use std::os::unix::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)?;
    let (try_op, wait_op) = if exclusive {
        (FlockOperation::NonBlockingLockExclusive, FlockOperation::LockExclusive)
    } else {
        (FlockOperation::NonBlockingLockShared, FlockOperation::LockShared)
    };
    match fcntl_lock(&f, try_op) {
        Ok(()) => {}
        Err(e) if e == rustix::io::Errno::AGAIN || e == rustix::io::Errno::ACCESS => {
            waiting();
            loop {
                match fcntl_lock(&f, wait_op) {
                    Ok(()) => break,
                    Err(rustix::io::Errno::INTR) => continue,
                    Err(e) => return Err(e.into()),
                }
            }
        }
        Err(e) => return Err(e.into()),
    }
    Ok(Lock { _file: Some(f) })
}

#[cfg(windows)]
pub fn acquire(path: &Path, exclusive: bool, waiting: &mut dyn FnMut()) -> io::Result<Lock> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::ERROR_LOCK_VIOLATION;
    use windows_sys::Win32::Storage::FileSystem::{LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx};
    use windows_sys::Win32::System::IO::OVERLAPPED;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    let flags = if exclusive { LOCKFILE_EXCLUSIVE_LOCK } else { 0 };
    let lock = |flags: u32| -> io::Result<()> {
        // SAFETY: the handle is valid for the life of `f`; the OVERLAPPED is
        // zeroed (offset 0) and outlives this synchronous call.
        let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
        let ok = unsafe { LockFileEx(f.as_raw_handle() as _, flags, 0, 1, 0, &mut ov) };
        if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
    };
    match lock(flags | LOCKFILE_FAIL_IMMEDIATELY) {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(ERROR_LOCK_VIOLATION as i32) => {
            waiting();
            lock(flags)?;
        }
        Err(e) => return Err(e),
    }
    Ok(Lock { _file: Some(f) })
}

#[cfg(not(any(unix, windows)))]
pub fn acquire(path: &Path, _exclusive: bool, waiting: &mut dyn FnMut()) -> io::Result<Lock> {
    for i in 0.. {
        match super::fs::create_new_private(path) {
            Ok(_) => {
                return Ok(Lock {
                    _file: None,
                    remove: Some(path.to_path_buf()),
                });
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
        if i == 0 {
            waiting();
        }
        if i == 600 {
            return Err(io::Error::other(format!(
                "vault still locked after a minute; if no other vault process is running, remove {}",
                path.display()
            )));
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    unreachable!()
}

/// Locks the vault at `root`. A shared (reader) lock on a read-only
/// filesystem, where nothing can be writing, proceeds without a lock; every
/// other failure is reported.
pub fn lock_vault(root: &Path, exclusive: bool) -> Result<Lock, String> {
    let path = root.join(LOCK_NAME);
    let mut waiting = || eprintln!("waiting for another vault process to finish");
    match acquire(&path, exclusive, &mut waiting) {
        Ok(l) => Ok(l),
        Err(e) if !exclusive && e.kind() == io::ErrorKind::ReadOnlyFilesystem => Ok(Lock {
            _file: None,
            #[cfg(not(any(unix, windows)))]
            remove: None,
        }),
        Err(e) => Err(format!("cannot lock the vault: {}", crate::util::io_msg("lock", &path, &e))),
    }
}
