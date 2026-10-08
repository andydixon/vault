// SPDX-License-Identifier: GPL-3.0-or-later

//! Locked, non-dumpable memory for the agent's secret.
//!
//! [`LockedBuf`] is an anonymous private mapping of whole pages: it never
//! moves or grows, it is `mlock`ed (kept out of swap) before any secret is
//! written into it and, on Linux, excluded from core dumps with
//! `MADV_DONTDUMP`. On drop it is cleared with volatile writes, unlocked and
//! unmapped, in that order. Every system call result is checked; a failure
//! is an error, never a silent downgrade.
//!
//! [`harden_process`] sets the core-file size limit to zero and, on Linux,
//! `PR_SET_DUMPABLE` to 0, which also stops same-user `ptrace` and
//! `/proc/PID/mem` access. Other Unix systems get the rlimit only. Windows
//! is not supported by the agent (see SECURITY.md).

#[cfg(unix)]
use std::io;

#[cfg(unix)]
pub struct LockedBuf {
    ptr: std::ptr::NonNull<u8>,
    len: usize,
    map_len: usize,
}

// SAFETY: the buffer is uniquely owned; no aliasing pointers escape except
// through borrows of self.
#[cfg(unix)]
unsafe impl Send for LockedBuf {}

#[cfg(unix)]
impl LockedBuf {
    pub fn new(len: usize) -> io::Result<LockedBuf> {
        use rustix::mm::{MapFlags, ProtFlags, mlock, mmap_anonymous, munmap};
        let page = rustix::param::page_size();
        let map_len = len.div_ceil(page).max(1) * page;
        // SAFETY: a fresh anonymous private mapping at an address of the
        // kernel's choosing aliases nothing.
        let p = unsafe { mmap_anonymous(std::ptr::null_mut(), map_len, ProtFlags::READ | ProtFlags::WRITE, MapFlags::PRIVATE)? };
        let unmap = |p| {
            // SAFETY: p/map_len is exactly the mapping created above.
            let _ = unsafe { munmap(p, map_len) };
        };
        // SAFETY: the range is the mapping just created.
        if let Err(e) = unsafe { mlock(p, map_len) } {
            unmap(p);
            return Err(io::Error::new(e.kind(), format!("cannot lock agent memory (mlock): {e}")));
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            use rustix::mm::{Advice, madvise};
            // SAFETY: the range is the mapping just created.
            if let Err(e) = unsafe { madvise(p, map_len, Advice::LinuxDontDump) } {
                // SAFETY: as above.
                let _ = unsafe { rustix::mm::munlock(p, map_len) };
                unmap(p);
                return Err(io::Error::new(
                    e.kind(),
                    format!("cannot exclude agent memory from core dumps: {e}"),
                ));
            }
        }
        let ptr = std::ptr::NonNull::new(p.cast::<u8>()).expect("mmap returned null");
        Ok(LockedBuf { ptr, len, map_len })
    }

    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: ptr is valid for map_len >= len bytes for the life of self.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: as above, and &mut self guarantees exclusivity.
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }

    pub fn clear(&mut self) {
        // SAFETY: as above, over the whole mapping.
        let all = unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.map_len) };
        zeroize::Zeroize::zeroize(all);
    }
}

#[cfg(unix)]
impl Drop for LockedBuf {
    fn drop(&mut self) {
        self.clear();
        let p = self.ptr.as_ptr().cast();
        // SAFETY: p/map_len is the mapping owned by self, not used again.
        unsafe {
            let _ = rustix::mm::munlock(p, self.map_len);
            let _ = rustix::mm::munmap(p, self.map_len);
        }
    }
}

/// No core dumps; on Linux, not dumpable (and so not ptrace-able).
#[cfg(unix)]
pub fn harden_process() -> io::Result<()> {
    use rustix::process::{Resource, Rlimit, setrlimit};
    setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .map_err(|e| io::Error::new(e.kind(), format!("cannot disable core dumps: {e}")))?;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use rustix::process::{DumpableBehavior, dumpable_behavior, set_dumpable_behavior};
        set_dumpable_behavior(DumpableBehavior::NotDumpable)
            .map_err(|e| io::Error::new(e.kind(), format!("cannot make the agent undumpable: {e}")))?;
        if dumpable_behavior()? != DumpableBehavior::NotDumpable {
            return Err(io::Error::other("the agent is still dumpable"));
        }
    }
    Ok(())
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::*;

    #[test]
    fn locked_buf() {
        let mut b = LockedBuf::new(34).unwrap();
        assert_eq!(b.as_slice().len(), 34);
        b.as_mut_slice()[0] = 7;
        b.clear();
        assert!(b.as_slice().iter().all(|&x| x == 0));
    }
}
