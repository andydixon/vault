// SPDX-License-Identifier: GPL-3.0-or-later

//! The key agent, wire-compatible with the Go version: `vault unlock`
//! starts a copy of this binary as a hidden `__agent` process, hands it the
//! suite ID and master seed over a pipe (never argv, never disk), and the
//! agent serves them on a Unix socket in a per-user 0700 directory until a
//! deadline, fixed or (with `--idle`) moved on each use, or `vault lock`.
//!
//! Protocol: the client connects and sends one byte, `g` (get: the agent
//! replies with the 2-byte big-endian suite ID and 32-byte seed) or `q`
//! (quit: the agent wipes the key and closes). Every request has a
//! two-second deadline. The socket is
//! `$XDG_RUNTIME_DIR` (else the temp dir) `/vault-UID/agent-` + the first 8
//! bytes of SHA-256(absolute key path) in hex, exactly as Go computes it,
//! so a Go client can use a Rust agent and the other way round.
//!
//! Before it accepts the secret, the agent disables core dumps, makes
//! itself undumpable (Linux) and locks the page that will hold the secret;
//! if any of that fails it reports why and exits without the key.

use crate::crypto::kem::Identity;
use crate::error::{Error, Result};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const AGENT_CMD: &str = "__agent";
#[cfg_attr(not(unix), allow(dead_code))]
const GET: u8 = b'g';
#[cfg_attr(not(unix), allow(dead_code))]
const QUIT: u8 = b'q';
#[cfg_attr(not(unix), allow(dead_code))]
const REPLY: usize = 2 + crate::crypto::kem::SEED_SIZE;
#[cfg_attr(not(unix), allow(dead_code))]
const TIMEOUT: Duration = Duration::from_secs(2);
/// How long `unlock` waits for a starting agent to say it is ready.
#[cfg_attr(not(unix), allow(dead_code))]
const START_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg_attr(not(unix), allow(dead_code))]
const SECRET_ENVS: [&str; 2] = ["VAULT_PASSPHRASE", "VAULT_DECOY_PASSPHRASE"];

/// Go's `filepath.Abs`: lexical, with `os.Getwd`'s preference for `$PWD`.
pub fn go_abs(p: &Path) -> std::io::Result<PathBuf> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let joined = if p.is_absolute() { p.to_path_buf() } else { go_getwd()?.join(p) };
        let s = std::str::from_utf8(joined.as_os_str().as_bytes()).map_err(|_| std::io::Error::other("key path is not valid UTF-8"))?;
        Ok(PathBuf::from(crate::util::clean(s)))
    }
    #[cfg(not(unix))]
    {
        std::path::absolute(p)
    }
}

#[cfg(unix)]
fn go_getwd() -> std::io::Result<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    let dot = std::fs::metadata(".")?;
    if let Some(pwd) = std::env::var_os("PWD").map(PathBuf::from)
        && pwd.is_absolute()
        && let Ok(m) = std::fs::metadata(&pwd)
        && m.dev() == dot.dev()
        && m.ino() == dot.ino()
    {
        return Ok(pwd);
    }
    std::env::current_dir()
}

/// The agent socket for the key file at `key`, creating the private
/// per-user directory if needed and refusing one that is not private.
pub fn socket_path(key: &Path) -> Result<PathBuf> {
    use sha2::Digest;
    let abs = go_abs(key).map_err(|e| Error::io("abs", key, &e))?;
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(go_temp_dir);
    let dir = base.join(format!("vault-{}", uid()));
    match crate::platform::fs::create_private_dir(&dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(Error::io("mkdir", &dir, &e)),
    }
    private_dir(&dir)?;
    let sum = sha2::Sha256::digest(abs.as_os_str().as_encoded_bytes());
    Ok(dir.join(format!("agent-{}", crate::store::hex(&sum[..8]))))
}

/// Go's `os.TempDir`: `$TMPDIR` or /tmp on Unix.
fn go_temp_dir() -> PathBuf {
    #[cfg(unix)]
    {
        std::env::var_os("TMPDIR")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/tmp"))
    }
    #[cfg(not(unix))]
    {
        std::env::temp_dir()
    }
}

fn uid() -> u32 {
    #[cfg(unix)]
    {
        rustix::process::getuid().as_raw()
    }
    #[cfg(not(unix))]
    {
        // Go's os.Getuid returns -1 on Windows.
        u32::MAX
    }
}

/// A real directory, owned by this user, with mode exactly 0700.
#[cfg(unix)]
fn private_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let m = std::fs::symlink_metadata(dir).map_err(|e| Error::io("lstat", dir, &e))?;
    if !m.is_dir() || m.uid() != uid() || m.permissions().mode() & 0o777 != 0o700 {
        crate::bail!("{} is not a private directory of this user", dir.display());
    }
    Ok(())
}

#[cfg(not(unix))]
fn private_dir(_: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
mod imp {
    use super::*;
    use crate::platform::memory::{LockedBuf, harden_process};
    use std::io::{Read, Write};
    use std::os::unix::net::{UnixListener, UnixStream};

    fn dial(key: &Path, op: u8) -> Result<UnixStream> {
        let sock = socket_path(key)?;
        let c = UnixStream::connect(&sock).map_err(|e| Error::io("dial", &sock, &e))?;
        c.set_read_timeout(Some(TIMEOUT))?;
        c.set_write_timeout(Some(TIMEOUT))?;
        (&c).write_all(&[op])?;
        Ok(c)
    }

    /// The identity a running agent holds for `key`.
    pub fn identity(key: &Path) -> Result<Identity> {
        let mut c = dial(key, GET)?;
        let mut buf = crate::secret::SecretArray::<REPLY>::zero();
        c.read_exact(buf.expose_mut())?;
        let b = buf.expose();
        Identity::from_suite_seed(u16::from_be_bytes([b[0], b[1]]), &b[2..]).map_err(Error::from)
    }

    /// Tells the agent for `key` to forget it; whether one was running.
    pub fn stop(key: &Path) -> bool {
        let Ok(mut c) = dial(key, QUIT) else { return false };
        // Returns once the agent has wiped the key and closed.
        let _ = std::io::copy(&mut c, &mut std::io::sink());
        true
    }

    /// The command that starts an agent: this binary, with passphrase
    /// variables removed from its environment and nothing secret in argv.
    pub fn command(sock: &Path, ttl: Duration, idle: bool) -> Result<std::process::Command> {
        let exe =
            std::env::current_exe().map_err(|e| Error::new(format!("cannot find this executable: {}", crate::util::io_reason(&e))))?;
        let mut c = std::process::Command::new(exe);
        c.arg(AGENT_CMD)
            .arg(sock)
            .arg(crate::util::format_duration(ttl))
            .arg(if idle { "idle" } else { "fixed" });
        for v in SECRET_ENVS {
            c.env_remove(v);
        }
        c.current_dir("/")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null());
        Ok(c)
    }

    /// Replaces any agent for `key` with one holding `id` for `ttl`.
    pub fn start(key: &Path, id: &Identity, ttl: Duration, idle: bool) -> Result<()> {
        let sock = socket_path(key)?;
        stop(key);
        let mut child = command(&sock, ttl, idle)?
            .spawn()
            .map_err(|e| Error::new(format!("cannot start the agent: {}", crate::util::io_reason(&e))))?;
        let mut secret = crate::secret::SecretArray::<REPLY>::zero();
        secret.expose_mut()[..2].copy_from_slice(&id.suite_id().to_be_bytes());
        secret.expose_mut()[2..].copy_from_slice(id.seed());
        let mut stdin = child.stdin.take().expect("piped");
        let wrote = stdin.write_all(secret.expose());
        drop(secret);
        drop(stdin);
        let mut stdout = child.stdout.take().expect("piped");
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut msg = Vec::new();
            let _ = stdout.by_ref().take(4096).read_to_end(&mut msg);
            let _ = tx.send(msg);
        });
        // The agent closes its standard output once listening, after saying
        // "ok" or why not.
        let msg = rx.recv_timeout(START_TIMEOUT);
        let fail = |child: &mut std::process::Child, why: String| {
            let _ = child.kill();
            let _ = child.wait();
            Err(Error::new(why))
        };
        if let Err(e) = wrote {
            return fail(
                &mut child,
                format!("cannot hand the key to the agent: {}", crate::util::io_reason(&e)),
            );
        }
        match msg {
            Ok(m) if m == b"ok" => Ok(()),
            Ok(m) => fail(&mut child, format!("agent did not start: {}", String::from_utf8_lossy(&m).trim())),
            Err(_) => fail(&mut child, "agent did not start in time".into()),
        }
    }

    /// The agent process. Returns when it expires or is told to quit.
    pub fn run(sock: &Path, ttl: &str, mode: &str) {
        let mut out = std::io::stdout();
        let report = |out: &mut std::io::Stdout, msg: &str| {
            let _ = out.write_all(msg.as_bytes());
            let _ = out.flush();
            // Closing standard output (by pointing it at /dev/null) tells
            // `unlock` the outcome is final.
            if let Ok(null) = rustix::fs::open("/dev/null", rustix::fs::OFlags::WRONLY, rustix::fs::Mode::empty()) {
                let _ = rustix::stdio::dup2_stdout(&null);
            }
        };
        let ttl = match crate::util::parse_duration(ttl) {
            Ok(n) if n > 0 && (mode == "fixed" || mode == "idle") => Duration::from_nanos(n as u64),
            _ => return report(&mut out, "bad duration or mode"),
        };
        if let Err(e) = harden_process() {
            return report(&mut out, &e.to_string());
        }
        let mut secret = match LockedBuf::new(REPLY) {
            Ok(b) => b,
            Err(e) => return report(&mut out, &e.to_string()),
        };
        if std::io::stdin().lock().read_exact(secret.as_mut_slice()).is_err() {
            return report(&mut out, "no key received");
        }
        {
            let s = secret.as_slice();
            if let Err(e) = Identity::from_suite_seed(u16::from_be_bytes([s[0], s[1]]), &s[2..]) {
                return report(&mut out, &e);
            }
        }
        // A socket left by an agent that died stops bind; start has already
        // stopped any live one.
        let _ = std::fs::remove_file(sock);
        let l = match UnixListener::bind(sock) {
            Ok(l) => l,
            Err(e) => return report(&mut out, &crate::util::io_msg("listen unix", sock, &e)),
        };
        let ours = match std::fs::symlink_metadata(sock) {
            Ok(m) => m,
            Err(e) => return report(&mut out, &crate::util::io_msg("stat", sock, &e)),
        };
        let cleanup = || {
            // Remove the socket only if it is still the one this agent made.
            use std::os::unix::fs::MetadataExt;
            if let Ok(m) = std::fs::symlink_metadata(sock)
                && m.ino() == ours.ino()
                && m.dev() == ours.dev()
            {
                let _ = std::fs::remove_file(sock);
            }
        };
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) = std::fs::set_permissions(sock, std::fs::Permissions::from_mode(0o600)).and_then(|_| l.set_nonblocking(true)) {
                cleanup();
                return report(&mut out, &crate::util::io_msg("chmod", sock, &e));
            }
        }
        report(&mut out, "ok");
        serve(&l, &mut secret, ttl, mode == "idle");
        secret.clear();
        drop(secret);
        cleanup();
    }

    /// Serves until the deadline. The listener is polled with a timeout, so
    /// expiry never waits for another client; each request is bounded by
    /// two seconds and by the time left.
    fn serve(l: &UnixListener, secret: &mut LockedBuf, ttl: Duration, idle: bool) {
        use rustix::event::{PollFd, PollFlags, Timespec, poll};
        let mut deadline = std::time::Instant::now() + ttl;
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                return;
            }
            let t = Timespec {
                tv_sec: left.as_secs() as i64,
                tv_nsec: left.subsec_nanos() as _,
            };
            let mut fds = [PollFd::new(l, PollFlags::IN)];
            match poll(&mut fds, Some(&t)) {
                Ok(0) => continue,
                Ok(_) => {}
                Err(rustix::io::Errno::INTR) => continue,
                Err(_) => return,
            }
            let Ok((c, _)) = l.accept() else { continue };
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                return;
            }
            let limit = left.min(TIMEOUT);
            if c.set_nonblocking(false)
                .and_then(|_| c.set_read_timeout(Some(limit)))
                .and_then(|_| c.set_write_timeout(Some(limit)))
                .is_err()
            {
                continue;
            }
            let mut op = [0u8; 1];
            if (&c).read_exact(&mut op).is_err() {
                continue;
            }
            match op[0] {
                GET => {
                    if std::time::Instant::now() < deadline {
                        let _ = (&c).write_all(secret.as_slice());
                        if idle {
                            deadline = std::time::Instant::now() + ttl;
                        }
                    }
                }
                QUIT => {
                    secret.clear();
                    drop(c);
                    return;
                }
                _ => {}
            }
        }
    }
}

#[cfg(unix)]
pub use imp::{command, identity, run, start, stop};

#[cfg(not(unix))]
mod imp {
    use super::*;
    const UNSUPPORTED: &str = "vault unlock is not supported on this platform; use the passphrase each time";

    pub fn identity(_: &Path) -> Result<Identity> {
        Err(Error::new(UNSUPPORTED))
    }
    pub fn stop(_: &Path) -> bool {
        false
    }
    pub fn start(_: &Path, _: &Identity, _: Duration, _: bool) -> Result<()> {
        Err(Error::new(UNSUPPORTED))
    }
    pub fn run(_: &Path, _: &str, _: &str) {}
}

#[cfg(not(unix))]
pub use imp::{identity, run, start, stop};

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn command_strips_secrets_from_the_environment() {
        let c = command(Path::new("/x/sock"), Duration::from_secs(300), true).unwrap();
        let removed: Vec<_> = c
            .get_envs()
            .filter(|(_, v)| v.is_none())
            .map(|(k, _)| k.to_string_lossy().into_owned())
            .collect();
        for v in SECRET_ENVS {
            assert!(removed.iter().any(|r| r == v), "{v} not removed");
        }
        let args: Vec<_> = c.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
        assert_eq!(args, [AGENT_CMD, "/x/sock", "5m0s", "idle"]);
    }

    #[test]
    fn abs_is_lexical() {
        assert_eq!(go_abs(Path::new("/a/b/../c/./d")).unwrap(), PathBuf::from("/a/c/d"));
    }
}
