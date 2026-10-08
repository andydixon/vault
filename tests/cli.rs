// SPDX-License-Identifier: GPL-3.0-or-later

//! The real binaries, end to end: the Rust CLI on its own, and the Rust
//! and Go CLIs sharing one key, one vault, one lock and one agent.
// The lock and agent tests are Unix-only; their imports are unused elsewhere.
#![cfg_attr(not(unix), allow(unused_imports))]

mod common;

use std::io::Write;
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const RUST: &str = env!("CARGO_BIN_EXE_vault");
const REAL: &str = "real passphrase for tests";
const DECOY: &str = "decoy passphrase for tests";

struct Env {
    dir: PathBuf,
}

impl Env {
    fn new(tag: &str) -> Env {
        let dir = std::env::temp_dir().join(format!(
            "vault-cli-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(dir.join("run")).unwrap();
        Env { dir }
    }

    fn cmd(&self, bin: &str, pass: Option<&str>) -> Command {
        let mut c = Command::new(bin);
        c.current_dir(&self.dir)
            .env_remove("VAULT_PASSPHRASE")
            .env_remove("VAULT_DECOY_PASSPHRASE")
            .env("VAULT_KEY", self.dir.join("key"))
            .env("VAULT_DIR", self.dir.join("store"))
            .env("XDG_RUNTIME_DIR", self.dir.join("run"))
            .stdin(Stdio::null());
        if let Some(p) = pass {
            c.env("VAULT_PASSPHRASE", p);
        }
        c
    }

    fn run(&self, bin: &str, pass: Option<&str>, args: &[&str]) -> Output {
        self.cmd(bin, pass).args(args).output().unwrap()
    }

    /// Runs and insists on success, returning stdout.
    fn ok(&self, bin: &str, pass: Option<&str>, args: &[&str]) -> String {
        let o = self.run(bin, pass, args);
        assert!(o.status.success(), "{bin} {args:?} failed: {}", String::from_utf8_lossy(&o.stderr));
        String::from_utf8(o.stdout).unwrap()
    }

    fn names(&self, bin: &str, pass: &str) -> Vec<String> {
        self.ok(bin, Some(pass), &["list"]).lines().map(|l| l[30..].to_string()).collect()
    }

    fn write(&self, rel: &str, body: &[u8]) -> PathBuf {
        let p = self.dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, body).unwrap();
        p
    }

    fn get(&self, bin: &str, pass: &str, name: &str) -> Vec<u8> {
        let out = format!("out-{}", self.dir.read_dir().unwrap().count());
        self.ok(bin, Some(pass), &["get", name, "-o", &out]);
        std::fs::read(self.dir.join(out)).unwrap()
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = Command::new(RUST)
            .arg("lock")
            .env("VAULT_KEY", self.dir.join("key"))
            .env("XDG_RUNTIME_DIR", self.dir.join("run"))
            .output();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn genkey(e: &Env, bin: &str, decoy: bool) {
    let mut c = e.cmd(bin, Some(REAL));
    if decoy {
        c.env("VAULT_DECOY_PASSPHRASE", DECOY);
    }
    let o = c.arg("genkey").output().unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
}

fn pattern(n: usize, salt: u8) -> Vec<u8> {
    (0..n).map(|i| (i as u8).wrapping_mul(31) ^ salt).collect()
}

/// One implementation creates the key and vault and adds files; the other
/// lists, reads, copies, moves and removes them, and the first checks the
/// result. Decoy files stay invisible to the real passphrase and back.
fn lifecycle(maker: &str, user: &str) {
    let e = Env::new("life");
    genkey(&e, maker, true);
    e.ok(maker, Some(REAL), &["init"]);
    let big = pattern(4 << 20, 1); // two objects
    e.write("in/big.bin", &big);
    e.write("in/sub/small.txt", b"small");
    e.write("in/sub/empty", b"");
    e.ok(maker, Some(REAL), &["add", "in", "docs"]);
    e.write("decoy.txt", b"shopping");
    e.ok(maker, Some(DECOY), &["add", "decoy.txt"]);

    assert_eq!(
        e.names(user, REAL),
        ["docs/in/big.bin", "docs/in/sub/empty", "docs/in/sub/small.txt"]
    );
    assert_eq!(e.names(user, DECOY), ["decoy.txt"]);
    assert_eq!(e.get(user, REAL, "docs/in/big.bin"), big);
    assert_eq!(e.get(user, REAL, "docs/in/sub/empty"), b"");
    e.ok(user, Some(REAL), &["cp", "-r", "docs/in", "copy"]);
    e.ok(user, Some(REAL), &["mv", "docs/in/sub/small.txt", "moved.txt"]);
    e.ok(user, Some(REAL), &["rm", "-rf", "docs"]);
    e.write("new.txt", b"from the other side");
    e.ok(user, Some(REAL), &["add", "new.txt", "/x/"]);

    // The copies still hold data whose originals were removed.
    assert_eq!(
        e.names(maker, REAL),
        ["copy/big.bin", "copy/sub/empty", "copy/sub/small.txt", "moved.txt", "x/new.txt"]
    );
    assert_eq!(e.get(maker, REAL, "copy/big.bin"), big);
    assert_eq!(e.get(maker, REAL, "moved.txt"), b"small");
    assert_eq!(e.get(maker, REAL, "x/new.txt"), b"from the other side");
    assert_eq!(e.names(maker, DECOY), ["decoy.txt"]);
    assert_eq!(e.get(maker, DECOY, "decoy.txt"), b"shopping");
}

#[test]
fn rust_lifecycle() {
    lifecycle(RUST, RUST);
}

#[test]
fn go_made_rust_used() {
    let Some(go) = common::go_oracle() else {
        return common::skip("go not installed");
    };
    lifecycle(go.to_str().unwrap(), RUST);
}

#[test]
fn rust_made_go_used() {
    let Some(go) = common::go_oracle() else {
        return common::skip("go not installed");
    };
    lifecycle(RUST, go.to_str().unwrap());
}

/// Boundary sizes written by one implementation read back by the other.
#[test]
fn boundary_sizes_interop() {
    let Some(go) = common::go_oracle() else {
        return common::skip("go not installed");
    };
    let go = go.to_str().unwrap();
    let e = Env::new("bounds");
    genkey(&e, RUST, false);
    e.ok(go, Some(REAL), &["init"]);
    let data = (4 << 20) - 16;
    let sizes = [0, 1, 65535, 65536 - 16, 65536, data - 1, data, data + 1];
    for (i, &n) in sizes.iter().enumerate() {
        let bin = if i % 2 == 0 { RUST } else { go };
        let p = e.write(&format!("f{i}"), &pattern(n, i as u8));
        e.ok(bin, Some(REAL), &["add", p.to_str().unwrap()]);
    }
    for (i, &n) in sizes.iter().enumerate() {
        let bin = if i % 2 == 0 { go } else { RUST };
        assert_eq!(e.get(bin, REAL, &format!("f{i}")), pattern(n, i as u8), "size {n}");
    }
}

#[test]
fn errors_and_messages() {
    let e = Env::new("errors");
    let o = e.run(RUST, Some(REAL), &["list"]);
    assert_eq!(o.status.code(), Some(1));
    let msg = String::from_utf8_lossy(&o.stderr);
    assert!(msg.starts_with("vault: open "), "{msg}");
    genkey(&e, RUST, false);
    let o = e.run(RUST, Some("wrong"), &["list"]);
    assert_eq!(String::from_utf8_lossy(&o.stderr), "vault: incorrect passphrase\n");
    let o = e.run(RUST, Some(REAL), &["list"]);
    assert!(String::from_utf8_lossy(&o.stderr).contains("is not a vault; run vault init"));
    e.ok(RUST, Some(REAL), &["init"]);
    let o = e.run(RUST, Some(REAL), &["init"]);
    assert!(String::from_utf8_lossy(&o.stderr).contains("is already a vault"));
    let o = e.run(RUST, None, &[]);
    assert_eq!(o.status.code(), Some(2));
    let o = e.run(RUST, Some(REAL), &["get"]);
    assert!(String::from_utf8_lossy(&o.stderr).starts_with("vault: wrong number of arguments for get\n\nUsage:"));
    let o = e.run(RUST, Some(REAL), &["frobnicate"]);
    assert!(String::from_utf8_lossy(&o.stderr).starts_with("vault: unknown command \"frobnicate\""));
    let o = e.run(RUST, Some(""), &["list"]);
    assert_eq!(String::from_utf8_lossy(&o.stderr), "vault: VAULT_PASSPHRASE is set but empty\n");
    let o = e.run(RUST, Some(REAL), &["get", "missing"]);
    assert_eq!(String::from_utf8_lossy(&o.stderr), "vault: missing: not in the vault\n");
    let p = e.write("f", b"data");
    e.ok(RUST, Some(REAL), &["add", p.to_str().unwrap()]);
    e.write("exists", b"keep");
    let o = e.run(RUST, Some(REAL), &["get", "f", "-o", "exists"]);
    assert_eq!(String::from_utf8_lossy(&o.stderr), "vault: exists already exists\n");
    assert_eq!(std::fs::read(e.dir.join("exists")).unwrap(), b"keep");
    // Diagnostics are lower-case and never end in a full stop.
    for args in [
        &["rm", "nope"][..],
        &["mv", "a", "b"],
        &["ls", "nope"],
        &["--workers", "0", "list"],
        &["init", "--filler", "2X"],
    ] {
        let o = e.run(RUST, Some(REAL), args);
        let m = String::from_utf8_lossy(&o.stderr).lines().next().unwrap_or_default().to_string();
        assert!(
            m.starts_with("vault: ") && !m.ends_with('.') && m.chars().nth(7).is_some_and(|c| !c.is_uppercase()),
            "{args:?}: {m}"
        );
    }
}

#[test]
fn migrate_deletes_only_stored_originals() {
    let e = Env::new("migrate");
    genkey(&e, RUST, false);
    e.ok(RUST, Some(REAL), &["init"]);
    e.write("tree/a/x", b"x");
    e.write("tree/y", b"y");
    e.ok(RUST, Some(REAL), &["migrate", "tree", "m"]);
    assert!(!e.dir.join("tree").exists(), "emptied directories should go");
    assert_eq!(e.names(RUST, REAL), ["m/tree/a/x", "m/tree/y"]);
    // A second migrate over existing names, without a terminal, is refused.
    e.write("tree/y", b"y2");
    let o = e.run(RUST, Some(REAL), &["migrate", "tree", "m"]);
    assert!(String::from_utf8_lossy(&o.stderr).contains("migrate cancelled; nothing changed"));
    assert!(e.dir.join("tree/y").exists());
    e.ok(RUST, Some(REAL), &["migrate", "--yes", "tree", "m"]);
    assert_eq!(e.get(RUST, REAL, "m/tree/y"), b"y2");
    // Never the vault or the key.
    let o = e.run(RUST, Some(REAL), &["add", "store"]);
    assert!(String::from_utf8_lossy(&o.stderr).contains("is the vault or its key"));
}

#[cfg(unix)]
#[test]
fn absorb_from_stdin() {
    let e = Env::new("absorb");
    genkey(&e, RUST, false);
    e.ok(RUST, Some(REAL), &["init"]);
    let mut tw = tar::Builder::new(Vec::new());
    let mut h = tar::Header::new_ustar();
    h.set_size(5);
    h.set_mode(0o640);
    h.set_mtime(1_600_000_000);
    tw.append_data(&mut h, "dir/a.txt", &b"hello"[..]).unwrap();
    let t = tw.into_inner().unwrap();
    let mut c = e
        .cmd(RUST, Some(REAL))
        .args(["absorb", "in"])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    c.stdin.take().unwrap().write_all(&t).unwrap();
    let o = c.wait_with_output().unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(String::from_utf8_lossy(&o.stderr), "added in/dir/a.txt\n");
    assert_eq!(e.get(RUST, REAL, "in/dir/a.txt"), b"hello");
    let o = e.run(RUST, Some(REAL), &["absorb"]);
    assert!(String::from_utf8_lossy(&o.stderr).contains("nothing to absorb"));
}

/// Starts `absorb` and feeds it one byte: it takes the exclusive lock and
/// then holds it until its standard input closes or it is killed. The
/// caller kills and waits for it.
#[cfg(unix)]
#[allow(clippy::zombie_processes)]
fn hold_lock(e: &Env, bin: &str) -> Child {
    let mut c = e
        .cmd(bin, Some(REAL))
        .arg("absorb")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    c.stdin.as_mut().unwrap().write_all(b"\0").unwrap();
    // Wait until the lock file is held exclusively: probe with our own
    // fcntl lock attempt from this process.
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if locked_exclusively(&e.dir.join("store/.lock")) {
            return c;
        }
        assert!(Instant::now() < deadline, "holder never took the lock");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(unix)]
fn locked_exclusively(p: &Path) -> bool {
    use rustix::fs::{FlockOperation, fcntl_lock};
    let Ok(f) = std::fs::OpenOptions::new().read(true).write(true).open(p) else {
        return false;
    };
    match fcntl_lock(&f, FlockOperation::NonBlockingLockShared) {
        Ok(()) => false,
        Err(_) => true,
    }
}

/// A reader of one implementation waits for a writer of the other, and
/// proceeds once the writer dies.
#[cfg(unix)]
fn lock_contention(holder: &str, waiter: &str) {
    let e = Env::new("lock");
    genkey(&e, RUST, false);
    e.ok(RUST, Some(REAL), &["init"]);
    let mut h = hold_lock(&e, holder);
    let mut w = e
        .cmd(waiter, Some(REAL))
        .arg("list")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(1500));
    assert!(w.try_wait().unwrap().is_none(), "reader did not wait for the writer");
    h.kill().unwrap(); // death releases the lock
    let _ = h.wait();
    let o = w.wait_with_output().unwrap();
    assert!(o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("waiting for another vault process to finish"));
}

#[cfg(unix)]
#[test]
fn lock_rust_waits_for_go() {
    let Some(go) = common::go_oracle() else {
        return common::skip("go not installed");
    };
    lock_contention(go.to_str().unwrap(), RUST);
}

#[cfg(unix)]
#[test]
fn lock_go_waits_for_rust() {
    let Some(go) = common::go_oracle() else {
        return common::skip("go not installed");
    };
    lock_contention(RUST, go.to_str().unwrap());
}

#[cfg(unix)]
#[test]
fn lock_rust_waits_for_rust() {
    lock_contention(RUST, RUST);
}

/// `unlock` re-executes the binary as an agent that serves the key
/// without the passphrase, to either implementation.
#[cfg(unix)]
fn agent_roundtrip(starter: &str, client: &str) {
    let e = Env::new("agent");
    genkey(&e, RUST, false);
    e.ok(RUST, Some(REAL), &["init"]);
    e.ok(starter, Some(REAL), &["unlock", "--for", "1m"]);
    // No passphrase in the environment, no terminal: only the agent can help.
    let out = e.ok(client, None, &["list"]);
    assert_eq!(out, "");
    let o = e.run(client, None, &["lock"]);
    assert_eq!(String::from_utf8_lossy(&o.stderr), "locked\n");
    let o = e.run(client, None, &["list"]);
    assert!(!o.status.success(), "key still available after lock");
    let o = e.run(client, None, &["lock"]);
    assert_eq!(String::from_utf8_lossy(&o.stderr), "nothing was unlocked\n");
}

#[cfg(unix)]
#[test]
fn agent_rust() {
    agent_roundtrip(RUST, RUST);
}

#[cfg(unix)]
#[test]
fn agent_go_client_rust_agent() {
    let Some(go) = common::go_oracle() else {
        return common::skip("go not installed");
    };
    agent_roundtrip(RUST, go.to_str().unwrap());
}

#[cfg(unix)]
#[test]
fn agent_rust_client_go_agent() {
    let Some(go) = common::go_oracle() else {
        return common::skip("go not installed");
    };
    agent_roundtrip(go.to_str().unwrap(), RUST);
}

#[cfg(unix)]
fn agent_pids(sock_dir: &Path) -> Vec<u32> {
    let mut pids = Vec::new();
    for e in std::fs::read_dir("/proc").into_iter().flatten().flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(cmd) = std::fs::read(e.path().join("cmdline")) else {
            continue;
        };
        let cmd = String::from_utf8_lossy(&cmd);
        if cmd.contains("__agent") && cmd.contains(&*sock_dir.to_string_lossy()) {
            pids.push(pid);
        }
    }
    pids
}

#[cfg(target_os = "linux")]
#[test]
fn agent_hardening_and_expiry() {
    let e = Env::new("agenthard");
    genkey(&e, RUST, false);
    e.ok(RUST, Some(REAL), &["unlock", "--for", "3s"]);
    let pids = agent_pids(&e.dir.join("run"));
    assert_eq!(pids.len(), 1, "exactly one agent process");
    let pid = pids[0];
    // Undumpable: its memory and environment are closed even to us.
    let environ = std::fs::read(format!("/proc/{pid}/environ"));
    assert!(environ.is_err(), "agent environment readable: it is still dumpable");
    assert!(std::fs::read(format!("/proc/{pid}/mem")).is_err());
    // Fixed expiry: gone after its time, with nobody connecting.
    let deadline = Instant::now() + Duration::from_secs(10);
    while std::path::Path::new(&format!("/proc/{pid}")).exists()
        && !std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .unwrap_or_default()
            .contains(") Z")
    {
        assert!(Instant::now() < deadline, "agent outlived its fixed time");
        std::thread::sleep(Duration::from_millis(100));
    }
    let sock_dir = e.dir.join("run").join(format!("vault-{}", rustix::process::getuid().as_raw()));
    assert_eq!(std::fs::read_dir(&sock_dir).unwrap().count(), 0, "socket left behind");
}

#[cfg(unix)]
#[test]
fn agent_idle_extends_and_expires() {
    let e = Env::new("idle");
    genkey(&e, RUST, false);
    e.ok(RUST, Some(REAL), &["init"]);
    e.ok(RUST, Some(REAL), &["unlock", "--for", "2s", "--idle"]);
    for _ in 0..4 {
        std::thread::sleep(Duration::from_millis(900));
        e.ok(RUST, None, &["list"]); // each use pushes expiry back
    }
    std::thread::sleep(Duration::from_millis(3500));
    assert!(!e.run(RUST, None, &["list"]).status.success(), "idle agent outlived its idle time");
}

#[cfg(unix)]
#[test]
fn agent_start_failures() {
    let e = Env::new("agentfail");
    let sock = e.dir.join("run").join("s");
    // No key on standard input: refuses, says why, exits.
    let o = Command::new(RUST)
        .args(["__agent", sock.to_str().unwrap(), "1m", "fixed"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&o.stdout), "no key received");
    let o = Command::new(RUST)
        .args(["__agent", sock.to_str().unwrap(), "soon", "fixed"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&o.stdout), "bad duration or mode");
    assert!(!sock.exists());
    // A stale socket from a dead agent does not stop a new one.
    genkey(&e, RUST, false);
    e.ok(RUST, Some(REAL), &["init"]);
    e.ok(RUST, Some(REAL), &["unlock"]);
    let pids = agent_pids(&e.dir.join("run"));
    for p in &pids {
        Command::new("kill").args(["-9", &p.to_string()]).status().unwrap();
    }
    std::thread::sleep(Duration::from_millis(200));
    assert!(!e.run(RUST, None, &["list"]).status.success(), "dead agent still answered");
    e.ok(RUST, Some(REAL), &["unlock"]);
    e.ok(RUST, None, &["list"]);
    // A wrong passphrase starts nothing.
    e.ok(RUST, None, &["lock"]);
    assert!(!e.run(RUST, Some("wrong"), &["unlock"]).status.success());
    assert!(agent_pids(&e.dir.join("run")).is_empty());
    // A socket directory that is not private is refused.
    let run2 = e.dir.join("run2");
    std::fs::create_dir_all(run2.join(format!("vault-{}", rustix::process::getuid().as_raw()))).unwrap();
    std::fs::set_permissions(
        run2.join(format!("vault-{}", rustix::process::getuid().as_raw())),
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .unwrap();
    let o = e
        .cmd(RUST, Some(REAL))
        .env("XDG_RUNTIME_DIR", &run2)
        .arg("unlock")
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&o.stderr).contains("is not a private directory of this user"));
}

#[test]
fn get_recursive_confined() {
    let e = Env::new("getr");
    genkey(&e, RUST, false);
    e.ok(RUST, Some(REAL), &["init"]);
    e.write("t/a/b/c.txt", b"c");
    e.write("t/a/d.txt", b"d");
    e.ok(RUST, Some(REAL), &["add", "t", "f"]);
    e.ok(RUST, Some(REAL), &["get", "-r", "f/t/a", "-o", "out"]);
    assert_eq!(std::fs::read(e.dir.join("out/b/c.txt")).unwrap(), b"c");
    assert_eq!(std::fs::read(e.dir.join("out/d.txt")).unwrap(), b"d");
    #[cfg(unix)]
    {
        // A symlink planted inside the destination is not followed out.
        let outside = e.dir.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::create_dir_all(e.dir.join("out2")).unwrap();
        std::os::unix::fs::symlink(&outside, e.dir.join("out2/b")).unwrap();
        let o = e.run(RUST, Some(REAL), &["get", "-r", "f/t/a", "-o", "out2"]);
        assert!(!o.status.success());
        assert!(
            String::from_utf8_lossy(&o.stderr).contains("refusing to extract through it"),
            "{}",
            String::from_utf8_lossy(&o.stderr)
        );
        assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0, "wrote through the symlink");
    }
}

/// Piping `list` into a reader that stops early ends quietly.
#[cfg(unix)]
#[test]
fn broken_pipe_is_quiet() {
    let e = Env::new("pipe");
    genkey(&e, RUST, false);
    e.ok(RUST, Some(REAL), &["init"]);
    for i in 0..30 {
        let p = e.write(&format!("f/{i:03}"), b"x");
        let _ = p;
    }
    e.ok(RUST, Some(REAL), &["add", "f"]);
    let mut c = e
        .cmd(RUST, Some(REAL))
        .arg("list")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(c.stdout.take());
    let o = c.wait_with_output().unwrap();
    assert!(
        !String::from_utf8_lossy(&o.stderr).contains("panicked"),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
}
