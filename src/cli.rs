// SPDX-License-Identifier: GPL-3.0-or-later

//! The command line, matching the Go version's commands, flags (Go `flag`
//! package syntax, flags before, between or after arguments), prompts,
//! messages and exit statuses.

use crate::agent;
use crate::error::{Error, Result};
use crate::keyfile;
use crate::pipeline::{MAX_WORKERS, Pool};
use crate::platform::{fs as pfs, lock, term};
use crate::secret::SecretVec;
use crate::store::{Catalogue, FILE_LIMIT, SourceStamp, Store, VaultName};
use crate::util::{self, human_size};
use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

pub const USAGE: &str = "Usage:
    vault genkey                    create a new passphrase-protected key
    vault init [--filler SIZE]      create a new, empty vault, with at least
                                    SIZE of filler (e.g. 500M, 2G)
    vault add FILE|DIR|URL [FOLDER] encrypt a file, a directory (recursively)
                                    or a downloaded URL into the vault,
                                    optionally under a folder inside the vault
    vault migrate FILE|DIR [FOLDER] like add, then delete each original once
    [--yes]                         it is stored; asks before overwriting
                                    anything already in the vault, unless
                                    --yes is given
    vault mirror URL [FOLDER]       crawl a website (same host only, one request
                                    at a time) into FOLDER/HOST, rewriting its
                                    links to relative paths
    vault absorb [FOLDER]           read a tar archive (optionally gzipped) from
                                    standard input and add every file in it,
                                    optionally under a folder inside the vault
    vault ls [FOLDER]               list one folder: its files, and its
                                    sub-folders (ending in /) with their
                                    total size; -r lists everything under it
    vault list [FOLDER]             list every stored file under FOLDER,
                                    with full names
    vault get NAME [-o OUTPUT]      decrypt a stored file (default: its base name)
    vault get -r FOLDER [-o DIR]    decrypt a folder and everything under it
                                    into DIR (default: the folder's base name)
    vault mv OLD NEW                rename or move a file or folder; NEW
                                    ending in / or naming an existing folder
                                    moves OLD into it
    vault cp [-r] OLD NEW           copy a file, or with -r a folder, like mv;
                                    copies share their encrypted data
    vault rm NAME                   delete a stored file
    vault rm -r FOLDER [-f]         delete a folder and everything under it;
                                    asks first unless -f (or -rf) is given
    vault unlock [--for DURATION]   remember the passphrase for DURATION
    [--idle]                        (default 5m), so commands skip asking;
                                    with --idle, DURATION since last used
    vault lock                      forget it now

Options (any command):
    --key PATH     key file (default $VAULT_KEY, else ~/.vault/key)
    --vault DIR    vault directory (default $VAULT_DIR, else ~/.vault/store)
    --workers N    encryption and I/O threads, 1 to 256 (default: CPUs, at
                   most 8)

Options for add URL and mirror:
    --max-bytes SIZE    largest download (add) or total (mirror); defaults
                        16G and 4G, at most 1T
    --timeout DURATION  deadline for each request; defaults 2h and 5m
    --max-pages N       pages and assets mirror fetches (default 10000)

The passphrase is read from the terminal, or from $VAULT_PASSPHRASE. After
vault unlock, commands use the remembered key instead, unless
$VAULT_PASSPHRASE is set.

Decoy passphrase: genkey offers a second, optional passphrase
($VAULT_DECOY_PASSPHRASE when scripted). It unlocks a separate key, so
every command run with it sees and changes only the decoy files, and the
real files stay invisible. The key file does not reveal whether a decoy
exists, and init fills each vault with unreadable filler, so hidden
files look like filler to anyone holding only the decoy passphrase.";

const PASSPHRASE_ENV: &str = "VAULT_PASSPHRASE";
const DECOY_ENV: &str = "VAULT_DECOY_PASSPHRASE";
/// Exit status when `mirror` stored some resources but skipped others.
pub const EXIT_PARTIAL: i32 = 3;

/// Prints to standard error, ignoring failure (as Go's Fprintf does).
macro_rules! say {
    ($($t:tt)*) => {{ let _ = writeln!(std::io::stderr(), $($t)*); }};
}

/// Prints to standard output; a closed pipe ends the program quietly, as
/// Go's SIGPIPE on standard output does.
fn out(line: &str) {
    let mut o = std::io::stdout().lock();
    if let Err(e) = o.write_all(line.as_bytes()).and_then(|_| o.flush())
        && e.kind() == std::io::ErrorKind::BrokenPipe
    {
        std::process::exit(128 + 13);
    }
}

#[derive(Default)]
struct Flags {
    key: Option<String>,
    vault: Option<String>,
    output: Option<String>,
    filler: Option<String>,
    yes: bool,
    ttl: Option<i64>,
    idle: bool,
    r: bool,
    f: bool,
    rf: bool,
    fr: bool,
    workers: Option<String>,
    max_bytes: Option<String>,
    timeout: Option<i64>,
    max_pages: Option<String>,
}

enum FlagKind {
    Str,
    Bool,
    Dur,
}

fn flag_kind(name: &str) -> Option<FlagKind> {
    Some(match name {
        "key" | "vault" | "o" | "filler" | "workers" | "max-bytes" | "max-pages" => FlagKind::Str,
        "yes" | "idle" | "r" | "f" | "rf" | "fr" => FlagKind::Bool,
        "for" | "timeout" => FlagKind::Dur,
        _ => return None,
    })
}

fn go_parse_bool(v: &str) -> Option<bool> {
    match v {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}

impl Flags {
    fn set(&mut self, name: &str, value: &str) -> std::result::Result<(), String> {
        match flag_kind(name).expect("known flag") {
            FlagKind::Bool => {
                let b = go_parse_bool(value).ok_or_else(|| format!("invalid boolean value {value:?} for -{name}: parse error"))?;
                *match name {
                    "yes" => &mut self.yes,
                    "idle" => &mut self.idle,
                    "r" => &mut self.r,
                    "f" => &mut self.f,
                    "rf" => &mut self.rf,
                    _ => &mut self.fr,
                } = b;
            }
            FlagKind::Dur => {
                let d = util::parse_duration(value).map_err(|_| format!("invalid value {value:?} for flag -{name}: parse error"))?;
                *if name == "for" { &mut self.ttl } else { &mut self.timeout } = Some(d);
            }
            FlagKind::Str => {
                let v = Some(value.to_string());
                match name {
                    "key" => self.key = v,
                    "vault" => self.vault = v,
                    "o" => self.output = v,
                    "filler" => self.filler = v,
                    "workers" => self.workers = v,
                    "max-bytes" => self.max_bytes = v,
                    _ => self.max_pages = v,
                }
            }
        }
        Ok(())
    }
}

/// Go's `flag.FlagSet.Parse`: consumes flags from the front of `args`,
/// returning the remaining arguments.
fn parse_flags(fl: &mut Flags, mut args: &[String]) -> std::result::Result<Vec<String>, String> {
    loop {
        let Some(s) = args.first() else { return Ok(Vec::new()) };
        let b = s.as_bytes();
        if b.len() < 2 || b[0] != b'-' {
            return Ok(args.to_vec());
        }
        let mut minuses = 1;
        if b[1] == b'-' {
            minuses = 2;
            if b.len() == 2 {
                return Ok(args[1..].to_vec());
            }
        }
        let mut name = &s[minuses..];
        if name.is_empty() || name.starts_with('-') || name.starts_with('=') {
            return Err(format!("bad flag syntax: {s}"));
        }
        args = &args[1..];
        let mut value = None;
        if let Some(i) = name[1..].find('=') {
            value = Some(&name[i + 2..]);
            name = &name[..i + 1];
        }
        let Some(kind) = flag_kind(name) else {
            if name == "help" || name == "h" {
                return Err("flag: help requested".into());
            }
            return Err(format!("flag provided but not defined: -{name}"));
        };
        match (kind, value) {
            (FlagKind::Bool, None) => fl.set(name, "true")?,
            (_, Some(v)) => fl.set(name, v)?,
            (_, None) => {
                let Some(v) = args.first() else {
                    return Err(format!("flag needs an argument: -{name}"));
                };
                fl.set(name, v)?;
                args = &args[1..];
            }
        }
    }
}

/// Flags may come before, between or after positional arguments.
fn parse_interleaved(fl: &mut Flags, args: &[String]) -> std::result::Result<Vec<String>, String> {
    let mut pos = Vec::new();
    let mut rest = args.to_vec();
    loop {
        let left = parse_flags(fl, &rest)?;
        let Some(first) = left.first() else { return Ok(pos) };
        pos.push(first.clone());
        rest = left[1..].to_vec();
    }
}

fn env_bytes(name: &str) -> Option<Vec<u8>> {
    let v = std::env::var_os(name)?;
    #[cfg(unix)]
    {
        Some(std::os::unix::ffi::OsStringExt::into_vec(v))
    }
    #[cfg(not(unix))]
    {
        Some(v.to_string_lossy().into_owned().into_bytes())
    }
}

fn read_passphrase(prompt: &str) -> Result<SecretVec> {
    match env_bytes(PASSPHRASE_ENV) {
        Some(v) if v.is_empty() => Err(Error::new(format!("{PASSPHRASE_ENV} is set but empty"))),
        Some(v) => Ok(SecretVec::from_vec(v)),
        None => term::read_secret(prompt).map_err(|e| {
            Error::new(format!(
                "could not read passphrase (set {PASSPHRASE_ENV} for non-interactive use): {}",
                util::io_reason(&e)
            ))
        }),
    }
}

fn new_passphrase(what: &str) -> Result<SecretVec> {
    if let Some(v) = env_bytes(PASSPHRASE_ENV).filter(|v| !v.is_empty()) {
        return Ok(SecretVec::from_vec(v));
    }
    let p = read_passphrase(&format!("Enter {what}:"))?;
    if p.is_empty() {
        crate::bail!("{what} must not be empty");
    }
    let again = read_passphrase(&format!("Confirm {what}:"))?;
    if !(p == *again.expose()) {
        crate::bail!("{what}s do not match");
    }
    Ok(p)
}

/// An optional second passphrase; empty means none.
fn decoy_passphrase() -> Result<SecretVec> {
    if let Some(v) = env_bytes(DECOY_ENV) {
        return Ok(SecretVec::from_vec(v));
    }
    if std::env::var_os(PASSPHRASE_ENV).is_some() {
        return Ok(SecretVec::from_vec(Vec::new())); // scripted, no decoy
    }
    let read = |p: &str| term::read_secret(p).map_err(|e| Error::new(util::io_reason(&e)));
    let p = read("Enter decoy passphrase (empty for none):")?;
    if p.is_empty() {
        return Ok(p);
    }
    let again = read("Confirm decoy passphrase:")?;
    if !(p == *again.expose()) {
        crate::bail!("decoy passphrases do not match");
    }
    Ok(p)
}

fn home() -> Option<PathBuf> {
    let v = if cfg!(windows) {
        std::env::var_os("USERPROFILE")
    } else {
        std::env::var_os("HOME")
    };
    v.filter(|h| !h.is_empty()).map(PathBuf::from)
}

fn default_path(flag: &Option<String>, env: &str, name: &str) -> Result<PathBuf> {
    if let Some(f) = flag {
        return Ok(PathBuf::from(f));
    }
    if let Some(v) = std::env::var_os(env).filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(v));
    }
    home()
        .map(|h| h.join(".vault").join(name))
        .ok_or_else(|| Error::new(format!("cannot find home directory; set {env}")))
}

/// The key: from a running agent unless a passphrase is in the
/// environment, else from the key file with the passphrase.
fn key_identity(key: &Path) -> Result<crate::crypto::kem::Identity> {
    if std::env::var_os(PASSPHRASE_ENV).is_none()
        && let Ok(id) = agent::identity(key)
    {
        return Ok(id);
    }
    let pass = read_passphrase("Enter passphrase:")?;
    keyfile::unlock(key, pass.expose()).map_err(|e| Error::new(e.to_string()))
}

struct Ctx {
    flags: Flags,
    pool: Option<Arc<Pool>>,
}

impl Ctx {
    fn key(&self) -> Result<PathBuf> {
        default_path(&self.flags.key, "VAULT_KEY", "key")
    }

    fn vault_dir(&self) -> Result<PathBuf> {
        default_path(&self.flags.vault, "VAULT_DIR", "store")
    }

    fn pool(&mut self) -> Result<Arc<Pool>> {
        if self.pool.is_none() {
            let n = match &self.flags.workers {
                None => Pool::default_workers(),
                Some(w) => match w.parse::<usize>() {
                    Ok(n) if (1..=MAX_WORKERS).contains(&n) => n,
                    _ => crate::bail!("--workers needs a number from 1 to {MAX_WORKERS}"),
                },
            };
            self.pool = Some(Arc::new(Pool::new(n)));
        }
        Ok(Arc::clone(self.pool.as_ref().expect("set")))
    }

    /// Unlocks the key, opens the vault, then takes the vault lock:
    /// exclusive for writers, shared for readers.
    fn open(&mut self, exclusive: bool) -> Result<(Store, lock::Lock)> {
        let key = self.key()?;
        let dir = self.vault_dir()?;
        let id = key_identity(&key)?;
        let s = Store::open(&dir, id, self.pool()?)?;
        let l = lock::lock_vault(&dir, exclusive)?;
        Ok((s, l))
    }

    fn net_limits(&self, mirror: bool) -> Result<crate::net::Limits> {
        let mut l = if mirror {
            crate::net::Limits::mirror_defaults()
        } else {
            crate::net::Limits::add_defaults()
        };
        if let Some(b) = &self.flags.max_bytes {
            l.max_bytes = util::parse_size(b, FILE_LIMIT)?;
        }
        if let Some(t) = self.flags.timeout {
            if t <= 0 {
                crate::bail!("--timeout needs a positive duration, such as 30s or 1h");
            }
            l.request = Duration::from_nanos(t as u64);
        }
        if let Some(p) = &self.flags.max_pages {
            l.max_pages = p
                .parse()
                .ok()
                .filter(|&n| n > 0)
                .ok_or_else(|| Error::new("--max-pages needs a positive number"))?;
        }
        Ok(l)
    }
}

fn report(verb: &str) -> impl FnMut(&VaultName, bool) + '_ {
    move |n, replaced| say!("{} {n}", if replaced { "replaced" } else { verb })
}

/// Runs the command line; returns the exit status.
pub fn main() -> i32 {
    let args: Vec<OsString> = std::env::args_os().collect();
    if args.len() < 2 {
        say!("{USAGE}");
        return 2;
    }
    if args[1] == agent::AGENT_CMD && args.len() == 5 {
        agent::run(Path::new(&args[2]), &args[3].to_string_lossy(), &args[4].to_string_lossy());
        return 0;
    }
    let mut strs = Vec::with_capacity(args.len());
    for a in &args[1..] {
        match a.to_str() {
            Some(s) => strs.push(s.to_string()),
            None => {
                say!("vault: arguments must be valid UTF-8: {}", a.to_string_lossy());
                return 1;
            }
        }
    }
    match run(&strs[0], &strs[1..]) {
        Ok(code) => code,
        Err(e) => {
            say!("vault: {e}");
            1
        }
    }
}

fn run(cmd: &str, args: &[String]) -> Result<i32> {
    let mut flags = Flags::default();
    let pos = parse_interleaved(&mut flags, args).map_err(|e| Error::new(format!("{e}\n\n{USAGE}")))?;
    let want = |min: usize, max: usize| -> Result<()> {
        if pos.len() < min || pos.len() > max {
            crate::bail!("wrong number of arguments for {cmd}\n\n{USAGE}");
        }
        Ok(())
    };
    let mut ctx = Ctx { flags, pool: None };
    match cmd {
        "genkey" => {
            want(0, 0)?;
            let key = ctx.key()?;
            if std::fs::metadata(&key).is_ok() {
                crate::bail!("{} already exists", key.display());
            }
            let pass = new_passphrase("passphrase")?;
            let decoy = decoy_passphrase()?;
            if pass == *decoy.expose() {
                crate::bail!("decoy passphrase must differ from the passphrase");
            }
            keyfile::write(&key, pass.expose(), decoy.expose()).map_err(|e| Error::new(e.to_string()))?;
            // One left from an old key at this path would serve it.
            agent::stop(&key);
            say!("key written to {}", key.display());
        }
        "init" => {
            want(0, 0)?;
            let size = util::parse_size(ctx.flags.filler.as_deref().unwrap_or("0"), FILE_LIMIT)?;
            let dir = ctx.vault_dir()?;
            Store::init(&dir, size, ctx.pool()?)?;
            say!("vault created at {}", dir.display());
        }
        "add" | "migrate" => {
            want(1, 2)?;
            let dest = pos.get(1).map(|d| d.trim_matches('/').to_string()).unwrap_or_default();
            let migrate = cmd == "migrate";
            if crate::net::is_url(&pos[0]) {
                if migrate {
                    crate::bail!("cannot migrate a URL; use add");
                }
                let limits = ctx.net_limits(false)?;
                let (s, _lock) = ctx.open(true)?;
                let mut cat = s.catalogue()?;
                crate::net::add_url(&s, &mut cat, &pos[0], &dest, &limits, &mut report("added"))?;
                return Ok(0);
            }
            let (s, _lock) = ctx.open(true)?;
            let mut cat = s.catalogue()?;
            // Never ingest, or delete, the vault, anything inside it, or its key.
            let vault_dir = ctx.vault_dir()?;
            if let (Ok(v), Ok(src)) = (std::fs::canonicalize(&vault_dir), std::fs::canonicalize(&pos[0]))
                && src != v
                && src.starts_with(&v)
            {
                crate::bail!("{} is inside the vault", pos[0]);
            }
            let skip: Vec<FileId> = [vault_dir, ctx.key()?].iter().filter_map(|p| FileId::of(p, true)).collect();
            let yes = ctx.flags.yes;
            add_path(&s, &mut cat, Path::new(&pos[0]), &dest, migrate, &skip, &mut |names| {
                yes || confirm_overwrite(names)
            })?;
        }
        "mirror" => {
            want(1, 2)?;
            if !crate::net::is_url(&pos[0]) {
                crate::bail!("mirror needs an http:// or https:// URL");
            }
            let dest = pos.get(1).map(|d| d.trim_matches('/').to_string()).unwrap_or_default();
            let limits = ctx.net_limits(true)?;
            let (s, _lock) = ctx.open(true)?;
            let mut cat = s.catalogue()?;
            match crate::net::mirror(&s, &mut cat, &pos[0], &dest, &limits, &mut report("added"))? {
                crate::net::MirrorOutcome::Complete { .. } => {}
                crate::net::MirrorOutcome::Partial { stored, skipped } => {
                    say!("vault: mirror incomplete: stored {stored}, skipped {skipped}");
                    return Ok(EXIT_PARTIAL);
                }
            }
        }
        "absorb" => {
            want(0, 1)?;
            if stdin_is_terminal() {
                crate::bail!("absorb reads a tar archive from standard input; pipe one in");
            }
            let dest = pos.first().map(|d| d.trim_matches('/').to_string()).unwrap_or_default();
            // Wait for the archive to start arriving before asking for the
            // passphrase, so a program feeding the pipe (gpg, ssh) has
            // finished with the terminal and cannot bury the prompt.
            let mut input = std::io::BufReader::with_capacity(1 << 16, std::io::stdin().lock());
            if std::io::BufRead::fill_buf(&mut input).map_or(true, |b| b.is_empty()) {
                crate::bail!("nothing to absorb on standard input");
            }
            let (s, _lock) = ctx.open(true)?;
            let mut cat = s.catalogue()?;
            crate::absorb::absorb(&s, &mut cat, input, &dest, &mut report("added"))?;
        }
        "list" | "ls" => {
            want(0, 1)?;
            let prefix = pos.first().map(|d| d.trim_matches('/').to_string()).unwrap_or_default();
            let (s, _lock) = ctx.open(false)?;
            let cat = s.catalogue()?;
            if cmd == "ls" && !ctx.flags.r {
                for line in ls(&cat, &prefix)? {
                    out(&line);
                }
            } else {
                let names: Vec<String> = if prefix.is_empty() {
                    cat.names().map(String::from).collect()
                } else {
                    cat.under(&prefix)
                };
                for n in names {
                    let r = cat.current(&n).expect("listed");
                    out(&format!("{:>10}  {}  {n}\n", human_size(r.size), r.modified.local_minute()));
                }
            }
        }
        "get" => {
            want(1, 1)?;
            let out_path = ctx.flags.output.clone().unwrap_or_else(|| util::base(pos[0].trim_end_matches('/')));
            let (s, _lock) = ctx.open(false)?;
            let cat = s.catalogue()?;
            if !ctx.flags.r {
                let r = cat
                    .current(&pos[0])
                    .ok_or_else(|| Error::new(format!("{}: not in the vault", pos[0])))?;
                let p = PathBuf::from(&out_path);
                let Some(fname) = p.file_name() else {
                    crate::bail!("{out_path} already exists");
                };
                let parent = p.parent().unwrap_or(Path::new(""));
                let dir = pfs::Dir::open(parent).map_err(|e| Error::io("open", parent, &e))?;
                s.extract(r, &dir, fname)?;
                return Ok(0);
            }
            let folder = pos[0].trim_matches('/');
            let names = cat.under(folder);
            if folder.is_empty() || names.is_empty() || cat.contains(folder) {
                crate::bail!("{}: not a folder in the vault", pos[0]);
            }
            let root = PathBuf::from(&out_path);
            pfs::create_private_dir_all(&root).map_err(|e| Error::io("mkdir", &root, &e))?;
            let top = pfs::Dir::open(&root).map_err(|e| Error::io("open", &root, &e))?;
            for n in names {
                let rel = &n[folder.len() + 1..];
                let parts: Vec<&str> = rel.split('/').collect();
                let mut dir = None::<pfs::Dir>;
                for p in &parts[..parts.len() - 1] {
                    let next = dir
                        .as_ref()
                        .unwrap_or(&top)
                        .subdir(p.as_ref())
                        .map_err(|e| Error::new(util::io_reason(&e)))?;
                    dir = Some(next);
                }
                let d = dir.as_ref().unwrap_or(&top);
                s.extract(cat.current(&n).expect("listed"), d, parts[parts.len() - 1].as_ref())?;
                say!("extracted {}", root.join(rel.replace('/', std::path::MAIN_SEPARATOR_STR)).display());
            }
        }
        "mv" | "rename" | "cp" => {
            want(2, 2)?;
            let (s, _lock) = ctx.open(true)?;
            let mut cat = s.catalogue()?;
            let pairs = transfers(&cat, &pos[0], &pos[1], cmd != "cp" || ctx.flags.r)?;
            let verb = if cmd == "cp" { "copied" } else { "moved" };
            s.copy_all(&mut cat, &pairs, cmd != "cp", &mut |from, to| say!("{verb} {from} -> {to}"))?;
        }
        "rm" | "delete" => {
            want(1, 1)?;
            let f = &ctx.flags;
            let (recursive, forced) = (f.r || f.rf || f.fr, f.f || f.rf || f.fr);
            let mut name = pos[0].clone();
            if recursive {
                name = name.trim_matches('/').to_string();
                if name.is_empty() {
                    crate::bail!("refusing to remove the whole vault");
                }
            }
            let (s, _lock) = ctx.open(true)?;
            let mut cat = s.catalogue()?;
            let names = if recursive {
                cat.under(&name)
            } else if cat.contains(&name) {
                vec![name.clone()]
            } else {
                Vec::new()
            };
            if names.is_empty() {
                if forced {
                    return Ok(0);
                }
                crate::bail!("{name}: not in the vault");
            }
            let size: u64 = names.iter().map(|n| cat.current(n).expect("listed").size).sum();
            if recursive
                && !forced
                && !confirm(
                    "these files will be deleted, with no undo:",
                    &names,
                    &format!("delete {} file(s), {}? [y/N]", names.len(), human_size(size)),
                )
            {
                crate::bail!("rm cancelled; nothing changed (-f skips the question)");
            }
            s.remove_all(&mut cat, &names, &mut |n| say!("removed {n}"))?;
            if recursive {
                say!("removed {} file(s), {}", names.len(), human_size(size));
            }
        }
        "unlock" => {
            want(0, 0)?;
            let ttl = ctx.flags.ttl.unwrap_or(5 * 60 * 1_000_000_000);
            if ttl <= 0 {
                crate::bail!("--for needs a positive duration, such as 5m or 1h");
            }
            let ttl = Duration::from_nanos(ttl as u64);
            let key = ctx.key()?;
            let pass = read_passphrase("Enter passphrase:")?;
            let id = keyfile::unlock(&key, pass.expose()).map_err(|e| Error::new(e.to_string()))?;
            drop(pass);
            agent::start(&key, &id, ttl, ctx.flags.idle)?;
            id.close();
            if ctx.flags.idle {
                say!(
                    "unlocked until unused for {}; vault lock forgets the key sooner",
                    util::format_duration(ttl)
                );
            } else {
                let until = util::Instant::from_system(std::time::SystemTime::now() + ttl);
                say!("unlocked until {}; vault lock forgets the key sooner", until.local_clock());
            }
        }
        "lock" => {
            want(0, 0)?;
            if agent::stop(&ctx.key()?) {
                say!("locked");
            } else {
                say!("nothing was unlocked");
            }
        }
        "help" | "-h" | "--help" => out(&format!("{USAGE}\n")),
        _ => crate::bail!("unknown command {cmd:?}\n\n{USAGE}"),
    }
    Ok(0)
}

fn stdin_is_terminal() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal()
}

/// Works out, like mv(1) and cp(1), what `src` and `dst` mean: each file
/// to copy or move, with its new name. `src` is a file, or with
/// `recursive` a folder; `dst` ending in / or naming an existing folder
/// means into it. No new name may already exist.
pub fn transfers(cat: &Catalogue, src: &str, dst: &str, recursive: bool) -> Result<Vec<(String, VaultName)>> {
    let mut into = dst.is_empty() || dst.ends_with('/');
    let (src, dst) = (src.trim_matches('/'), dst.trim_matches('/'));
    if src.is_empty() {
        crate::bail!("name a file or folder to copy or move");
    }
    if dst.is_empty() || (!cat.contains(dst) && !cat.under(dst).is_empty()) {
        into = true;
    }
    let dst = if into {
        util::join(&[dst, &util::base(src)])
    } else {
        dst.to_string()
    };
    let raw: Vec<(String, String)> = if cat.contains(src) {
        vec![(src.to_string(), dst)]
    } else {
        let names = cat.under(src);
        if names.is_empty() {
            crate::bail!("{src}: not in the vault");
        }
        if !recursive {
            crate::bail!("{src} is a folder; use -r");
        }
        if dst == src || dst.starts_with(&format!("{src}/")) {
            crate::bail!("cannot put {src} inside itself");
        }
        names
            .into_iter()
            .map(|n| (n.clone(), format!("{dst}{}", &n[src.len()..])))
            .collect()
    };
    let mut pairs = Vec::with_capacity(raw.len());
    for (from, to) in raw {
        let Some(name) = VaultName::new(&to) else {
            crate::bail!("invalid vault path {to:?}")
        };
        if cat.contains(&to) {
            crate::bail!("{to} already exists");
        }
        pairs.push((from, name));
    }
    Ok(pairs)
}

/// One level of the vault, like ls(1): the files directly in `folder`
/// and each sub-folder once, with a trailing slash, the total size and
/// the newest date beneath it. Folders first. A file's own name lists it.
pub fn ls(cat: &Catalogue, folder: &str) -> Result<Vec<String>> {
    let mut entries: std::collections::BTreeMap<String, (u64, Option<util::Instant>)> = Default::default();
    for (name, r) in cat.iter() {
        let rel = if folder.is_empty() {
            name.to_string()
        } else if name == folder {
            util::base(name)
        } else if let Some(rest) = name.strip_prefix(folder).and_then(|r| r.strip_prefix('/')) {
            rest.to_string()
        } else {
            continue;
        };
        let rel = match rel.find('/') {
            Some(i) => rel[..i + 1].to_string(),
            None => rel,
        };
        let e = entries.entry(rel).or_default();
        e.0 += r.size;
        if e.1.is_none_or(|m| r.modified > m) {
            e.1 = Some(r.modified);
        }
    }
    if entries.is_empty() && !folder.is_empty() {
        crate::bail!("{folder}: not in the vault");
    }
    let mut names: Vec<_> = entries.into_iter().collect();
    names.sort_by(|a, b| b.0.ends_with('/').cmp(&a.0.ends_with('/')).then(a.0.cmp(&b.0)));
    Ok(names
        .into_iter()
        .map(|(n, (size, m))| {
            format!(
                "{:>10}  {}  {n}\n",
                human_size(size),
                m.unwrap_or(util::Instant { secs: 0, nanos: 0 }).local_minute()
            )
        })
        .collect())
}

fn confirm_overwrite(names: &[String]) -> bool {
    confirm(
        "these files are already in the vault and would be overwritten:",
        names,
        &format!("overwrite {} file(s)? [y/N]", names.len()),
    )
}

/// Shows `intro` and the first 20 names, then asks on the terminal. No
/// terminal means no.
fn confirm(intro: &str, names: &[String], question: &str) -> bool {
    say!("{intro}");
    for (i, n) in names.iter().enumerate() {
        if i == 20 {
            say!("    … and {} more", names.len() - i);
            break;
        }
        say!("    {n}");
    }
    match term::confirm(question) {
        Ok(b) => b,
        Err(e) => {
            say!("cannot ask for confirmation: {}", util::io_reason(&e));
            false
        }
    }
}

/// Identifies a file for Go's `os.SameFile`.
#[derive(PartialEq, Eq)]
struct FileId(u64, u64, PathBuf);

impl FileId {
    fn of(p: &Path, follow: bool) -> Option<FileId> {
        let m = if follow {
            std::fs::metadata(p)
        } else {
            std::fs::symlink_metadata(p)
        }
        .ok()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let _ = &m;
            Some(FileId(m.dev(), m.ino(), PathBuf::new()))
        }
        #[cfg(not(unix))]
        {
            let _ = m;
            Some(FileId(0, 0, std::fs::canonicalize(p).ok()?))
        }
    }
}

fn utf8_rel(p: &Path) -> Result<String> {
    let mut parts = Vec::new();
    for c in p.components() {
        let s = c
            .as_os_str()
            .to_str()
            .ok_or_else(|| Error::new(format!("invalid vault path {:?}", p.to_string_lossy())))?;
        parts.push(s.to_string());
    }
    Ok(parts.join("/"))
}

/// Adds a file, or every regular file under a directory, beneath `dest`,
/// keeping the structure. A directory named "." or ".." adds its contents
/// directly. With `migrate`, nothing is stored unless `overwrite` approves
/// the names it would replace, each original is deleted once stored and
/// checked unchanged, then emptied directories go.
fn add_path(
    s: &Store,
    cat: &mut Catalogue,
    src: &Path,
    dest: &str,
    migrate: bool,
    skip: &[FileId],
    overwrite: &mut dyn FnMut(&[String]) -> bool,
) -> Result<()> {
    let info = std::fs::metadata(src).map_err(|e| Error::io("stat", src, &e))?;
    let skipped = |p: &Path, follow: bool| FileId::of(p, follow).is_some_and(|id| skip.contains(&id));
    if skipped(src, true) {
        crate::bail!("{} is the vault or its key", src.display());
    }
    let mut items: Vec<(PathBuf, String)> = Vec::new();
    let mut dirs = Vec::new();
    if !info.is_dir() {
        let base = src.file_name().map(|b| utf8_rel(Path::new(b))).transpose()?.unwrap_or_default();
        items.push((src.to_path_buf(), util::join(&[dest, &base])));
    } else {
        let base = match src.components().next_back() {
            Some(std::path::Component::Normal(b)) => utf8_rel(Path::new(b))?,
            _ => String::new(),
        };
        walk(src, src, &mut |p, rel, ft| {
            if skipped(p, false) {
                say!("skipping {}: the vault or its key", p.display());
                return Ok(false);
            }
            if ft.is_dir() {
                dirs.push(p.to_path_buf());
                return Ok(true);
            }
            if !ft.is_file() {
                say!("skipping {}: not a regular file", p.display());
                return Ok(false);
            }
            items.push((p.to_path_buf(), util::join(&[dest, &base, &utf8_rel(rel)?])));
            Ok(false)
        })?;
    }
    if migrate {
        let existing: Vec<String> = items.iter().filter(|(_, n)| cat.contains(n)).map(|(_, n)| n.clone()).collect();
        if !existing.is_empty() && !overwrite(&existing) {
            crate::bail!("migrate cancelled; nothing changed");
        }
    }
    for (p, n) in &items {
        let name = VaultName::new(n).ok_or_else(|| Error::new(format!("invalid vault path {n:?}")))?;
        let (added, stamp) = s.add_file(cat, p, &name)?;
        let mut verb = if added.replaced { "replaced" } else { "added" };
        if migrate {
            remove_source(p, stamp)?;
            verb = "migrated";
        }
        say!("{verb} {n}");
    }
    if migrate {
        // Children come after their parents in walk order, so go backwards.
        // Directories still holding skipped files stay.
        for d in dirs.iter().rev() {
            let _ = std::fs::remove_dir(d);
        }
    }
    Ok(())
}

/// Deletes a migrated original, but only if it is still the very file
/// that was stored (same inode, size and modification time).
fn remove_source(p: &Path, stamp: SourceStamp) -> Result<()> {
    match std::fs::metadata(p) {
        Ok(m) if SourceStamp::of(&m) == stamp => std::fs::remove_file(p).map_err(|e| Error::io("remove", p, &e)),
        _ => crate::bail!("{} changed after it was stored; not deleting it", p.display()),
    }
}

/// Go's `filepath.WalkDir`: lexical order, the root first, symlinks not
/// followed. `visit` returns whether to descend into a directory.
fn walk(root: &Path, p: &Path, visit: &mut dyn FnMut(&Path, &Path, &std::fs::FileType) -> Result<bool>) -> Result<()> {
    let ft = std::fs::symlink_metadata(p).map_err(|e| Error::io("lstat", p, &e))?.file_type();
    let rel = p.strip_prefix(root).unwrap_or(Path::new(""));
    if !visit(p, rel, &ft)? || !ft.is_dir() {
        return Ok(());
    }
    let mut entries: Vec<_> = std::fs::read_dir(p)
        .map_err(|e| Error::io("open", p, &e))?
        .map(|e| e.map(|e| e.file_name()))
        .collect::<std::io::Result<_>>()
        .map_err(|e| Error::io("readdir", p, &e))?;
    entries.sort();
    for e in entries {
        walk(root, &p.join(e), visit)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn go_flag_syntax() {
        let mut f = Flags::default();
        let pos = parse_interleaved(&mut f, &s(&["a", "-o", "out", "--yes", "b", "-for=1h", "-r=false"])).unwrap();
        assert_eq!(pos, ["a", "b"]);
        assert_eq!(f.output.as_deref(), Some("out"));
        assert!(f.yes && !f.r);
        assert_eq!(f.ttl, Some(3_600_000_000_000));
        let mut f = Flags::default();
        assert_eq!(parse_interleaved(&mut f, &s(&["--", "-x", "y"])).unwrap(), ["-x", "y"]);
        assert_eq!(parse_interleaved(&mut f, &s(&["-", "y"])).unwrap(), ["-", "y"]);
        for (args, err) in [
            (vec!["-x"], "flag provided but not defined: -x"),
            (vec!["-o"], "flag needs an argument: -o"),
            (vec!["---o"], "bad flag syntax: ---o"),
            (vec!["-=x"], "bad flag syntax: -=x"),
            (vec!["-for", "soon"], "invalid value \"soon\" for flag -for: parse error"),
            (vec!["-yes=maybe"], "invalid boolean value \"maybe\" for -yes: parse error"),
            (vec!["-h"], "flag: help requested"),
        ] {
            assert_eq!(parse_interleaved(&mut Flags::default(), &s(&args)).err().as_deref(), Some(err));
        }
    }
}
