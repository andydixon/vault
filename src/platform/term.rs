// SPDX-License-Identifier: GPL-3.0-or-later

//! Terminal prompts, as the Go `internal/term` package and
//! `golang.org/x/term.ReadPassword` behave: the prompt and input use the
//! controlling terminal (`/dev/tty`, else a terminal on standard input;
//! `CONIN$`/`CONOUT$` on Windows), echo is off while a secret is typed,
//! the line is cleared afterwards, and the bytes typed are kept exactly
//! (a backspace byte deletes the previous byte; `\n` ends the line on Unix,
//! `\r` on Windows).

use crate::secret::SecretVec;
use std::fs::File;
use std::io::{self, Read, Write};

/// Longest secret accepted from the terminal; the buffer never grows.
const MAX_SECRET: usize = 64 << 10;

fn open_terminal() -> io::Result<(File, File)> {
    #[cfg(windows)]
    {
        let i = std::fs::OpenOptions::new().read(true).write(true).open("CONIN$")?;
        let o = std::fs::OpenOptions::new().write(true).open("CONOUT$")?;
        Ok((i, o))
    }
    #[cfg(not(windows))]
    {
        match std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty") {
            Ok(t) => {
                let o = t.try_clone()?;
                Ok((t, o))
            }
            Err(e) => {
                #[cfg(unix)]
                if rustix::termios::isatty(rustix::stdio::stdin()) {
                    let i = File::from(rustix::io::dup(rustix::stdio::stdin())?);
                    let o = i.try_clone()?;
                    return Ok((i, o));
                }
                Err(io::Error::new(
                    e.kind(),
                    format!(
                        "standard input is not a terminal, and /dev/tty is not available: {}",
                        crate::util::io_reason(&e)
                    ),
                ))
            }
        }
    }
}

fn clear_line(out: &mut File) {
    let _ = out.write_all(b"\r\n");
    #[cfg(windows)]
    let ok = enable_vt(out);
    #[cfg(not(windows))]
    let ok = true;
    if ok {
        let _ = out.write_all(b"\x1b[F\x1b[K");
    }
}

#[cfg(windows)]
fn enable_vt(out: &File) -> bool {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::Console::{
        ENABLE_PROCESSED_OUTPUT, ENABLE_VIRTUAL_TERMINAL_PROCESSING, GetConsoleMode, SetConsoleMode,
    };
    let h = out.as_raw_handle() as _;
    let mut mode = 0;
    // SAFETY: h is a live console handle owned by `out`.
    unsafe {
        GetConsoleMode(h, &mut mode) != 0 && SetConsoleMode(h, mode | ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0
    }
}

/// x/term's readPasswordLine.
fn read_line_bytes(r: &mut impl Read) -> io::Result<SecretVec> {
    let mut ret = SecretVec::with_capacity(MAX_SECRET);
    let mut b = [0u8; 1];
    loop {
        match r.read(&mut b) {
            Ok(0) => {
                if !ret.is_empty() {
                    return Ok(ret);
                }
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            Ok(_) => match b[0] {
                0x08 => {
                    let n = ret.len().saturating_sub(1);
                    ret.resize_within_capacity(n);
                }
                b'\n' if cfg!(not(windows)) => return Ok(ret),
                b'\r' if cfg!(windows) => return Ok(ret),
                b'\n' | b'\r' => {}
                c => {
                    if ret.len() == MAX_SECRET {
                        return Err(io::Error::new(io::ErrorKind::InvalidInput, "input too long"));
                    }
                    ret.extend_within_capacity(&[c]);
                }
            },
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

#[cfg(unix)]
fn without_echo<T>(input: &mut File, f: impl FnOnce(&mut File) -> io::Result<T>) -> io::Result<T> {
    use rustix::termios::{InputModes, LocalModes, OptionalActions, tcgetattr, tcsetattr};
    let old = tcgetattr(&*input)?;
    let mut new = old.clone();
    new.local_modes.remove(LocalModes::ECHO);
    new.local_modes.insert(LocalModes::ICANON | LocalModes::ISIG);
    new.input_modes.insert(InputModes::ICRNL);
    tcsetattr(&*input, OptionalActions::Now, &new)?;
    let r = f(input);
    tcsetattr(&*input, OptionalActions::Now, &old)?;
    r
}

#[cfg(windows)]
fn without_echo<T>(input: &mut File, f: impl FnOnce(&mut File) -> io::Result<T>) -> io::Result<T> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::Console::{
        ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT, ENABLE_PROCESSED_OUTPUT, GetConsoleMode, SetConsoleMode,
    };
    let h = input.as_raw_handle() as _;
    let mut old = 0;
    // SAFETY: h is a live console handle owned by `input`.
    if unsafe { GetConsoleMode(h, &mut old) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let new = (old & !ENABLE_ECHO_INPUT) | ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_OUTPUT;
    // SAFETY: as above.
    if unsafe { SetConsoleMode(h, new) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let r = f(input);
    // SAFETY: as above.
    unsafe { SetConsoleMode(h, old) };
    r
}

#[cfg(not(any(unix, windows)))]
fn without_echo<T>(_: &mut File, _: impl FnOnce(&mut File) -> io::Result<T>) -> io::Result<T> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "no terminal support on this platform"))
}

/// Reads a secret from the terminal with echo off. The prompt is erased.
pub fn read_secret(prompt: &str) -> io::Result<SecretVec> {
    let (mut input, mut out) = open_terminal()?;
    write!(out, "{prompt} ")?;
    let r = without_echo(&mut input, read_line_bytes);
    clear_line(&mut out);
    r
}

/// Asks a yes/no question on the terminal; only "y" or "yes" is yes.
pub fn confirm(prompt: &str) -> io::Result<bool> {
    let (mut input, mut out) = open_terminal()?;
    write!(out, "{prompt} ")?;
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    loop {
        match input.read(&mut b) {
            Ok(0) => {
                if line.is_empty() {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                break;
            }
            Ok(_) => {
                line.push(b[0]);
                if b[0] == b'\n' || line.len() > 4096 {
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    let answer = String::from_utf8_lossy(&line).trim().to_lowercase();
    Ok(answer == "y" || answer == "yes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_line_editing() {
        let got = read_line_bytes(&mut &b"ab\x08c\rd\nrest"[..]).unwrap();
        if cfg!(windows) {
            assert_eq!(got.expose(), b"ac");
        } else {
            assert_eq!(got.expose(), b"acd");
        }
        assert_eq!(read_line_bytes(&mut &b"tail"[..]).unwrap().expose(), b"tail");
        assert!(read_line_bytes(&mut &b""[..]).is_err());
    }
}
