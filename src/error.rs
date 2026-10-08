// SPDX-License-Identifier: GPL-3.0-or-later

//! The command-level error: a lower-case message without a trailing full
//! stop, printed as `vault: MESSAGE`.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    pub msg: String,
    pub kind: Kind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Other,
    /// A source ended before its declared size.
    SourceShort,
    /// A file was written under its final name, but a later durability step
    /// failed: what it depends on must not be deleted.
    AfterPublish,
    /// The thing to remove or read was not there.
    NotFound,
}

impl Error {
    pub fn new(msg: impl Into<String>) -> Error {
        Error {
            msg: msg.into(),
            kind: Kind::Other,
        }
    }

    pub fn with_kind(mut self, kind: Kind) -> Error {
        self.kind = kind;
        self
    }

    pub fn io(op: &str, path: &std::path::Path, e: &std::io::Error) -> Error {
        Error::new(crate::util::io_msg(op, path, e))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.msg)
    }
}

impl std::error::Error for Error {}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error::new(s)
    }
}

impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Error::new(s)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::new(crate::util::io_reason(&e))
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[macro_export]
macro_rules! bail {
    ($($t:tt)*) => { return Err($crate::error::Error::new(format!($($t)*))) };
}
