// SPDX-License-Identifier: GPL-3.0-or-later

//! vault: a post-quantum encrypted file vault. The binary is a thin wrapper
//! around [`cli::main`]; the library exists so integration tests and
//! benchmarks can reach the same code.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod crypto;
pub mod keyfile;
pub mod platform;
pub mod rng;
pub mod secret;
pub mod util;
