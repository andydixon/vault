// SPDX-License-Identifier: GPL-3.0-or-later

//! Operating-system specifics. All `unsafe` code outside third-party crates
//! lives in this module, in small documented blocks.

pub mod fs;
pub mod lock;
pub mod memory;
pub mod term;
