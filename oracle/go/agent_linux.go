// Copyright 2026 The vault Authors.
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import "golang.org/x/sys/unix"

// Not dumpable also means not ptrace-able by the same user.
func init() {
	undumpable = func() { unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0) }
}
