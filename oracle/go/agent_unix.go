// Copyright 2026 The vault Authors.
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build unix

package main

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// undumpable stops other processes of this user reading the agent's memory,
// where the platform can.
var undumpable = func() {}

// protectMemory keeps b out of swap and the agent out of core dumps.
func protectMemory(b []byte) {
	unix.Mlock(b)
	unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{})
	undumpable()
}

// privateDir checks dir is a real directory that only this user can use,
// so nobody else can reach, swap or plant the agent's socket.
func privateDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.IsDir() || !ok || int(st.Uid) != os.Getuid() || fi.Mode().Perm() != 0o700 {
		return fmt.Errorf("%s is not a private directory of this user", dir)
	}
	return nil
}
