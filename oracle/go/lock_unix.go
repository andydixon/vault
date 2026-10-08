// Copyright 2026 The vault Authors.
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build unix

package main

import (
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// acquireLock uses fcntl record locks, which the kernel releases if the
// process dies, and which also work on NFS.
func acquireLock(path string, exclusive bool, waiting func()) (func(), error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	lk := unix.Flock_t{Type: unix.F_RDLCK, Whence: io.SeekStart}
	if exclusive {
		lk.Type = unix.F_WRLCK
	}
	err = unix.FcntlFlock(f.Fd(), unix.F_SETLK, &lk)
	if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EACCES) {
		waiting()
		for err = unix.EINTR; errors.Is(err, unix.EINTR); {
			err = unix.FcntlFlock(f.Fd(), unix.F_SETLKW, &lk)
		}
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return func() { f.Close() }, nil
}
