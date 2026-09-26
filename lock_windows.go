// Copyright 2026 The vault Authors.
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build windows

package main

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// acquireLock uses LockFileEx, which Windows releases if the process dies.
func acquireLock(path string, exclusive bool, waiting func()) (func(), error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	h := windows.Handle(f.Fd())
	var flags uint32
	if exclusive {
		flags = windows.LOCKFILE_EXCLUSIVE_LOCK
	}
	err = windows.LockFileEx(h, flags|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, new(windows.Overlapped))
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		waiting()
		err = windows.LockFileEx(h, flags, 0, 1, 0, new(windows.Overlapped))
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return func() { f.Close() }, nil
}
