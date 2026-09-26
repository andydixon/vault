// Copyright 2026 The vault Authors.
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !unix && !windows

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"
)

// acquireLock falls back to an exclusive lock file where the OS offers no
// file locks. Every lock is exclusive here.
// ponytail: a crash leaves the lock file behind; the error names it for manual removal.
func acquireLock(path string, _ bool, waiting func()) (func(), error) {
	for i := 0; ; i++ {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			f.Close()
			return func() { os.Remove(path) }, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
		if i == 0 {
			waiting()
		}
		if i == 600 {
			return nil, fmt.Errorf("vault still locked after a minute; if no other vault process is running, remove %s", path)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
