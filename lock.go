// Copyright 2026 The vault Authors.
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"fmt"
	"os"
	"path/filepath"
)

const lockName = ".lock"

// lockVault takes the vault lock: exclusive for commands that change the
// vault, shared for commands that only read it. If another vault process
// holds a conflicting lock it says so and waits. The returned function
// releases the lock.
func lockVault(root string, exclusive bool) (func(), error) {
	release, err := acquireLock(filepath.Join(root, lockName), exclusive, func() {
		fmt.Fprintln(os.Stderr, "waiting for another vault process to finish")
	})
	if err != nil && !exclusive {
		// A reader on read-only storage cannot create the lock file, and
		// nothing can be writing there either.
		return func() {}, nil
	}
	return release, err
}
