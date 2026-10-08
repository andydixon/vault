// Copyright 2026 The vault Authors.
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !unix

package main

// ponytail: no memory locking off unix; VirtualLock on Windows if wanted.
func protectMemory([]byte) {}

// privateDir trusts the per-user temporary directory; Windows keeps it
// private with its ACL.
func privateDir(string) error { return nil }
