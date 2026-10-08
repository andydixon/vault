// SPDX-License-Identifier: GPL-3.0-or-later

// Test-only benchmarks for comparing with the Rust port (scripts/bench.sh).

package main

import (
	"path/filepath"
	"testing"
)

// Unlocking a key file: Argon2id for both slots.
func BenchmarkOracleUnlock(b *testing.B) {
	p := filepath.Join(b.TempDir(), "key")
	if err := writeKeyFile(p, "bench", ""); err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		if _, err := unlockKeyFile(p, "bench"); err != nil {
			b.Fatal(err)
		}
	}
}
