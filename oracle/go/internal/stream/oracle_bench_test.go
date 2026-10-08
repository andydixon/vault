// SPDX-License-Identifier: GPL-3.0-or-later

// Test-only benchmarks for comparing with the Rust port (scripts/bench.sh).

package stream

import (
	"bytes"
	"io"
	"testing"
)

// STREAM seal and open of 64 MiB, one goroutine (the sequential path).
func BenchmarkOracleStream64MiB(b *testing.B) {
	key := make([]byte, 32)
	pt := make([]byte, 64<<20)
	var ct bytes.Buffer
	b.SetBytes(int64(len(pt)))
	for b.Loop() {
		ct.Reset()
		w, _ := NewEncryptWriter(key, &ct)
		w.Write(pt)
		w.Close()
		r, _ := NewDecryptReader(key, bytes.NewReader(ct.Bytes()))
		io.Copy(io.Discard, r)
	}
}
