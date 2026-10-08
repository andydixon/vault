// SPDX-License-Identifier: GPL-3.0-or-later

// Test-only benchmarks for comparing with the Rust port (scripts/bench.sh).

package pqcrypt

import (
	"bytes"
	"io"
	"testing"
)

func BenchmarkOracleDerive(b *testing.B) {
	seed := pattern(32, 1)
	for b.Loop() {
		id, _ := NewPQIdentityFromSeed(0x0001, seed)
		id.Close()
	}
}

func BenchmarkOracleWrap(b *testing.B) {
	id, _ := NewPQIdentityFromSeed(0x0001, pattern(32, 1))
	r := id.Recipient()
	fk := pattern(32, 2)
	for b.Loop() {
		r.Wrap(fk)
	}
}

func BenchmarkOracleUnwrap(b *testing.B) {
	id, _ := NewPQIdentityFromSeed(0x0001, pattern(32, 1))
	st, _ := id.Recipient().Wrap(pattern(32, 2))
	for b.Loop() {
		if _, err := id.Unwrap(st); err != nil {
			b.Fatal(err)
		}
	}
}

// Whole-file encryption and decryption of 4 MiB: one vault object.
func BenchmarkOracleObject4MiB(b *testing.B) {
	id, _ := NewPQIdentityFromSeed(0x0001, pattern(32, 1))
	pt := pattern(4<<20, 3)
	var ct bytes.Buffer
	b.SetBytes(int64(len(pt)))
	for b.Loop() {
		ct.Reset()
		w, _ := Encrypt(&ct, id.Recipient())
		w.Write(pt)
		w.Close()
		r, err := Decrypt(bytes.NewReader(ct.Bytes()), id)
		if err != nil {
			b.Fatal(err)
		}
		io.Copy(io.Discard, r)
	}
}
