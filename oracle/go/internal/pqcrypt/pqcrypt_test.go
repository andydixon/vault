// Copyright 2026 The fury Authors.
// SPDX-License-Identifier: GPL-3.0-or-later

package pqcrypt

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"testing"
)

// TestEncryptWithOptionsRoundTrip exercises the parallel STREAM path end to
// end, at a size spanning many chunks, across a few explicit worker counts
// (including 1, which forces the original sequential code path).
func TestEncryptWithOptionsRoundTrip(t *testing.T) {
	id, err := GeneratePQIdentity()
	if err != nil {
		t.Fatal(err)
	}
	r := id.Recipient()

	plaintext := make([]byte, 4<<20) // 4 MiB: many STREAM chunks
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}

	for _, workers := range []int{1, 2, 8} {
		t.Run(fmt.Sprintf("workers=%d", workers), func(t *testing.T) {
			buf := &bytes.Buffer{}
			w, err := EncryptWithOptions(buf, Options{Workers: workers}, r)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write(plaintext); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}

			out, err := DecryptWithOptions(bytes.NewReader(buf.Bytes()), Options{Workers: workers}, id)
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(out)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Fatal("round-trip mismatch")
			}
		})
	}
}

func TestOptionsWorkers(t *testing.T) {
	if got := (Options{}).workers(); got <= 0 {
		t.Fatalf("default workers = %d, want > 0", got)
	}
	if got := (Options{Workers: 3}).workers(); got != 3 {
		t.Fatalf("explicit workers = %d, want 3", got)
	}
	// An explicit request is honoured even above the automatic cap; only the
	// zero-value automatic path is capped.
	if got := (Options{Workers: 1000}).workers(); got != 1000 {
		t.Fatalf("explicit workers = %d, want 1000", got)
	}
}
