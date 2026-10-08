// Copyright 2026 The fury Authors.
// SPDX-License-Identifier: GPL-3.0-or-later

package stream_test

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"runtime"
	"testing"

	"github.com/andydixon/vault/internal/stream"
	"golang.org/x/crypto/chacha20poly1305"
)

func workerCounts() []int {
	return []int{1, 2, 4, runtime.NumCPU() + 4}
}

func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// TestParallelEncryptMatchesSequential is the main compatibility check: for a
// range of lengths and worker counts, the parallel encrypter must produce
// byte-identical ciphertext to the sequential one, and ciphertext from
// either encrypter must decrypt correctly with either reader.
func TestParallelEncryptMatchesSequential(t *testing.T) {
	lengths := []int{0, 1000, cs - 1, cs, cs + 1, cs + 100, 2 * cs, 2*cs + 500}

	for _, length := range lengths {
		for _, workers := range workerCounts() {
			t.Run(fmt.Sprintf("len=%d,workers=%d", length, workers), func(t *testing.T) {
				src := randBytes(t, length)
				key := randBytes(t, chacha20poly1305.KeySize)

				seqBuf := &bytes.Buffer{}
				sw, err := stream.NewEncryptWriter(key, seqBuf)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := sw.Write(src); err != nil {
					t.Fatal(err)
				}
				if err := sw.Close(); err != nil {
					t.Fatal(err)
				}

				parBuf := &bytes.Buffer{}
				pw, err := stream.NewParallelEncryptWriter(key, parBuf, workers)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := pw.Write(src); err != nil {
					t.Fatal(err)
				}
				if err := pw.Close(); err != nil {
					t.Fatal(err)
				}

				if !bytes.Equal(seqBuf.Bytes(), parBuf.Bytes()) {
					t.Fatalf("parallel ciphertext (%d bytes) differs from sequential (%d bytes)",
						parBuf.Len(), seqBuf.Len())
				}

				t.Run("decrypt-with-sequential", func(t *testing.T) {
					dr, err := stream.NewDecryptReader(key, bytes.NewReader(parBuf.Bytes()))
					if err != nil {
						t.Fatal(err)
					}
					checkRoundTrip(t, dr, src)
				})
				t.Run("decrypt-with-parallel", func(t *testing.T) {
					dr, err := stream.NewParallelDecryptReader(key, bytes.NewReader(parBuf.Bytes()), workers)
					if err != nil {
						t.Fatal(err)
					}
					checkRoundTrip(t, dr, src)
				})
				t.Run("sequential-ciphertext-decrypts-with-parallel", func(t *testing.T) {
					dr, err := stream.NewParallelDecryptReader(key, bytes.NewReader(seqBuf.Bytes()), workers)
					if err != nil {
						t.Fatal(err)
					}
					checkRoundTrip(t, dr, src)
				})
			})
		}
	}
}

func checkRoundTrip(t *testing.T, r io.Reader, want []byte) {
	t.Helper()
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("decrypted mismatch: got %d bytes, want %d bytes", len(got), len(want))
	}
}

// TestParallelEncryptWriteInSteps confirms the parallel writer's output is
// unaffected by how the caller chunks its Write calls, mirroring the
// sequential TestRoundTrip's step-size coverage but scoped to a couple of
// representative lengths to keep runtime reasonable.
func TestParallelEncryptWriteInSteps(t *testing.T) {
	lengths := []int{cs + 100, 2*cs + 500}
	steps := []int{1, 537, cs}

	for _, length := range lengths {
		for _, step := range steps {
			t.Run(fmt.Sprintf("len=%d,step=%d", length, step), func(t *testing.T) {
				src := randBytes(t, length)
				key := randBytes(t, chacha20poly1305.KeySize)

				seqBuf := &bytes.Buffer{}
				sw, err := stream.NewEncryptWriter(key, seqBuf)
				if err != nil {
					t.Fatal(err)
				}
				writeInSteps(t, sw, src, step)
				if err := sw.Close(); err != nil {
					t.Fatal(err)
				}

				parBuf := &bytes.Buffer{}
				pw, err := stream.NewParallelEncryptWriter(key, parBuf, 4)
				if err != nil {
					t.Fatal(err)
				}
				writeInSteps(t, pw, src, step)
				if err := pw.Close(); err != nil {
					t.Fatal(err)
				}

				if !bytes.Equal(seqBuf.Bytes(), parBuf.Bytes()) {
					t.Fatalf("parallel ciphertext differs from sequential with step=%d", step)
				}
			})
		}
	}
}

func writeInSteps(t *testing.T, w io.Writer, src []byte, step int) {
	t.Helper()
	for len(src) > 0 {
		n := min(step, len(src))
		if _, err := w.Write(src[:n]); err != nil {
			t.Fatal(err)
		}
		src = src[n:]
	}
}

// TestParallelDecryptMalformed exercises the same categories of malformed
// input the sequential reader rejects. The parallel reader resolves the
// last-chunk ambiguity from the shape of the raw stream (read-ahead) rather
// than by a trial decryption, so in adversarial cases the exact error
// message can differ from the sequential reader's -- what must not differ is
// the accept/reject verdict. Where the message is deterministic under the
// new strategy too, it's asserted explicitly.
func TestParallelDecryptMalformed(t *testing.T) {
	newCiphertext := func(t *testing.T, key []byte, plaintext []byte) []byte {
		t.Helper()
		buf := &bytes.Buffer{}
		w, err := stream.NewEncryptWriter(key, buf)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(plaintext); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}

	t.Run("wrong key", func(t *testing.T) {
		key := randBytes(t, chacha20poly1305.KeySize)
		ciphertext := newCiphertext(t, key, randBytes(t, 1000))
		wrongKey := randBytes(t, chacha20poly1305.KeySize)

		dr, err := stream.NewParallelDecryptReader(wrongKey, bytes.NewReader(ciphertext), 4)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadAll(dr); err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("corrupted byte in non-final chunk", func(t *testing.T) {
		key := randBytes(t, chacha20poly1305.KeySize)
		ciphertext := newCiphertext(t, key, randBytes(t, 2*cs+500))
		ciphertext[10] ^= 0xff // inside the first (non-final) chunk

		dr, err := stream.NewParallelDecryptReader(key, bytes.NewReader(ciphertext), 4)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadAll(dr); err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("truncated", func(t *testing.T) {
		key := randBytes(t, chacha20poly1305.KeySize)
		ciphertext := newCiphertext(t, key, randBytes(t, 2*cs+500))
		truncated := ciphertext[:len(ciphertext)-100]

		dr, err := stream.NewParallelDecryptReader(key, bytes.NewReader(truncated), 4)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadAll(dr); err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("trailing data appended after short last chunk", func(t *testing.T) {
		// With a bytes.Reader, io.ReadFull for the (undersized) chunk buffer
		// greedily consumes the real short chunk AND the trailing garbage in
		// one read, since everything is available at once: the result is a
		// misaligned AEAD tag, not a distinguishable "trailing data" case.
		// This is also true of the sequential reader (same io.ReadFull over
		// the same fixed-size buffer) -- the verdict, an error, is what must
		// hold, not a specific message.
		key := randBytes(t, chacha20poly1305.KeySize)
		ciphertext := newCiphertext(t, key, randBytes(t, 1000)) // ends in a short chunk
		withTrailer := append(append([]byte(nil), ciphertext...), 1, 2, 3, 4, 5)

		dr, err := stream.NewParallelDecryptReader(key, bytes.NewReader(withTrailer), 4)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadAll(dr); err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("trailing data after full-length last chunk", func(t *testing.T) {
		key := randBytes(t, chacha20poly1305.KeySize)
		ciphertext := newCiphertext(t, key, randBytes(t, cs)) // exact multiple: full-length last chunk
		withTrailer := append(append([]byte(nil), ciphertext...), 1, 2, 3, 4, 5)

		dr, err := stream.NewParallelDecryptReader(key, bytes.NewReader(withTrailer), 4)
		if err != nil {
			t.Fatal(err)
		}
		// The trailing bytes are re-interpreted as a short "final" chunk here
		// (a different, but still safe, rejection path than the sequential
		// reader's trailing-byte probe); the verdict must still be an error.
		if _, err := io.ReadAll(dr); err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("empty chunk after a non-empty chunk is rejected", func(t *testing.T) {
		key := randBytes(t, chacha20poly1305.KeySize)
		aead, err := chacha20poly1305.New(key)
		if err != nil {
			t.Fatal(err)
		}

		var malformed []byte
		malformed = append(malformed, sealChunkForTest(t, aead, 0, false, randBytes(t, cs))...)
		malformed = append(malformed, sealChunkForTest(t, aead, 1, true, nil)...)

		dr, err := stream.NewParallelDecryptReader(key, bytes.NewReader(malformed), 4)
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.ReadAll(dr)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if got, want := err.Error(), "last chunk is empty; encrypted payload is malformed"; got != want {
			t.Fatalf("error = %q, want %q", got, want)
		}
	})
}

// sealChunkForTest manually seals a chunk using the same nonce scheme as the
// stream package (a big-endian chunk counter in bytes [3:11], a last-chunk
// flag in the final byte), to construct deliberately malformed streams that
// aren't reachable through the public encrypt API.
func sealChunkForTest(t *testing.T, aead cipher.AEAD, index int64, last bool, plaintext []byte) []byte {
	t.Helper()
	var nonce [chacha20poly1305.NonceSize]byte
	binary.BigEndian.PutUint64(nonce[3:11], uint64(index))
	if last {
		nonce[len(nonce)-1] = 1
	}
	return aead.Seal(nil, nonce[:], plaintext, nil)
}

// TestParallelRace exercises the pipeline with oversubscribed workers on a
// multi-chunk payload; run with -race to catch data races in the ordered
// fan-in.
func TestParallelRace(t *testing.T) {
	key := randBytes(t, chacha20poly1305.KeySize)
	src := randBytes(t, 6*cs+12345)

	buf := &bytes.Buffer{}
	w, err := stream.NewParallelEncryptWriter(key, buf, runtime.NumCPU()*2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(src); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	dr, err := stream.NewParallelDecryptReader(key, bytes.NewReader(buf.Bytes()), runtime.NumCPU()*2)
	if err != nil {
		t.Fatal(err)
	}
	checkRoundTrip(t, dr, src)
}
