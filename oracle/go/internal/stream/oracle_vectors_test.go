// SPDX-License-Identifier: GPL-3.0-or-later

// Test-only vector generator for the Rust port; see oracle/gen-vectors.sh.

package stream

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestOracleVectors(t *testing.T) {
	dir := os.Getenv("VAULT_ORACLE_OUT")
	if dir == "" {
		t.Skip("set VAULT_ORACLE_OUT to write vectors")
	}
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	type vec struct {
		Size      int    `json:"size"`
		CtLen     int    `json:"ct_len"`
		CtSHA256  string `json:"ct_sha256"`
		CtHex     string `json:"ct_hex,omitempty"`
	}
	var vs []vec
	for _, size := range []int{0, 1, 15, 16, 17, ChunkSize - 1, ChunkSize, ChunkSize + 1, 2 * ChunkSize, 2*ChunkSize + 1, 3*ChunkSize - 16, 300000} {
		pt := make([]byte, size)
		for i := range pt {
			pt[i] = byte(i*13 + 7)
		}
		var buf bytes.Buffer
		w, _ := NewEncryptWriter(key, &buf)
		w.Write(pt)
		w.Close()
		// The reader-side encryptor must agree.
		r, _ := NewEncryptReader(key, bytes.NewReader(pt))
		alt, _ := io.ReadAll(r)
		if !bytes.Equal(alt, buf.Bytes()) {
			t.Fatal("EncryptReader disagrees with EncryptWriter")
		}
		s := sha256.Sum256(buf.Bytes())
		v := vec{Size: size, CtLen: buf.Len(), CtSHA256: hex.EncodeToString(s[:])}
		if size <= 17 {
			v.CtHex = hex.EncodeToString(buf.Bytes())
		}
		vs = append(vs, v)
	}
	b, _ := json.MarshalIndent(map[string]any{
		"provenance": "oracle/go at 4c1507c, internal/stream/oracle_vectors_test.go",
		"key":        hex.EncodeToString(key),
		"plaintext":  "byte(i*13+7)",
		"vectors":    vs,
	}, "", " ")
	if err := os.WriteFile(filepath.Join(dir, "stream.json"), append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
