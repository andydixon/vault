// SPDX-License-Identifier: GPL-3.0-or-later

// Test-only: decrypts files another implementation wrote, for the Rust
// port's interoperability tests. Skips unless VAULT_ORACLE_DECRYPT is set.

package pqcrypt

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestOracleDecrypt opens every DIR/pattern-SIZE.fury with the identity of
// master seed pattern(32, 1) and checks it holds pattern(SIZE, 0x5a), and
// that every DIR/bad-*.fury is rejected.
func TestOracleDecrypt(t *testing.T) {
	dir := os.Getenv("VAULT_ORACLE_DECRYPT")
	if dir == "" {
		t.Skip("set VAULT_ORACLE_DECRYPT")
	}
	id, err := NewPQIdentityFromSeed(0x0001, pattern(32, 1))
	if err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.fury"))
	if len(files) == 0 {
		t.Fatal("no files")
	}
	for _, f := range files {
		data, _ := os.ReadFile(f)
		r, err := Decrypt(bytes.NewReader(data), id)
		var got []byte
		if err == nil {
			got, err = io.ReadAll(r)
		}
		base := filepath.Base(f)
		if strings.HasPrefix(base, "bad-") {
			if err == nil {
				t.Errorf("%s: accepted", base)
			}
			continue
		}
		size, _ := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(base, "pattern-"), ".fury"))
		if err != nil || !bytes.Equal(got, pattern(size, 0x5a)) {
			t.Errorf("%s: %v", base, err)
		}
		t.Logf("%s ok", base)
	}
}
