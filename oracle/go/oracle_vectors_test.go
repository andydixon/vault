// SPDX-License-Identifier: GPL-3.0-or-later

// Test-only vector and fixture generator for the Rust port. It calls the
// frozen implementation and records what it computes; it changes nothing in
// the vault binary. Run through oracle/gen-vectors.sh.

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	"github.com/andydixon/vault/internal/pqcrypt"
	"golang.org/x/crypto/argon2"
)

// Synthetic, public test passphrases. Never use them for anything real.
const (
	oracleReal  = "oracle-real passphrase"
	oracleDecoy = "oracle-decoy passphrase"
)

func TestOracleVectors(t *testing.T) {
	dir := os.Getenv("VAULT_ORACLE_OUT")
	if dir == "" {
		t.Skip("set VAULT_ORACLE_OUT to write vectors")
	}
	out := map[string]any{"provenance": "oracle/go at 4c1507c, oracle_vectors_test.go"}

	// Key files.
	keys := map[string]any{}
	for _, k := range []struct{ name, real, decoy string }{
		{"key-with-decoy.pem", oracleReal, oracleDecoy},
		{"key-no-decoy.pem", oracleReal, ""},
	} {
		p := filepath.Join(dir, k.name)
		os.Remove(p)
		if err := writeKeyFile(p, k.real, k.decoy); err != nil {
			t.Fatal(err)
		}
		entry := map[string]any{}
		for label, pass := range map[string]string{"real": k.real, "decoy": k.decoy} {
			if pass == "" {
				continue
			}
			id, err := unlockKeyFile(p, pass)
			if err != nil {
				t.Fatal(err)
			}
			entry[label] = map[string]any{"passphrase": pass, "suite": id.SuiteID(), "seed": hex.EncodeToString(id.Seed())}
		}
		keys[k.name] = entry
	}
	out["keys"] = keys

	var argon []map[string]string
	for i, pass := range []string{"", "a", "correct horse", "pässwörd ü", "x\x00y"} {
		salt := make([]byte, 16)
		for j := range salt {
			salt[j] = byte(i*16 + j)
		}
		k := argon2.IDKey([]byte(pass), salt, argonTime, argonMemory, argonThreads, 32)
		argon = append(argon, map[string]string{"passphrase_hex": hex.EncodeToString([]byte(pass)), "salt": hex.EncodeToString(salt), "key": hex.EncodeToString(k)})
	}
	out["argon2id"] = argon
	out["key_header_hex"] = hex.EncodeToString(keyHeader())

	// Object IDs and sizes.
	seed := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	var ids []string
	for i := range int64(4) {
		ids = append(ids, objectID(seed, i))
	}
	out["object_ids"] = map[string]any{"seed": seed, "ids": ids, "big_index": objectID(seed, 1<<40), "big_index_value": int64(1 << 40)}
	padded := map[string]int64{}
	counts := map[string]int64{}
	for _, n := range []int64{0, 1, 16, 65535, 65536, 65537, 1 << 20, chunkSize - 1, chunkSize, chunkData - 1, chunkData, chunkData + 1, 2 * chunkData, fileLimit} {
		padded[fmt.Sprint(n)] = paddedSize(n)
		counts[fmt.Sprint(n)] = objectCount(n)
	}
	out["padded_size"] = padded
	out["object_count"] = counts

	names := map[string]bool{}
	for _, n := range []string{"", "a", "a/b", "/a", "a/", "a//b", "./a", "a/./b", "../a", "a/..", "..", ".", "a/../b", "a\\b", "a\x00b",
		"a\nb", "a\x7fb", "a\u0085b", "ü/ñ", "\xff", "a b", " a", "...", "a/...", "..a", "a/.b", string(make([]byte, 1024)), longName(1024), longName(1025), "a​b", " "} {
		names[hex.EncodeToString([]byte(n))] = validName(n)
	}
	out["valid_name_hex"] = names

	sizes := map[string]any{}
	for _, s := range []string{"0", "512", "2k", "500M", "2G", "1TB", "", "G", "-1", "2X", "1.5G", "2T", "+5", "1KB", "1MK", "1kb", "B", "1T", "1099511627776", "1099511627777", " 1", "0x10", "1024G", "1025G", "-0", "1bb"} {
		n, err := parseSize(s)
		if err != nil {
			sizes[s] = nil
		} else {
			sizes[s] = n
		}
	}
	out["parse_size"] = sizes

	human := map[string]string{}
	for _, n := range []int64{0, 1, 1023, 1024, 1025, 1536, 1101, 10239, 10240, 1048575, 1048576, 1 << 30, 1<<40 - 1, 1 << 40, 1<<62 + 12345, 1<<63 - 1, 1075, 1126, 1177, 1638, 1689} {
		human[fmt.Sprint(n)] = humanSize(n)
	}
	out["human_size"] = human

	clean := map[string]string{}
	for _, p := range []string{"", ".", "..", "/", "//", "a/b/../c", "/../a", "a/./b/", "../../a", "a//b", "./", "/a/b/..", "a/b/../../..", "abc/def/ghi/../.."} {
		clean[p] = path.Clean(p)
	}
	out["path_clean"] = clean

	durs := map[string]any{}
	for _, d := range []string{"5m", "1h", "90s", "1.5h", "300ms", "1h30m", "0", "-5m", "", "5", "1d", "2h45m30.5s", "1us", "1µs", "1ns", ".5s", "5.s", "+5m", "9223372036854775807ns", "9223372036854775808ns"} {
		v, err := time.ParseDuration(d)
		if err != nil {
			durs[d] = nil
		} else {
			durs[d] = map[string]any{"ns": int64(v), "string": v.String()}
		}
	}
	out["durations"] = durs

	// Record JSON, exactly as written.
	var recs []map[string]any
	for _, r := range []record{
		{Name: "plain.txt", Seed: seed, Size: 5, Mode: 0o644, Modified: time.Unix(1700000000, 123456789).UTC(), Added: time.Unix(1700000001, 0).UTC()},
		{Name: "<a&b>/  '\"\\x", Seed: seed, Size: 0, Mode: 0o755, Modified: time.Unix(0, 0).UTC(), Added: time.Unix(1, 100).UTC()},
		{Name: "ü/日本語", Seed: seed, Size: 1 << 40, Mode: 0o600, Modified: time.Unix(-1, 500000000).UTC(), Added: time.Unix(253402300799, 999999999).UTC()},
		{Name: "tab\there", Seed: seed, Size: 1, Mode: 0, Modified: time.Unix(1234567890, 120000000).UTC(), Added: time.Unix(1234567890, 1000).UTC()},
	} {
		b, err := json.Marshal(&r)
		if err != nil {
			t.Fatal(err)
		}
		recs = append(recs, map[string]any{"json": string(b), "name": r.Name, "modified_unix_nano": r.Modified.UnixNano(), "added_unix_nano": r.Added.UnixNano()})
	}
	out["records"] = recs

	writeMiniVault(t, filepath.Join(dir, "mini-vault"), filepath.Join(dir, "key-with-decoy.pem"))

	b, _ := json.MarshalIndent(out, "", " ")
	if err := os.WriteFile(filepath.Join(dir, "store.json"), append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func longName(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'a' + byte(i%26)
	}
	return string(b)
}

// writeMiniVault builds a small vault through the real store code, without
// init's filler (which would make the fixture megabytes): three real files,
// one decoy file and one record sealed to a throwaway key.
func writeMiniVault(t *testing.T, root, keyPath string) {
	os.RemoveAll(root)
	for _, d := range []string{recordsDir, objectsDir} {
		for i := range 256 {
			if err := os.MkdirAll(filepath.Join(root, d, fmt.Sprintf("%02x", i)), 0o700); err != nil {
				t.Fatal(err)
			}
		}
	}
	os.WriteFile(filepath.Join(root, markerName), []byte(markerContent), 0o600)
	src := filepath.Join(t.TempDir(), "src")
	put := func(s *store, name string, body []byte, mode os.FileMode, mtime time.Time) {
		os.WriteFile(src, body, 0o600)
		os.Chmod(src, mode)
		os.Chtimes(src, mtime, mtime)
		cat, err := s.catalogue()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.add(cat, src, name); err != nil {
			t.Fatal(err)
		}
	}
	real, _ := unlockKeyFile(keyPath, oracleReal)
	decoy, _ := unlockKeyFile(keyPath, oracleDecoy)
	throwaway, _ := pqcrypt.GeneratePQIdentity()
	rs := &store{root: root, id: real}
	boundary := make([]byte, minPadding-idSize)
	for i := range boundary {
		boundary[i] = byte(i * 7)
	}
	put(rs, "hello.txt", []byte("hello"), 0o644, time.Unix(1700000000, 123456789))
	put(rs, "dir/empty", nil, 0o600, time.Unix(1600000000, 0))
	put(rs, "dir/ünïcode.bin", boundary, 0o755, time.Unix(1500000000, 999999999))
	put(&store{root: root, id: decoy}, "shopping.txt", []byte("milk\n"), 0o600, time.Unix(1700000000, 0))
	put(&store{root: root, id: throwaway}, "foreign", []byte("not yours"), 0o600, time.Unix(1700000000, 0))
	for _, d := range []string{recordsDir, objectsDir} {
		shards, _ := filepath.Glob(filepath.Join(root, d, "??"))
		for _, p := range append(shards, filepath.Join(root, d)) {
			os.Chtimes(p, epoch, epoch)
		}
	}
}
