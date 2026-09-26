// Copyright 2026 The vault Authors.
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestKeyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if err := writeKeyFile(path, "pass"); err != nil {
		t.Fatal(err)
	}
	if _, err := unlockKeyFile(path, "wrong"); err == nil {
		t.Fatal("wrong passphrase unlocked the key")
	}
	if _, err := unlockKeyFile(path, "pass"); err != nil {
		t.Fatal(err)
	}
}

func newTestStore(t *testing.T, keyPath, pass string) *store {
	t.Helper()
	id, err := unlockKeyFile(keyPath, pass)
	if err != nil {
		t.Fatal(err)
	}
	s, err := openStore(filepath.Join(filepath.Dir(keyPath), "store"), id)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestStoreLifecycle(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key")
	if err := writeKeyFile(keyPath, "pass"); err != nil {
		t.Fatal(err)
	}
	if err := initStore(filepath.Join(dir, "store")); err != nil {
		t.Fatal(err)
	}
	s := newTestStore(t, keyPath, "pass")
	src := filepath.Join(dir, "in")
	want := bytes.Repeat([]byte("x"), 70000)
	os.WriteFile(src, want, 0o640)

	cat, _ := s.catalogue()
	if _, err := s.add(cat, src, "a/b"); err != nil {
		t.Fatal(err)
	}
	if replaced, err := s.add(cat, src, "a/b"); err != nil || !replaced {
		t.Fatalf("replace: %v %v", replaced, err)
	}
	if _, err := s.add(cat, src, "c"); err != nil {
		t.Fatal(err)
	}
	if cat, _ = s.catalogue(); len(cat) != 2 || len(cat["a/b"]) != 1 {
		t.Fatalf("catalogue = %v", cat)
	}
	if err := s.rename("a/b", "d"); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	if err := s.get("d", out); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(out); !bytes.Equal(got, want) {
		t.Fatal("round trip mismatch")
	}
	if err := s.get("d", out); err == nil {
		t.Fatal("get overwrote an existing file")
	}

	// Swapping one object for another must be detected.
	cat, _ = s.catalogue()
	d, c := cat["d"][0], cat["c"][0]
	objects := filepath.Join(s.root, objectsDir)
	data, _ := os.ReadFile(filepath.Join(objects, c.Object))
	os.WriteFile(filepath.Join(objects, d.Object), data, 0o600)
	if err := s.get("d", filepath.Join(dir, "swapped")); err == nil {
		t.Fatal("swapped object was accepted")
	}

	if err := s.delete("c"); err != nil {
		t.Fatal(err)
	}
	if cat, _ = s.catalogue(); len(cat) != 1 {
		t.Fatalf("after delete: %v", cat)
	}
}
