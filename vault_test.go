// Copyright 2026 The vault Authors.
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestKeyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if err := writeKeyFile(path, "pass", ""); err != nil {
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
	if err := writeKeyFile(keyPath, "pass", ""); err != nil {
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

func TestDecoy(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key")
	if err := writeKeyFile(keyPath, "real", "decoy"); err != nil {
		t.Fatal(err)
	}
	if err := initStore(filepath.Join(dir, "store")); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(dir, "in")
	os.WriteFile(src, []byte("data"), 0o600)
	real, decoy := newTestStore(t, keyPath, "real"), newTestStore(t, keyPath, "decoy")
	for s, name := range map[*store]string{real: "secret", decoy: "shopping"} {
		cat, err := s.catalogue()
		if err != nil || len(cat) != 0 {
			t.Fatalf("fresh vault catalogue = %v, %v", cat, err)
		}
		if _, err := s.add(cat, src, name); err != nil {
			t.Fatal(err)
		}
	}
	for s, name := range map[*store]string{real: "secret", decoy: "shopping"} {
		if cat, _ := s.catalogue(); len(cat) != 1 || cat[name] == nil {
			t.Fatalf("catalogue = %v, want only %s", cat, name)
		}
	}
	if _, err := unlockKeyFile(keyPath, "neither"); err == nil {
		t.Fatal("wrong passphrase unlocked the key")
	}
	entries, _ := os.ReadDir(filepath.Join(dir, "store", recordsDir))
	if len(entries) < fillerMin+2 {
		t.Fatalf("only %d records; filler missing", len(entries))
	}
}

// TestLockExcludesOtherProcess runs a copy of the test binary that holds the
// exclusive lock, then checks this process has to wait for it.
func TestLockExcludesOtherProcess(t *testing.T) {
	if dir := os.Getenv("VAULT_TEST_LOCK_HOLDER"); dir != "" {
		release, err := lockVault(dir, true)
		if err != nil {
			os.Exit(1)
		}
		os.Stdout.WriteString("locked\n")
		io.Copy(io.Discard, os.Stdin) // hold until the parent closes stdin
		release()
		os.Exit(0)
	}
	dir := t.TempDir()
	holder := exec.Command(os.Args[0], "-test.run=^TestLockExcludesOtherProcess$")
	holder.Env = append(os.Environ(), "VAULT_TEST_LOCK_HOLDER="+dir)
	stdin, _ := holder.StdinPipe()
	stdout, _ := holder.StdoutPipe()
	if err := holder.Start(); err != nil {
		t.Fatal(err)
	}
	defer holder.Wait()
	if line, _ := bufio.NewReader(stdout).ReadString('\n'); line != "locked\n" {
		t.Fatalf("holder said %q", line)
	}
	waited := make(chan bool, 1)
	go func() {
		time.Sleep(200 * time.Millisecond)
		stdin.Close() // let the holder go only after we have started waiting
	}()
	for _, exclusive := range []bool{false, true} {
		release, err := acquireLock(filepath.Join(dir, lockName), exclusive, func() { waited <- true })
		if err != nil {
			t.Fatal(err)
		}
		release()
		if !exclusive && len(waited) == 0 {
			t.Fatal("shared lock did not wait for the exclusive holder")
		}
	}
}
