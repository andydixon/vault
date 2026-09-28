// Copyright 2026 The vault Authors.
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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
	if err := initStore(filepath.Join(dir, "store"), 0); err != nil {
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
	data, _ := os.ReadFile(s.path(objectsDir, objectID(c.Seed, 0)))
	os.WriteFile(s.path(objectsDir, objectID(d.Seed, 0)), data, 0o600)
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
	if err := initStore(filepath.Join(dir, "store"), 0); err != nil {
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
	if n := len(ciphertexts(t, filepath.Join(dir, "store", recordsDir))); n < fillerMin+2 {
		t.Fatalf("only %d records; filler missing", n)
	}
}

// ciphertexts maps every file under dir to its size.
func ciphertexts(t *testing.T, dir string) map[string]int64 {
	t.Helper()
	sizes := map[string]int64{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		info, err := d.Info()
		sizes[p] = info.Size()
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return sizes
}

// TestChunks checks a file bigger than one chunk becomes unlinkable 4 MiB
// objects plus a bucket-sized tail, all in their shards, and that reordering
// the chunks is caught.
func TestChunks(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key")
	if err := writeKeyFile(keyPath, "pass", ""); err != nil {
		t.Fatal(err)
	}
	if err := initStore(filepath.Join(dir, "store"), 0); err != nil {
		t.Fatal(err)
	}
	s := newTestStore(t, keyPath, "pass")
	objects := filepath.Join(s.root, objectsDir)
	before := ciphertexts(t, objects)

	src := filepath.Join(dir, "in")
	want := make([]byte, 2*chunkData+100)
	rand.Read(want)
	os.WriteFile(src, want, 0o600)
	cat, _ := s.catalogue()
	if _, err := s.add(cat, src, "big"); err != nil {
		t.Fatal(err)
	}
	cat, _ = s.catalogue()
	r := cat["big"][0]
	var sizes []int64
	for i := range objectCount(r.Size) {
		p := s.path(objectsDir, objectID(r.Seed, i))
		if filepath.Base(filepath.Dir(p)) != filepath.Base(p)[:2] {
			t.Fatalf("%s is in the wrong shard", p)
		}
		sizes = append(sizes, ciphertexts(t, p)[p])
	}
	if len(sizes) != 3 || sizes[0] != sizes[1] || sizes[2] >= sizes[0] {
		t.Fatalf("object sizes = %v, want two full chunks and a smaller tail", sizes)
	}
	if n := len(ciphertexts(t, objects)) - len(before); n != 3 {
		t.Fatalf("add wrote %d objects, want 3", n)
	}
	for p, size := range ciphertexts(t, objects) {
		if size > sizes[0] {
			t.Fatalf("%s is %d bytes, larger than a chunk", p, size)
		}
	}

	out := filepath.Join(dir, "out")
	if err := s.get("big", out); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(out); !bytes.Equal(got, want) {
		t.Fatal("round trip mismatch")
	}

	a, b := s.path(objectsDir, objectID(r.Seed, 0)), s.path(objectsDir, objectID(r.Seed, 1))
	os.Rename(a, a+".x")
	os.Rename(b, a)
	os.Rename(a+".x", b)
	if err := s.get("big", filepath.Join(dir, "swapped")); err == nil {
		t.Fatal("reordered chunks were accepted")
	}

	if err := s.delete("big"); err != nil {
		t.Fatal(err)
	}
	if n := len(ciphertexts(t, objects)); n != len(before) {
		t.Fatalf("%d objects after rm, want %d", n, len(before))
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

func TestParseSize(t *testing.T) {
	for in, want := range map[string]int64{"0": 0, "512": 512, "2k": 2 << 10, "500M": 500 << 20, "2G": 2 << 30, "1TB": 1 << 40} {
		if got, err := parseSize(in); err != nil || got != want {
			t.Errorf("parseSize(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "G", "-1", "2X", "1.5G", "2T"} {
		if _, err := parseSize(in); err == nil {
			t.Errorf("parseSize(%q) accepted", in)
		}
	}
}

// TestFiller checks a filler target is met with entries shaped like real
// files: fixed-size records and objects no bigger than a chunk.
func TestFiller(t *testing.T) {
	root := filepath.Join(t.TempDir(), "store")
	if err := initStore(root, 24<<20); err != nil {
		t.Fatal(err)
	}
	if n := len(ciphertexts(t, filepath.Join(root, recordsDir))); n < fillerMin {
		t.Fatalf("%d filler records, want at least %d", n, fillerMin)
	}
	var total, largest int64
	for _, size := range ciphertexts(t, filepath.Join(root, objectsDir)) {
		total, largest = total+size, max(largest, size)
	}
	if total < 24<<20 || largest > chunkSize+chunkSize/64 {
		t.Fatalf("filler objects total %d, largest %d", total, largest)
	}
}

// TestAddTree migrates "." holding the vault and key: structure is kept,
// originals and emptied directories go, the vault and key are left alone.
// A URL download is then added under a folder.
func TestAddTree(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key")
	if err := writeKeyFile(keyPath, "pass", ""); err != nil {
		t.Fatal(err)
	}
	if err := initStore(filepath.Join(dir, "store"), 0); err != nil {
		t.Fatal(err)
	}
	s := newTestStore(t, keyPath, "pass")
	os.MkdirAll(filepath.Join(dir, "a", "b"), 0o755)
	os.WriteFile(filepath.Join(dir, "x"), []byte("x"), 0o600)
	os.WriteFile(filepath.Join(dir, "a", "b", "y"), []byte("y"), 0o600)
	t.Chdir(dir)

	var skip []os.FileInfo
	for _, p := range []string{"store", "key"} {
		fi, _ := os.Stat(p)
		skip = append(skip, fi)
	}
	cat, _ := s.catalogue()
	if err := addPath(s, cat, "x", "d", false, skip, nil); err != nil {
		t.Fatal(err)
	}
	// Migrating over d/x must ask first, and a no must leave everything.
	var asked []string
	no := func(names []string) bool { asked = names; return false }
	if err := addPath(s, cat, ".", "d", true, skip, no); err == nil || !slices.Equal(asked, []string{"d/x"}) {
		t.Fatalf("migrate over d/x: err %v, asked %v", err, asked)
	}
	if _, err := os.Stat("x"); err != nil || len(cat) != 1 {
		t.Fatalf("declined migrate changed things: %v, %d stored", err, len(cat))
	}
	if err := addPath(s, cat, ".", "d", true, skip, func([]string) bool { return true }); err != nil {
		t.Fatal(err)
	}
	var got []string
	for name := range cat {
		got = append(got, name)
	}
	slices.Sort(got)
	if !slices.Equal(got, []string{"d/a/b/y", "d/x"}) {
		t.Fatalf("stored %v", got)
	}
	var left []string
	entries, _ := os.ReadDir(".")
	for _, e := range entries {
		left = append(left, e.Name())
	}
	if !slices.Equal(left, []string{"key", "store"}) {
		t.Fatalf("left behind %v", left)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.UserAgent() != chromeUA {
			http.Error(w, "bad agent", http.StatusForbidden)
			return
		}
		io.WriteString(w, "body")
	}))
	defer srv.Close()
	if err := addURL(s, cat, srv.URL+"/files/page.html", "web"); err != nil {
		t.Fatal(err)
	}
	if err := s.get("web/page.html", "out"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile("out"); string(b) != "body" {
		t.Fatalf("downloaded %q", b)
	}
}
