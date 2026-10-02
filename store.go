// Copyright 2026 The vault Authors.
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	mrand "math/rand/v2"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/andydixon/vault/internal/pqcrypt"
)

// On disk a vault is:
//
//	DIR/.vault              marker
//	DIR/records/<xx>/<id>   one encrypted catalogue record per file
//	DIR/objects/<xx>/<id>   the encrypted body of a file, in one or more chunks
//
// <xx> is the first two hex digits of <id>, spreading entries over 256
// shards. IDs look random: record IDs are, and a file's object IDs derive
// from a secret seed in its record, so nothing on disk links a file's
// chunks. Records are padded to one fixed size. A body is cut into
// chunkSize objects and the last is padded to a power-of-two bucket, so
// every object is 64 KiB to 4 MiB whatever the file size. Every ciphertext's
// and shard's mtime is pinned to the epoch.

const (
	markerName     = ".vault"
	markerContent  = "VAULT 2\n"
	recordsDir     = "records"
	objectsDir     = "objects"
	recordSize     = 4096
	nameLimit      = 1024
	fileLimit      = int64(1) << 40
	minPadding     = int64(64 << 10)
	chunkSize      = minPadding << 6 // 4 MiB, the largest bucket
	chunkData      = chunkSize - idSize
	idSize         = 16
	objectSeedSize = 32
	fillerMin      = 8
	fillerMax      = 32
)

var epoch = time.Unix(0, 0)

type record struct {
	Name     string    `json:"name"`
	Seed     string    `json:"seed"` // derives the file's object IDs
	Size     int64     `json:"size"`
	Mode     uint32    `json:"mode"`
	Modified time.Time `json:"modified"`
	Added    time.Time `json:"added"`

	id string // record file ID; not stored
}

type store struct {
	root   string
	id     *pqcrypt.PQIdentity
	noSync bool // filler needs no per-file durability
}

// initStore creates a vault at root holding at least filler bytes of filler.
func initStore(root string, filler int64) error {
	if _, err := os.Stat(filepath.Join(root, markerName)); err == nil {
		return fmt.Errorf("%s is already a vault", root)
	}
	// Every shard exists from the start, so the tree's shape says nothing.
	for _, dir := range []string{recordsDir, objectsDir} {
		for i := range 256 {
			if err := os.MkdirAll(filepath.Join(root, dir, fmt.Sprintf("%02x", i)), 0o700); err != nil {
				return err
			}
		}
	}
	if err := writeFiller(root, filler); err != nil {
		return err
	}
	for _, dir := range []string{recordsDir, objectsDir} {
		shards, _ := filepath.Glob(filepath.Join(root, dir, "??"))
		for _, p := range append(shards, filepath.Join(root, dir)) {
			if err := os.Chtimes(p, epoch, epoch); err != nil {
				return err
			}
		}
	}
	return os.WriteFile(filepath.Join(root, markerName), []byte(markerContent), 0o600)
}

// writeFiller stores random entries sealed to a key that is thrown away.
// Every vault therefore holds entries nobody can open, so a file hidden from
// a decoy passphrase is indistinguishable from filler. Filler entries are
// real entries, written by the same code as add, of log-uniformly random
// sizes: fillerMin to fillerMax of them, or more until they total target
// bytes.
func writeFiller(root string, target int64) error {
	throwaway, err := pqcrypt.GeneratePQIdentity()
	if err != nil {
		return err
	}
	defer throwaway.Close()
	s := &store{root: root, id: throwaway, noSync: true}
	// Bigger targets allow bigger files, so the filler holds multi-chunk
	// files in about the proportion a real collection would.
	upper := float64(min(max(target/8, chunkSize), 1<<30))
	count := fillerMin + mrand.IntN(fillerMax-fillerMin+1)
	for i, total := 0, int64(0); i < count || total < target; i++ {
		size := int64(1024 * math.Exp(mrand.Float64()*math.Log(upper/1024)))
		seed, err := randomHex(objectSeedSize)
		if err != nil {
			return err
		}
		if err := s.writeObjects(rand.Reader, seed, size); err != nil {
			return err
		}
		name, err := randomHex(8)
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		if err := s.writeRecord(&record{Name: name, Seed: seed, Size: size, Mode: 0o600, Modified: now, Added: now}); err != nil {
			return err
		}
		total += size
	}
	return nil
}

func openStore(root string, id *pqcrypt.PQIdentity) (*store, error) {
	marker, err := os.ReadFile(filepath.Join(root, markerName))
	if err != nil || string(marker) != markerContent {
		return nil, fmt.Errorf("%s is not a vault; run vault init", root)
	}
	return &store{root: root, id: id}, nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func validHex(s string, n int) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == n && hex.EncodeToString(b) == s
}

func validID(s string) bool { return validHex(s, idSize) }

// objectID derives the ID of a file's i-th object from its record's seed.
// Without the seed the IDs are unlinkable, so a file's chunks can't be told
// apart from any other object.
func objectID(seed string, i int64) string {
	key, _ := hex.DecodeString(seed)
	m := hmac.New(sha256.New, key)
	binary.Write(m, binary.BigEndian, i)
	return hex.EncodeToString(m.Sum(nil)[:idSize])
}

// objectCount is how many objects hold a file of size bytes.
func objectCount(size int64) int64 {
	return max(1, (size+chunkData-1)/chunkData)
}

func (s *store) path(dir, id string) string {
	return filepath.Join(s.root, dir, id[:2], id)
}

// removeFile deletes dir/id and re-pins its shard's mtime.
func (s *store) removeFile(dir, id string) error {
	p := s.path(dir, id)
	if err := os.Remove(p); err != nil {
		return err
	}
	return os.Chtimes(filepath.Dir(p), epoch, epoch)
}

func validName(name string) bool {
	if name == "" || len(name) > nameLimit || !utf8.ValidString(name) || path.Clean(name) != name ||
		path.IsAbs(name) || name == "." || name == ".." || strings.HasPrefix(name, "../") || strings.Contains(name, "\\") {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// paddedSize rounds size up to the next power-of-two bucket.
func paddedSize(size int64) int64 {
	p := minPadding
	for p < size {
		p *= 2
	}
	return p
}

// writeCiphertext encrypts to dir/id via a temporary file, so a partial
// ciphertext never appears under a real ID.
func (s *store) writeCiphertext(dir, id string, write func(io.Writer) error) error {
	dst := s.path(dir, id)
	dir = filepath.Dir(dst)
	tmp, err := os.CreateTemp(dir, ".pending-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	w, err := pqcrypt.Encrypt(tmp, s.id.Recipient())
	if err != nil {
		return err
	}
	if err := write(w); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	if !s.noSync {
		if err := tmp.Sync(); err != nil {
			return err
		}
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chtimes(tmp.Name(), epoch, epoch); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), dst); err != nil {
		return err
	}
	if err := os.Chtimes(dir, epoch, epoch); err != nil || s.noSync {
		return err
	}
	return syncDir(dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (s *store) writeRecord(r *record) error {
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if len(data) > recordSize-4 {
		return errors.New("catalogue record too large")
	}
	plain := make([]byte, recordSize)
	binary.BigEndian.PutUint32(plain, uint32(len(data)))
	copy(plain[4:], data)
	if _, err := rand.Read(plain[4+len(data):]); err != nil {
		return err
	}
	if r.id, err = randomHex(idSize); err != nil {
		return err
	}
	return s.writeCiphertext(recordsDir, r.id, func(w io.Writer) error {
		_, err := w.Write(plain)
		return err
	})
}

// catalogue decrypts every record this identity can open. Records sealed to
// a different key are skipped silently: they are simply not ours.
func (s *store) catalogue() (map[string][]*record, error) {
	shards, err := os.ReadDir(filepath.Join(s.root, recordsDir))
	if err != nil {
		return nil, err
	}
	byName := map[string][]*record{}
	for _, shard := range shards {
		if !shard.IsDir() {
			continue
		}
		entries, err := os.ReadDir(filepath.Join(s.root, recordsDir, shard.Name()))
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if !validID(e.Name()) || e.Name()[:2] != shard.Name() {
				continue
			}
			r, err := s.readRecord(e.Name())
			var noMatch *pqcrypt.NoIdentityMatchError
			if errors.As(err, &noMatch) {
				continue
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "vault: skipping unreadable record %s: %v\n", e.Name(), err)
				continue
			}
			byName[r.Name] = append(byName[r.Name], r)
		}
	}
	// Newest first, so [0] is current. Duplicates only exist after an
	// interrupted replace; the next write of that name cleans them up.
	for _, rs := range byName {
		sort.Slice(rs, func(i, j int) bool { return rs[i].Added.After(rs[j].Added) })
	}
	return byName, nil
}

func (s *store) readRecord(id string) (*record, error) {
	f, err := os.Open(s.path(recordsDir, id))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	pr, err := pqcrypt.Decrypt(f, s.id)
	if err != nil {
		return nil, err
	}
	plain, err := io.ReadAll(io.LimitReader(pr, recordSize+1))
	if err != nil {
		return nil, err
	}
	if len(plain) != recordSize {
		return nil, errors.New("wrong record size")
	}
	n := binary.BigEndian.Uint32(plain)
	if n > recordSize-4 {
		return nil, errors.New("malformed record")
	}
	r := &record{id: id}
	dec := json.NewDecoder(bytes.NewReader(plain[4 : 4+n]))
	dec.DisallowUnknownFields()
	if err := dec.Decode(r); err != nil {
		return nil, err
	}
	if !validName(r.Name) || !validHex(r.Seed, objectSeedSize) || r.Size < 0 || r.Size > fileLimit {
		return nil, errors.New("malformed record")
	}
	return r, nil
}

// add stores the file at src as name, replacing any existing file of that
// name, and updates cat to match. It reports whether something was replaced.
func (s *store) add(cat map[string][]*record, src, name string) (bool, error) {
	if !validName(name) {
		return false, fmt.Errorf("invalid vault path %q", name)
	}
	f, err := os.Open(src)
	if err != nil {
		return false, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() || info.Size() > fileLimit {
		return false, fmt.Errorf("%s: not a regular file of at most 1 TiB", src)
	}
	replaced, err := s.addReader(cat, f, info.Size(), info.Mode().Perm(), info.ModTime(), name)
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		err = fmt.Errorf("%s changed while being added", src)
	}
	return replaced, err
}

// addReader stores size bytes from r as name, like add. Reading fewer than
// size bytes stores nothing and fails with io.ErrUnexpectedEOF or io.EOF.
func (s *store) addReader(cat map[string][]*record, r io.Reader, size int64, mode fs.FileMode, mtime time.Time, name string) (bool, error) {
	if !validName(name) {
		return false, fmt.Errorf("invalid vault path %q", name)
	}
	if size < 0 || size > fileLimit {
		return false, fmt.Errorf("%s: larger than 1 TiB", name)
	}
	seed, err := randomHex(objectSeedSize)
	if err != nil {
		return false, err
	}
	if err := s.writeObjects(r, seed, size); err != nil {
		s.dropObjects(seed, size)
		return false, err
	}
	rec := &record{
		Name: name, Seed: seed, Size: size, Mode: uint32(mode.Perm()),
		Modified: mtime.UTC(), Added: time.Now().UTC(),
	}
	if err := s.writeRecord(rec); err != nil {
		s.dropObjects(seed, size)
		return false, err
	}
	replaced := len(cat[name]) > 0
	if err := s.remove(cat, name, true); err != nil {
		return replaced, err
	}
	cat[name] = []*record{rec}
	return replaced, nil
}

// writeObjects reads size bytes from f into the objects derived from seed.
// Chunks are read in order but encrypted, written and synced by a few
// workers at once, so their fsyncs overlap instead of queueing.
func (s *store) writeObjects(f io.Reader, seed string, size int64) error {
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		firstErr error
	)
	fail := func(err error) {
		mu.Lock()
		defer mu.Unlock()
		if firstErr == nil {
			firstErr = err
		}
	}
	failed := func() bool {
		mu.Lock()
		defer mu.Unlock()
		return firstErr != nil
	}
	slots := make(chan struct{}, 8) // at most 8 chunks, 32 MiB, in memory
	remaining := size
	for i := range objectCount(size) {
		if failed() {
			break
		}
		// The object ID leads the plaintext so a record can only ever
		// open the objects it derives, each in its place, not one
		// swapped in under its ID.
		id := objectID(seed, i)
		part := min(remaining, chunkData)
		remaining -= part
		slots <- struct{}{}
		buf := make([]byte, idSize+part)
		hex.Decode(buf, []byte(id))
		if _, err := io.ReadFull(f, buf[idSize:]); err != nil {
			<-slots
			fail(err)
			break
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
			err := s.writeCiphertext(objectsDir, id, func(w io.Writer) error {
				if _, err := w.Write(buf); err != nil {
					return err
				}
				_, err := io.CopyN(w, rand.Reader, paddedSize(int64(len(buf)))-int64(len(buf)))
				return err
			})
			if err != nil {
				fail(err)
			}
		}()
	}
	wg.Wait()
	return firstErr
}

// remove deletes every record for name and, when dropObjects is set, any of
// their objects no other record still uses. Records go first, so an
// interruption only ever leaves an orphaned object.
func (s *store) remove(cat map[string][]*record, name string, dropObjects bool) error {
	inUse := map[string]bool{}
	for n, rs := range cat {
		for _, r := range rs {
			if n != name {
				inUse[r.Seed] = true
			}
		}
	}
	for _, r := range cat[name] {
		if err := s.removeFile(recordsDir, r.id); err != nil {
			return err
		}
		if dropObjects && !inUse[r.Seed] {
			if err := s.dropObjects(r.Seed, r.Size); err != nil {
				return err
			}
		}
	}
	return nil
}

// dropObjects deletes the objects holding a file of size bytes, skipping any
// already gone.
func (s *store) dropObjects(seed string, size int64) error {
	for i := range objectCount(size) {
		if err := s.removeFile(objectsDir, objectID(seed, i)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func (s *store) lookup(name string) (map[string][]*record, *record, error) {
	cat, err := s.catalogue()
	if err != nil {
		return nil, nil, err
	}
	rs := cat[name]
	if len(rs) == 0 {
		return nil, nil, fmt.Errorf("%s: not in the vault", name)
	}
	return cat, rs[0], nil
}

func (s *store) delete(name string) error {
	cat, _, err := s.lookup(name)
	if err != nil {
		return err
	}
	return s.removeAll(cat, []string{name}, func(string) {})
}

// under returns the names in cat at or beneath the folder prefix, sorted.
func under(cat map[string][]*record, prefix string) []string {
	var names []string
	for name := range cat {
		if name == prefix || strings.HasPrefix(name, prefix+"/") {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// removeAll deletes every record for names and the objects they hold, then
// drops them from cat, calling done after each name. Like remove, but it
// works out once which objects other records still use, so deleting a large
// folder stays linear.
func (s *store) removeAll(cat map[string][]*record, names []string, done func(name string)) error {
	gone := map[string]bool{}
	for _, name := range names {
		gone[name] = true
	}
	inUse := map[string]bool{}
	for name, rs := range cat {
		if !gone[name] {
			for _, r := range rs {
				inUse[r.Seed] = true
			}
		}
	}
	for _, name := range names {
		for _, r := range cat[name] {
			if err := s.removeFile(recordsDir, r.id); err != nil {
				return err
			}
			if !inUse[r.Seed] {
				if err := s.dropObjects(r.Seed, r.Size); err != nil {
					return err
				}
			}
		}
		delete(cat, name)
		done(name)
	}
	return nil
}

func (s *store) rename(oldName, newName string) error {
	if !validName(newName) {
		return fmt.Errorf("invalid vault path %q", newName)
	}
	cat, r, err := s.lookup(oldName)
	if err != nil {
		return err
	}
	if len(cat[newName]) > 0 {
		return fmt.Errorf("%s already exists", newName)
	}
	moved := *r
	moved.Name = newName
	if err := s.writeRecord(&moved); err != nil {
		return err
	}
	return s.remove(cat, oldName, false)
}

// get decrypts name to out. Nothing appears at out until every object,
// padding included, has authenticated.
func (s *store) get(name, out string) error {
	_, r, err := s.lookup(name)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(out); err == nil {
		return fmt.Errorf("%s already exists", out)
	}
	tmp, err := os.CreateTemp(filepath.Dir(out), ".vault-get-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	remaining := r.Size
	for i := range objectCount(r.Size) {
		part := min(remaining, chunkData)
		if err := s.readObject(tmp, objectID(r.Seed, i), part); err != nil {
			return err
		}
		remaining -= part
	}
	if err := tmp.Chmod(os.FileMode(r.Mode) & 0o777); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chtimes(tmp.Name(), r.Modified, r.Modified); err != nil {
		return err
	}
	if _, err := os.Lstat(out); err == nil {
		return fmt.Errorf("%s already exists", out)
	}
	return os.Rename(tmp.Name(), out)
}

// readObject decrypts object id to w, checking it leads with its own ID and
// holds part bytes padded to their bucket.
func (s *store) readObject(w io.Writer, id string, part int64) error {
	f, err := os.Open(s.path(objectsDir, id))
	if err != nil {
		return err
	}
	defer f.Close()
	pr, err := pqcrypt.Decrypt(f, s.id)
	if err != nil {
		return err
	}
	head := make([]byte, idSize)
	if _, err := io.ReadFull(pr, head); err != nil || hex.EncodeToString(head) != id {
		return errors.New("object does not match its catalogue record")
	}
	if _, err := io.CopyN(w, pr, part); err != nil {
		return err
	}
	pad, err := io.Copy(io.Discard, pr)
	if err != nil {
		return err
	}
	if idSize+part+pad != paddedSize(idSize+part) {
		return errors.New("object size does not match its catalogue record")
	}
	return nil
}
