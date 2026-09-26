// Copyright 2026 The vault Authors.
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/andydixon/vault/internal/pqcrypt"
)

// On disk a vault is:
//
//	DIR/.vault            marker
//	DIR/records/<id>      one encrypted catalogue record per file
//	DIR/objects/<id>      one encrypted file body per record
//
// IDs are random. Records are padded to one fixed size and objects to
// power-of-two buckets, so the storage reveals neither names, exact sizes nor
// timestamps. Every ciphertext's mtime is pinned to the epoch.

const (
	markerName    = ".vault"
	markerContent = "VAULT 1\n"
	recordsDir    = "records"
	objectsDir    = "objects"
	recordSize    = 4096
	nameLimit     = 1024
	fileLimit     = int64(1) << 40
	minPadding    = int64(64 << 10)
	idSize        = 16
)

type record struct {
	Name     string    `json:"name"`
	Object   string    `json:"object"`
	Size     int64     `json:"size"`
	Mode     uint32    `json:"mode"`
	Modified time.Time `json:"modified"`
	Added    time.Time `json:"added"`

	id string // record file ID; not stored
}

type store struct {
	root string
	id   *pqcrypt.PQIdentity
}

func initStore(root string) error {
	if _, err := os.Stat(filepath.Join(root, markerName)); err == nil {
		return fmt.Errorf("%s is already a vault", root)
	}
	for _, dir := range []string{root, filepath.Join(root, recordsDir), filepath.Join(root, objectsDir)} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	return os.WriteFile(filepath.Join(root, markerName), []byte(markerContent), 0o600)
}

func openStore(root string, id *pqcrypt.PQIdentity) (*store, error) {
	marker, err := os.ReadFile(filepath.Join(root, markerName))
	if err != nil || string(marker) != markerContent {
		return nil, fmt.Errorf("%s is not a vault; run vault init", root)
	}
	return &store{root: root, id: id}, nil
}

func randomID() (string, error) {
	b := make([]byte, idSize)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func validID(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == idSize && hex.EncodeToString(b) == s
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
	dir = filepath.Join(s.root, dir)
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
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	epoch := time.Unix(0, 0)
	if err := os.Chtimes(tmp.Name(), epoch, epoch); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), filepath.Join(dir, id)); err != nil {
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
	if r.id, err = randomID(); err != nil {
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
	entries, err := os.ReadDir(filepath.Join(s.root, recordsDir))
	if err != nil {
		return nil, err
	}
	byName := map[string][]*record{}
	for _, e := range entries {
		if !validID(e.Name()) {
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
	// Newest first, so [0] is current. Duplicates only exist after an
	// interrupted replace; the next write of that name cleans them up.
	for _, rs := range byName {
		sort.Slice(rs, func(i, j int) bool { return rs[i].Added.After(rs[j].Added) })
	}
	return byName, nil
}

func (s *store) readRecord(id string) (*record, error) {
	f, err := os.Open(filepath.Join(s.root, recordsDir, id))
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
	if !validName(r.Name) || !validID(r.Object) || r.Size < 0 || r.Size > fileLimit {
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
	objID, err := randomID()
	if err != nil {
		return false, err
	}
	err = s.writeCiphertext(objectsDir, objID, func(w io.Writer) error {
		// The object ID leads the plaintext so a record can only ever
		// open the object it names, not one swapped in under its ID.
		raw, _ := hex.DecodeString(objID)
		if _, err := w.Write(raw); err != nil {
			return err
		}
		n, err := io.Copy(w, io.LimitReader(f, info.Size()))
		if err != nil {
			return err
		}
		if n != info.Size() {
			return fmt.Errorf("%s changed while being added", src)
		}
		_, err = io.CopyN(w, rand.Reader, paddedSize(idSize+n)-idSize-n)
		return err
	})
	if err != nil {
		return false, err
	}
	r := &record{
		Name: name, Object: objID, Size: info.Size(), Mode: uint32(info.Mode().Perm()),
		Modified: info.ModTime().UTC(), Added: time.Now().UTC(),
	}
	if err := s.writeRecord(r); err != nil {
		os.Remove(filepath.Join(s.root, objectsDir, objID))
		return false, err
	}
	replaced := len(cat[name]) > 0
	if err := s.remove(cat, name, true); err != nil {
		return replaced, err
	}
	cat[name] = []*record{r}
	return replaced, nil
}

// remove deletes every record for name and, when dropObjects is set, any of
// their objects no other record still uses. Records go first, so an
// interruption only ever leaves an orphaned object.
func (s *store) remove(cat map[string][]*record, name string, dropObjects bool) error {
	inUse := map[string]bool{}
	for n, rs := range cat {
		for _, r := range rs {
			if n != name {
				inUse[r.Object] = true
			}
		}
	}
	for _, r := range cat[name] {
		if err := os.Remove(filepath.Join(s.root, recordsDir, r.id)); err != nil {
			return err
		}
		if dropObjects && !inUse[r.Object] {
			if err := os.Remove(filepath.Join(s.root, objectsDir, r.Object)); err != nil && !os.IsNotExist(err) {
				return err
			}
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
	return s.remove(cat, name, true)
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

// get decrypts name to out. Nothing appears at out until the entire object,
// padding included, has authenticated.
func (s *store) get(name, out string) error {
	_, r, err := s.lookup(name)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(out); err == nil {
		return fmt.Errorf("%s already exists", out)
	}
	f, err := os.Open(filepath.Join(s.root, objectsDir, r.Object))
	if err != nil {
		return err
	}
	defer f.Close()
	pr, err := pqcrypt.Decrypt(f, s.id)
	if err != nil {
		return err
	}
	head := make([]byte, idSize)
	if _, err := io.ReadFull(pr, head); err != nil || hex.EncodeToString(head) != r.Object {
		return errors.New("object does not match its catalogue record")
	}
	tmp, err := os.CreateTemp(filepath.Dir(out), ".vault-get-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	if _, err := io.CopyN(tmp, pr, r.Size); err != nil {
		return err
	}
	pad, err := io.Copy(io.Discard, pr)
	if err != nil {
		return err
	}
	if idSize+r.Size+pad != paddedSize(idSize+r.Size) {
		return errors.New("object size does not match its catalogue record")
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
