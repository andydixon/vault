// Copyright 2026 The vault Authors.
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
)

// absorb reads a tar archive, gzipped or not, from r and adds every regular
// file in it beneath dest, streaming each straight into the vault so no
// plaintext touches the disk. Other entries, and names that would escape
// dest, are reported and skipped.
func absorb(s *store, cat map[string][]*record, r io.Reader, dest string) error {
	br := bufio.NewReader(r)
	if magic, _ := br.Peek(2); bytes.Equal(magic, []byte{0x1f, 0x8b}) {
		zr, err := gzip.NewReader(br)
		if err != nil {
			return err
		}
		defer zr.Close()
		r = zr
	} else {
		r = br
	}
	tr := tar.NewReader(r)
	n := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading archive: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			if hdr.Typeflag != tar.TypeDir {
				fmt.Fprintf(os.Stderr, "skipping %s: not a regular file\n", hdr.Name)
			}
			continue
		}
		name := strings.TrimPrefix(path.Clean("/"+hdr.Name), "/")
		if strings.Contains(hdr.Name, "\\") || name == "" || name != path.Clean(strings.TrimPrefix(strings.TrimPrefix(hdr.Name, "./"), "/")) {
			fmt.Fprintf(os.Stderr, "skipping %s: unsafe name\n", hdr.Name)
			continue
		}
		name = path.Join(dest, name)
		replaced, err := s.addReader(cat, tr, hdr.Size, hdr.FileInfo().Mode(), hdr.ModTime, name)
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			err = fmt.Errorf("%s: archive ends early", hdr.Name)
		}
		if err != nil {
			return err
		}
		verb := "added"
		if replaced {
			verb = "replaced"
		}
		fmt.Fprintf(os.Stderr, "%s %s\n", verb, name)
		n++
	}
	if n == 0 {
		return errors.New("no files in archive")
	}
	return nil
}
