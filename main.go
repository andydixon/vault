// Copyright 2026 The vault Authors.
// SPDX-License-Identifier: GPL-3.0-or-later

// vault is a post-quantum encrypted file vault.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/andydixon/vault/internal/term"
)

const usage = `Usage:
    vault genkey                    create a new passphrase-protected key
    vault init [--filler SIZE]      create a new, empty vault, with at least
                                    SIZE of filler (e.g. 500M, 2G)
    vault add FILE|DIR|URL [FOLDER] encrypt a file, a directory (recursively)
                                    or a downloaded URL into the vault,
                                    optionally under a folder inside the vault
    vault migrate FILE|DIR [FOLDER] like add, then delete each original once
    [--yes]                         it is stored; asks before overwriting
                                    anything already in the vault, unless
                                    --yes is given
    vault mirror URL [FOLDER]       crawl a website (same host only, one request
                                    at a time) into FOLDER/HOST, rewriting its
                                    links to relative paths
    vault absorb [FOLDER]           read a tar archive (optionally gzipped) from
                                    standard input and add every file in it,
                                    optionally under a folder inside the vault
    vault list [PREFIX]             list stored files
    vault get NAME [-o OUTPUT]      decrypt a stored file (default: its base name)
    vault mv OLD NEW                rename a stored file
    vault rm NAME                   delete a stored file

Options (any command):
    --key PATH     key file (default $VAULT_KEY, else ~/.vault/key)
    --vault DIR    vault directory (default $VAULT_DIR, else ~/.vault/store)

The passphrase is read from the terminal, or from $VAULT_PASSPHRASE.

Decoy passphrase: genkey offers a second, optional passphrase
($VAULT_DECOY_PASSPHRASE when scripted). It unlocks a separate key, so
every command run with it sees and changes only the decoy files, and the
real files stay invisible. The key file does not reveal whether a decoy
exists, and init fills each vault with unreadable filler, so hidden
files look like filler to anyone holding only the decoy passphrase.`

const (
	passphraseEnv = "VAULT_PASSPHRASE"
	decoyEnv      = "VAULT_DECOY_PASSPHRASE"
)

// unlock releases the vault lock taken by open. fail calls it too, because
// os.Exit skips deferred calls.
var unlock = func() {}

func main() {
	defer func() { unlock() }()
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	fset := flag.NewFlagSet("vault "+cmd, flag.ContinueOnError)
	fset.SetOutput(io.Discard)
	keyPath := fset.String("key", defaultPath("VAULT_KEY", "key"), "")
	vaultDir := fset.String("vault", defaultPath("VAULT_DIR", "store"), "")
	output := fset.String("o", "", "")
	filler := fset.String("filler", "0", "")
	yes := fset.Bool("yes", false, "")
	pos, err := parseInterleaved(fset, args)
	if err != nil {
		fail("%v\n\n%s", err, usage)
	}
	want := func(min, max int) {
		if len(pos) < min || len(pos) > max {
			fail("wrong number of arguments for %s\n\n%s", cmd, usage)
		}
	}

	switch cmd {
	case "genkey":
		want(0, 0)
		if _, err := os.Stat(*keyPath); err == nil {
			fail("%s already exists", *keyPath)
		}
		pass := newPassphrase("passphrase")
		decoy := decoyPassphrase()
		if decoy == pass {
			fail("decoy passphrase must differ from the passphrase")
		}
		check(writeKeyFile(*keyPath, pass, decoy))
		fmt.Fprintf(os.Stderr, "key written to %s\n", *keyPath)
	case "init":
		want(0, 0)
		size, err := parseSize(*filler)
		check(err)
		check(initStore(*vaultDir, size))
		fmt.Fprintf(os.Stderr, "vault created at %s\n", *vaultDir)
	case "add", "migrate":
		want(1, 2)
		dest := ""
		if len(pos) == 2 {
			dest = strings.Trim(pos[1], "/")
		}
		s := open(*keyPath, *vaultDir, true)
		cat, err := s.catalogue()
		check(err)
		if isURL(pos[0]) {
			if cmd == "migrate" {
				fail("cannot migrate a URL; use add")
			}
			check(addURL(s, cat, pos[0], dest))
			break
		}
		// Never ingest, or delete, the vault or its key.
		var skip []os.FileInfo
		for _, p := range []string{*vaultDir, *keyPath} {
			if fi, err := os.Stat(p); err == nil {
				skip = append(skip, fi)
			}
		}
		overwrite := confirmOverwrite
		if *yes {
			overwrite = func([]string) bool { return true }
		}
		check(addPath(s, cat, pos[0], dest, cmd == "migrate", skip, overwrite))
	case "mirror":
		want(1, 2)
		if !isURL(pos[0]) {
			fail("mirror needs an http:// or https:// URL")
		}
		dest := ""
		if len(pos) == 2 {
			dest = strings.Trim(pos[1], "/")
		}
		s := open(*keyPath, *vaultDir, true)
		cat, err := s.catalogue()
		check(err)
		check(mirror(s, cat, pos[0], dest))
	case "absorb":
		want(0, 1)
		if fi, err := os.Stdin.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
			fail("absorb reads a tar archive from standard input; pipe one in")
		}
		dest := ""
		if len(pos) == 1 {
			dest = strings.Trim(pos[0], "/")
		}
		// Wait for the archive to start arriving before asking for the
		// passphrase, so a program feeding the pipe (gpg, ssh) has finished
		// with the terminal and cannot bury the prompt.
		in := bufio.NewReader(os.Stdin)
		if _, err := in.Peek(1); err != nil {
			fail("nothing to absorb on standard input")
		}
		s := open(*keyPath, *vaultDir, true)
		cat, err := s.catalogue()
		check(err)
		check(absorb(s, cat, in, dest))
	case "list", "ls":
		want(0, 1)
		prefix := ""
		if len(pos) == 1 {
			prefix = strings.Trim(pos[0], "/")
		}
		cat, err := open(*keyPath, *vaultDir, false).catalogue()
		check(err)
		list(cat, prefix)
	case "get":
		want(1, 1)
		out := *output
		if out == "" {
			out = path.Base(pos[0])
		}
		check(open(*keyPath, *vaultDir, false).get(pos[0], out))
	case "mv", "rename":
		want(2, 2)
		check(open(*keyPath, *vaultDir, true).rename(pos[0], pos[1]))
	case "rm", "delete":
		want(1, 1)
		check(open(*keyPath, *vaultDir, true).delete(pos[0]))
	case "help", "-h", "--help":
		fmt.Println(usage)
	default:
		fail("unknown command %q\n\n%s", cmd, usage)
	}
}

// parseInterleaved lets flags appear before, between or after positional
// arguments.
func parseInterleaved(fset *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fset.Parse(args); err != nil {
			return nil, err
		}
		if fset.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fset.Arg(0))
		args = fset.Args()[1:]
	}
}

// parseSize reads a byte count with an optional K, M, G or T suffix, in
// powers of 1024.
func parseSize(s string) (int64, error) {
	num, shift := strings.TrimSuffix(strings.ToUpper(s), "B"), 0
	for i, unit := range "KMGT" {
		if strings.HasSuffix(num, string(unit)) {
			num, shift = strings.TrimSuffix(num, string(unit)), 10*(i+1)
		}
	}
	n, err := strconv.ParseInt(num, 10, 64)
	if err != nil || n < 0 || n > fileLimit>>shift {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	return n << shift, nil
}

func defaultPath(env, name string) string {
	if v := os.Getenv(env); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		fail("cannot find home directory; set %s", env)
	}
	return filepath.Join(home, ".vault", name)
}

// open unlocks the key and opens the vault, holding the vault lock
// exclusively for writers and shared for readers.
func open(keyPath, vaultDir string, exclusive bool) *store {
	pass, err := term.ReadPassphrase("Enter passphrase:", passphraseEnv)
	check(err)
	id, err := unlockKeyFile(keyPath, pass)
	check(err)
	s, err := openStore(vaultDir, id)
	check(err)
	unlock, err = lockVault(vaultDir, exclusive)
	check(err)
	return s
}

func newPassphrase(what string) string {
	if p, ok := os.LookupEnv(passphraseEnv); ok && p != "" {
		return p
	}
	p, err := term.ReadPassphrase("Enter "+what+":", passphraseEnv)
	check(err)
	if p == "" {
		fail("%s must not be empty", what)
	}
	again, err := term.ReadPassphrase("Confirm "+what+":", passphraseEnv)
	check(err)
	if p != again {
		fail("%ss do not match", what)
	}
	return p
}

// decoyPassphrase asks for an optional second passphrase. Empty means none.
func decoyPassphrase() string {
	if p, ok := os.LookupEnv(decoyEnv); ok {
		return p
	}
	if _, ok := os.LookupEnv(passphraseEnv); ok {
		return "" // non-interactive run without a decoy
	}
	p, err := term.ReadSecret("Enter decoy passphrase (empty for none):")
	check(err)
	if len(p) == 0 {
		return ""
	}
	again, err := term.ReadSecret("Confirm decoy passphrase:")
	check(err)
	if string(p) != string(again) {
		fail("decoy passphrases do not match")
	}
	return string(p)
}

// addPath adds a file, or every regular file under a directory, beneath dest,
// keeping the directory structure. A directory named "." or ".." adds its
// contents directly beneath dest. With migrate, each original is deleted
// once stored, then any directories left empty, and nothing is stored
// unless overwrite approves the vault names it would replace, if any.
func addPath(s *store, cat map[string][]*record, src, dest string, migrate bool, skip []os.FileInfo, overwrite func([]string) bool) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	base := filepath.Base(filepath.Clean(src))
	if base == "." || base == ".." || base == string(filepath.Separator) {
		base = ""
	}
	skipped := func(fi os.FileInfo) bool {
		for _, s := range skip {
			if os.SameFile(fi, s) {
				return true
			}
		}
		return false
	}
	if skipped(info) {
		return fmt.Errorf("%s is the vault or its key", src)
	}
	type item struct{ src, name string }
	var items []item
	var dirs []string
	if !info.IsDir() {
		items = append(items, item{src, path.Join(dest, filepath.Base(src))})
	} else {
		err = filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if fi, err := d.Info(); err == nil && skipped(fi) {
				fmt.Fprintf(os.Stderr, "skipping %s: the vault or its key\n", p)
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				dirs = append(dirs, p)
				return nil
			}
			if !d.Type().IsRegular() {
				fmt.Fprintf(os.Stderr, "skipping %s: not a regular file\n", p)
				return nil
			}
			rel, err := filepath.Rel(src, p)
			if err != nil {
				return err
			}
			items = append(items, item{p, path.Join(dest, base, filepath.ToSlash(rel))})
			return nil
		})
		if err != nil {
			return err
		}
	}
	if migrate {
		var existing []string
		for _, it := range items {
			if len(cat[it.name]) > 0 {
				existing = append(existing, it.name)
			}
		}
		if len(existing) > 0 && !overwrite(existing) {
			return errors.New("migrate cancelled; nothing changed")
		}
	}
	for _, it := range items {
		if err := addOne(s, cat, it.src, it.name, migrate); err != nil {
			return err
		}
	}
	if migrate {
		// Children come after their parents in walk order, so go backwards.
		// Directories still holding skipped files stay.
		for i := len(dirs) - 1; i >= 0; i-- {
			os.Remove(dirs[i])
		}
	}
	return nil
}

// confirmOverwrite lists the vault names a migrate would replace and asks
// on the terminal whether to go ahead. No terminal means no.
func confirmOverwrite(names []string) bool {
	fmt.Fprintln(os.Stderr, "these files are already in the vault and would be overwritten:")
	for _, name := range names {
		fmt.Fprintf(os.Stderr, "    %s\n", name)
	}
	ok, err := term.Confirm(fmt.Sprintf("overwrite %d file(s)? [y/N]", len(names)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot ask for confirmation: %v\n", err)
	}
	return ok
}

func isURL(s string) bool {
	return strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "http://")
}

const chromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"

// addURL downloads rawURL to a private temporary file and adds it beneath
// dest, named after the last element of the final (post-redirect) URL path.
func addURL(s *store, cat map[string][]*record, rawURL, dest string) error {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", chromeUA)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", rawURL, resp.Status)
	}
	name := path.Base(resp.Request.URL.Path)
	if name == "/" || name == "." {
		name = resp.Request.URL.Hostname()
	}
	tmp, err := os.CreateTemp("", "vault-download-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	if _, err := io.Copy(tmp, resp.Body); err != nil {
		return fmt.Errorf("%s: %w", rawURL, err)
	}
	if t, err := http.ParseTime(resp.Header.Get("Last-Modified")); err == nil {
		os.Chtimes(tmp.Name(), t, t)
	}
	return addOne(s, cat, tmp.Name(), path.Join(dest, name), false)
}

func addOne(s *store, cat map[string][]*record, src, name string, migrate bool) error {
	replaced, err := s.add(cat, src, name)
	if err != nil {
		return err
	}
	verb := "added"
	if replaced {
		verb = "replaced"
	}
	if migrate {
		if err := os.Remove(src); err != nil {
			return err
		}
		verb = "migrated"
	}
	fmt.Fprintf(os.Stderr, "%s %s\n", verb, name)
	return nil
}

func list(cat map[string][]*record, prefix string) {
	var names []string
	for name := range cat {
		if prefix == "" || name == prefix || strings.HasPrefix(name, prefix+"/") {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		r := cat[name][0]
		fmt.Printf("%10s  %s  %s\n", humanSize(r.Size), r.Modified.Local().Format("2006-01-02 15:04"), name)
	}
}

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func check(err error) {
	if err != nil {
		fail("%v", err)
	}
}

func fail(format string, args ...any) {
	unlock()
	fmt.Fprintf(os.Stderr, "vault: "+format+"\n", args...)
	os.Exit(1)
}
