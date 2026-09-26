// Copyright 2026 The vault Authors.
// SPDX-License-Identifier: GPL-3.0-or-later

// vault is a post-quantum encrypted file vault.
package main

import (
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/andydixon/vault/internal/term"
)

const usage = `Usage:
    vault genkey                    create a new passphrase-protected key
    vault init                      create a new, empty vault
    vault add FILE|DIR [FOLDER]     encrypt a file or directory into the vault,
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

func main() {
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
		check(initStore(*vaultDir))
		fmt.Fprintf(os.Stderr, "vault created at %s\n", *vaultDir)
	case "add":
		want(1, 2)
		dest := ""
		if len(pos) == 2 {
			dest = strings.Trim(pos[1], "/")
		}
		s := open(*keyPath, *vaultDir)
		cat, err := s.catalogue()
		check(err)
		check(addPath(s, cat, pos[0], dest))
	case "list", "ls":
		want(0, 1)
		prefix := ""
		if len(pos) == 1 {
			prefix = strings.Trim(pos[0], "/")
		}
		cat, err := open(*keyPath, *vaultDir).catalogue()
		check(err)
		list(cat, prefix)
	case "get":
		want(1, 1)
		out := *output
		if out == "" {
			out = path.Base(pos[0])
		}
		check(open(*keyPath, *vaultDir).get(pos[0], out))
	case "mv", "rename":
		want(2, 2)
		check(open(*keyPath, *vaultDir).rename(pos[0], pos[1]))
	case "rm", "delete":
		want(1, 1)
		check(open(*keyPath, *vaultDir).delete(pos[0]))
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

func open(keyPath, vaultDir string) *store {
	pass, err := term.ReadPassphrase("Enter passphrase:", passphraseEnv)
	check(err)
	id, err := unlockKeyFile(keyPath, pass)
	check(err)
	s, err := openStore(vaultDir, id)
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

// addPath adds a file, or every regular file under a directory, beneath dest.
func addPath(s *store, cat map[string][]*record, src, dest string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	base := filepath.Base(filepath.Clean(src))
	if !info.IsDir() {
		return addOne(s, cat, src, path.Join(dest, base))
	}
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if !d.Type().IsRegular() {
			fmt.Fprintf(os.Stderr, "skipping %s: not a regular file\n", p)
			return nil
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		return addOne(s, cat, p, path.Join(dest, base, filepath.ToSlash(rel)))
	})
}

func addOne(s *store, cat map[string][]*record, src, name string) error {
	replaced, err := s.add(cat, src, name)
	if err != nil {
		return err
	}
	verb := "added"
	if replaced {
		verb = "replaced"
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
	fmt.Fprintf(os.Stderr, "vault: "+format+"\n", args...)
	os.Exit(1)
}
