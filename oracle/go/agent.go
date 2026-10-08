// Copyright 2026 The vault Authors.
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/andydixon/vault/internal/pqcrypt"
	"github.com/andydixon/vault/internal/term"
)

// The agent remembers an unlocked key for a while, like ssh-agent, so
// commands skip the passphrase. `vault unlock` checks the passphrase, then
// starts a copy of itself (agentCmd) and hands it the suite ID and master
// seed over a pipe; it never touches the disk. The agent serves them on a
// Unix socket in a directory only this user can enter, keeps them in locked,
// undumpable memory where the platform allows, and wipes them and exits at
// a deadline, or on `vault lock`. The deadline is fixed, or with --idle it
// moves on each time a command uses the key.

const (
	agentCmd     = "__agent" // hidden: the agent process itself
	agentGet     = 'g'
	agentQuit    = 'q'
	agentReply   = 2 + seedSize
	agentTimeout = 2 * time.Second
)

// agentSocket is the socket of the agent for the key file at keyPath, one
// per key file, in a private per-user directory it creates if needed.
func agentSocket(keyPath string) (string, error) {
	abs, err := filepath.Abs(keyPath)
	if err != nil {
		return "", err
	}
	base := os.Getenv("XDG_RUNTIME_DIR")
	if base == "" {
		base = os.TempDir()
	}
	dir := filepath.Join(base, fmt.Sprintf("vault-%d", os.Getuid()))
	if err := os.Mkdir(dir, 0o700); err != nil && !os.IsExist(err) {
		return "", err
	}
	if err := privateDir(dir); err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(abs))
	return filepath.Join(dir, "agent-"+hex.EncodeToString(sum[:8])), nil
}

// agentDial connects to the agent for keyPath and sends it op.
func agentDial(keyPath string, op byte) (net.Conn, error) {
	sock, err := agentSocket(keyPath)
	if err != nil {
		return nil, err
	}
	c, err := net.DialTimeout("unix", sock, agentTimeout)
	if err != nil {
		return nil, err
	}
	c.SetDeadline(time.Now().Add(agentTimeout))
	if _, err := c.Write([]byte{op}); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// agentIdentity asks a running agent for the key at keyPath.
func agentIdentity(keyPath string) (*pqcrypt.PQIdentity, error) {
	c, err := agentDial(keyPath, agentGet)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	buf := make([]byte, agentReply)
	defer clear(buf)
	if _, err := io.ReadFull(c, buf); err != nil {
		return nil, err
	}
	return pqcrypt.NewPQIdentityFromSeed(binary.BigEndian.Uint16(buf), buf[2:])
}

// agentStop tells the agent for keyPath to forget its key, reporting
// whether one was running.
func agentStop(keyPath string) bool {
	c, err := agentDial(keyPath, agentQuit)
	if err != nil {
		return false
	}
	defer c.Close()
	io.Copy(io.Discard, c) // returns once the agent has wiped the key
	return true
}

// agentStart replaces any agent for keyPath with one holding id until ttl
// has passed, since it started or, with idle, since the key was last used.
func agentStart(keyPath string, id *pqcrypt.PQIdentity, ttl time.Duration, idle bool) error {
	sock, err := agentSocket(keyPath)
	if err != nil {
		return err
	}
	agentStop(keyPath)
	self, err := os.Executable()
	if err != nil {
		return err
	}
	mode := "fixed"
	if idle {
		mode = "idle"
	}
	cmd := exec.Command(self, agentCmd, sock, ttl.String(), mode)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	secret := binary.BigEndian.AppendUint16(make([]byte, 0, agentReply), id.SuiteID())
	seed := id.Seed()
	secret = append(secret, seed...)
	clear(seed)
	_, err = stdin.Write(secret)
	clear(secret)
	stdin.Close()
	// The agent closes its standard output once listening, after saying
	// "ok" or why not.
	msg, _ := io.ReadAll(stdout)
	if err != nil || string(msg) != "ok" {
		cmd.Process.Kill()
		cmd.Wait()
		if err == nil {
			err = fmt.Errorf("agent did not start: %s", strings.TrimSpace(string(msg)))
		}
		return err
	}
	return cmd.Process.Release()
}

// runAgent is the agent process: it reads the key from in, says "ok" or
// why not on out and closes it, then serves the key on sock until ttl has
// passed, since it started or with mode "idle" since the key was last
// handed out, or until it is told to quit.
func runAgent(sock, ttlArg, mode string, in io.Reader, out io.WriteCloser) {
	report := func(msg string) { io.WriteString(out, msg); out.Close() }
	ttl, err := time.ParseDuration(ttlArg)
	if err != nil || ttl <= 0 || mode != "fixed" && mode != "idle" {
		report("bad duration or mode")
		return
	}
	secret := make([]byte, agentReply)
	protectMemory(secret)
	if _, err := io.ReadFull(in, secret); err != nil {
		report("no key received")
		return
	}
	// A socket left by an agent that died stops Listen; agentStart has
	// already stopped any live one.
	os.Remove(sock)
	l, err := net.Listen("unix", sock)
	if err != nil {
		clear(secret)
		report(err.Error())
		return
	}
	os.Chmod(sock, 0o600)
	report("ok")
	expiry := time.AfterFunc(ttl, func() { l.Close() })
	for {
		c, err := l.Accept()
		if err != nil {
			break
		}
		op := serveAgent(c, secret)
		c.Close()
		if op == agentQuit {
			break
		}
		if op == agentGet && mode == "idle" {
			expiry.Reset(ttl)
		}
	}
	l.Close()
	clear(secret)
	os.Remove(sock)
}

// serveAgent answers one request and returns its operation.
func serveAgent(c net.Conn, secret []byte) byte {
	c.SetDeadline(time.Now().Add(agentTimeout))
	op := make([]byte, 1)
	if _, err := io.ReadFull(c, op); err != nil {
		return 0
	}
	switch op[0] {
	case agentGet:
		c.Write(secret)
	case agentQuit:
		clear(secret)
	}
	return op[0]
}

// keyIdentity unlocks the key at keyPath: from the agent if one is running
// and no passphrase is in the environment, else with the passphrase.
func keyIdentity(keyPath string) (*pqcrypt.PQIdentity, error) {
	if _, ok := os.LookupEnv(passphraseEnv); !ok {
		if id, err := agentIdentity(keyPath); err == nil {
			return id, nil
		}
	}
	pass, err := term.ReadPassphrase("Enter passphrase:", passphraseEnv)
	if err != nil {
		return nil, err
	}
	return unlockKeyFile(keyPath, pass)
}
