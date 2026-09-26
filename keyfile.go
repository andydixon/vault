// Copyright 2026 The vault Authors.
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"

	"github.com/andydixon/vault/internal/pqcrypt"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// A key file seals a (suite ID, master seed) pair under an Argon2id-derived
// key. The private seed never touches disk unencrypted.

const (
	keyPEMType    = "VAULT KEY"
	argonTime     = 3
	argonMemory   = 64 * 1024 // KiB
	argonThreads  = 4
	slotSaltSize  = 16
	seedSize      = 32
	slotPlainSize = 2 + seedSize
	slotSize      = slotSaltSize + chacha20poly1305.NonceSizeX + slotPlainSize + chacha20poly1305.Overhead
)

var keyMagic = []byte("VAULTKEY1")

// keyHeader is the authenticated, non-secret prefix of every key file.
func keyHeader() []byte {
	h := append([]byte(nil), keyMagic...)
	h = binary.BigEndian.AppendUint32(h, argonTime)
	h = binary.BigEndian.AppendUint32(h, argonMemory)
	return append(h, argonThreads)
}

// sealSlot encrypts the identity's seed under passphrase.
func sealSlot(id *pqcrypt.PQIdentity, passphrase string) ([]byte, error) {
	slot := make([]byte, slotSaltSize+chacha20poly1305.NonceSizeX, slotSize)
	if _, err := rand.Read(slot); err != nil {
		return nil, err
	}
	aead, err := slotAEAD(passphrase, slot[:slotSaltSize])
	if err != nil {
		return nil, err
	}
	plain := binary.BigEndian.AppendUint16(nil, id.SuiteID())
	seed := id.Seed()
	plain = append(plain, seed...)
	clear(seed)
	defer clear(plain)
	return aead.Seal(slot, slot[slotSaltSize:], plain, keyHeader()), nil
}

func slotAEAD(passphrase string, salt []byte) (interface {
	Seal(dst, nonce, plaintext, ad []byte) []byte
	Open(dst, nonce, ciphertext, ad []byte) ([]byte, error)
}, error) {
	key := argon2.IDKey([]byte(passphrase), salt, argonTime, argonMemory, argonThreads, chacha20poly1305.KeySize)
	defer clear(key)
	return chacha20poly1305.NewX(key)
}

// writeKeyFile creates a new key file holding a fresh identity.
func writeKeyFile(path, passphrase string) error {
	id, err := pqcrypt.GeneratePQIdentity()
	if err != nil {
		return err
	}
	slot, err := sealSlot(id, passphrase)
	id.Close()
	if err != nil {
		return err
	}
	body := append(keyHeader(), slot...)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err := pem.Encode(f, &pem.Block{Type: keyPEMType, Bytes: body}); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// unlockKeyFile returns the identity the passphrase unlocks.
func unlockKeyFile(path, passphrase string) (*pqcrypt.PQIdentity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	header := keyHeader()
	if block == nil || block.Type != keyPEMType || len(bytes.TrimSpace(rest)) != 0 ||
		len(block.Bytes) != len(header)+slotSize || !bytes.Equal(block.Bytes[:len(header)], header) {
		return nil, errors.New("not a vault key file")
	}
	slot := block.Bytes[len(header):]
	aead, err := slotAEAD(passphrase, slot[:slotSaltSize])
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, slot[slotSaltSize:][:chacha20poly1305.NonceSizeX],
		slot[slotSaltSize+chacha20poly1305.NonceSizeX:], header)
	if err != nil {
		return nil, errors.New("incorrect passphrase")
	}
	defer clear(plain)
	return pqcrypt.NewPQIdentityFromSeed(binary.BigEndian.Uint16(plain), plain[2:])
}
