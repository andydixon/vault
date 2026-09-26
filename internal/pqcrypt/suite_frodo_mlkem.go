// Copyright 2026 The fury Authors.
// SPDX-License-Identifier: GPL-3.0-or-later

package pqcrypt

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/andydixon/vault/internal/format"
	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/frodo/frodo640shake"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"golang.org/x/crypto/hkdf"
)

// frodoMLKEM768 is the default post-quantum suite: a hybrid of FrodoKEM-640
// (unstructured-lattice) and ML-KEM-768 (module-lattice). The file key stays
// secret unless both KEMs are broken. It is pure Go, so fury keeps building as a
// static binary with no cgo. (A code-based suite such as HQC or Classic McEliece
// via liboqs can be registered later with a higher rank; see suite.go.)
type frodoMLKEM768 struct{}

func init() { registerSuite(frodoMLKEM768{}) }

func (frodoMLKEM768) id() uint16    { return 0x0001 }
func (frodoMLKEM768) tag() string   { return "frodo640shake+mlkem768" }
func (frodoMLKEM768) rank() int     { return 10 }
func (frodoMLKEM768) seedSize() int { return 32 }

func (frodoMLKEM768) schemes() (frodo, ml kem.Scheme) {
	return frodo640shake.Scheme(), mlkem768.Scheme()
}

func (s frodoMLKEM768) publicKeySize() int {
	frodo, ml := s.schemes()
	return frodo.PublicKeySize() + ml.PublicKeySize()
}

// deriveKeypair expands a 32-byte master seed into per-KEM seeds via HKDF, then
// derives each keypair deterministically. The public key is frodoPub||mlkemPub
// and the private key is frodoPriv||mlkemPriv.
func (s frodoMLKEM768) deriveKeypair(seed []byte) (pub, priv []byte, err error) {
	frodo, ml := s.schemes()
	r := hkdf.New(sha256.New, seed, nil, []byte("fury/v1 seed-expand "+s.tag()))
	frodoSeed := make([]byte, frodo.SeedSize())
	mlSeed := make([]byte, ml.SeedSize())
	// The per-KEM seeds regenerate the private keys, so they are as sensitive
	// as the master seed and are cleared as soon as the keys are derived.
	defer wipe(frodoSeed)
	defer wipe(mlSeed)
	if _, err := io.ReadFull(r, frodoSeed); err != nil {
		return nil, nil, err
	}
	if _, err := io.ReadFull(r, mlSeed); err != nil {
		return nil, nil, err
	}

	fpk, fsk := frodo.DeriveKeyPair(frodoSeed)
	mpk, msk := ml.DeriveKeyPair(mlSeed)

	fpkb, err := fpk.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	mpkb, err := mpk.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	fskb, err := fsk.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	defer wipe(fskb)
	mskb, err := msk.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	defer wipe(mskb)
	// fpkb and mpkb are public key bytes; wiping them would be theatre.
	return slices.Concat(fpkb, mpkb), slices.Concat(fskb, mskb), nil
}

// wrap encapsulates to both KEMs and seals the file key under the combined
// KEK.
//
// INVARIANT (fresh encapsulation). Both Encapsulate calls draw fresh
// randomness on every invocation. Wrapping the same file key to the same
// recipient twice therefore produces two independent KEKs, never a repeat.
func (s frodoMLKEM768) wrap(pub, fileKey []byte) ([]*Stanza, error) {
	frodo, ml := s.schemes()
	if len(pub) != s.publicKeySize() {
		return nil, fmt.Errorf("invalid %s public key size", s.tag())
	}
	fpk, err := frodo.UnmarshalBinaryPublicKey(pub[:frodo.PublicKeySize()])
	if err != nil {
		return nil, fmt.Errorf("invalid FrodoKEM public key: %v", err)
	}
	mpk, err := ml.UnmarshalBinaryPublicKey(pub[frodo.PublicKeySize():])
	if err != nil {
		return nil, fmt.Errorf("invalid ML-KEM public key: %v", err)
	}

	ct1, ss1, err := frodo.Encapsulate(fpk)
	if err != nil {
		return nil, fmt.Errorf("FrodoKEM encapsulation failed: %v", err)
	}
	ct2, ss2, err := ml.Encapsulate(mpk)
	if err != nil {
		return nil, fmt.Errorf("ML-KEM encapsulation failed: %v", err)
	}

	kek := s.deriveKEK(ss1, ss2, ct1, ct2)
	defer wipe(ss1)
	defer wipe(ss2)
	defer wipe(kek)
	body, err := aeadEncrypt(kek, fileKey)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap file key: %v", err)
	}

	return []*Stanza{{
		Type: s.tag(),
		Args: []string{format.EncodeToString(ct1), format.EncodeToString(ct2)},
		Body: body,
	}}, nil
}

func (s frodoMLKEM768) unwrap(priv []byte, st *Stanza) ([]byte, error) {
	frodo, ml := s.schemes()
	if st.Type != s.tag() {
		return nil, ErrIncorrectIdentity
	}
	if len(st.Args) != 2 {
		return nil, fmt.Errorf("invalid %s stanza: expected 2 arguments", s.tag())
	}
	ct1, err := format.DecodeString(st.Args[0])
	if err != nil {
		return nil, fmt.Errorf("invalid FrodoKEM ciphertext: %v", err)
	}
	ct2, err := format.DecodeString(st.Args[1])
	if err != nil {
		return nil, fmt.Errorf("invalid ML-KEM ciphertext: %v", err)
	}
	if len(ct1) != frodo.CiphertextSize() || len(ct2) != ml.CiphertextSize() {
		return nil, errIncorrectCiphertextSize
	}
	if len(priv) != frodo.PrivateKeySize()+ml.PrivateKeySize() {
		return nil, errors.New("invalid private key size")
	}

	fsk, err := frodo.UnmarshalBinaryPrivateKey(priv[:frodo.PrivateKeySize()])
	if err != nil {
		return nil, fmt.Errorf("invalid FrodoKEM private key: %v", err)
	}
	// priv itself belongs to the caller's identity and is cleared by
	// PQIdentity.Close; the parsed key objects are owned by CIRCL and expose
	// no buffer Fury can clear.
	msk, err := ml.UnmarshalBinaryPrivateKey(priv[frodo.PrivateKeySize():])
	if err != nil {
		return nil, fmt.Errorf("invalid ML-KEM private key: %v", err)
	}

	ss1, err := frodo.Decapsulate(fsk, ct1)
	if err != nil {
		return nil, fmt.Errorf("FrodoKEM decapsulation failed: %v", err)
	}
	ss2, err := ml.Decapsulate(msk, ct2)
	if err != nil {
		return nil, fmt.Errorf("ML-KEM decapsulation failed: %v", err)
	}

	// Both KEMs use implicit rejection, so a mismatched key yields a wrong
	// shared secret rather than an error; detection happens here at aeadDecrypt.
	kek := s.deriveKEK(ss1, ss2, ct1, ct2)
	defer wipe(ss1)
	defer wipe(ss2)
	defer wipe(kek)
	fileKey, err := aeadDecrypt(kek, fileKeySize, st.Body)
	if err != nil {
		return nil, ErrIncorrectIdentity
	}
	return fileKey, nil
}

// deriveKEK combines the two KEM shared secrets and both ciphertexts into a
// 256-bit key-encryption key.
//
// INVARIANT (both secrets contribute). ss1 and ss2 are concatenated as the
// HKDF input keying material, so the KEK stays unpredictable unless both KEMs
// are broken for the same target. Dropping either would silently reduce the
// construction to a single KEM.
//
// INVARIANT (transcript binding). Both ciphertexts are bound into the HKDF
// info string, preventing a mix-and-match of encapsulations across the two
// KEMs: an attacker cannot pair ct1 from one stanza with ct2 from another and
// obtain a KEK either party would compute.
//
// INVARIANT (single use). Because both encapsulations are performed freshly
// for every wrap, the resulting KEK is unique to that wrap. That is what
// makes the fixed AEAD nonce in aeadEncrypt safe; see primitives.go.
func (s frodoMLKEM768) deriveKEK(ss1, ss2, ct1, ct2 []byte) []byte {
	secret := slices.Concat(ss1, ss2)
	defer wipe(secret)
	info := slices.Concat([]byte("fury/v1 kek "+s.tag()), ct1, ct2)
	r := hkdf.New(sha256.New, secret, nil, info)
	kek := make([]byte, 32)
	if _, err := io.ReadFull(r, kek); err != nil {
		panic("fury: internal error: failed to read from HKDF: " + err.Error())
	}
	return kek
}
