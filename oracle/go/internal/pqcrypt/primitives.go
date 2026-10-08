// SPDX-License-Identifier: GPL-3.0-or-later

package pqcrypt

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"io"

	"github.com/andydixon/vault/internal/format"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// aeadEncrypt encrypts a message with a one-time key.
//
// INVARIANT (fixed nonce). The all-zero nonce below is safe only because
// every key reaching this function is a fresh, unique, single-use derived
// KEK. It is not a shortcut and must not be reused anywhere that condition
// does not hold: repeating a (key, nonce) pair under ChaCha20-Poly1305
// destroys both confidentiality and authenticity.
//
// The condition holds today because aeadEncrypt has exactly one caller, the
// default suite's wrap, whose KEK is
// HKDF-SHA-256(ss1 || ss2, info = label || ct1 || ct2). Both KEM
// encapsulations are performed freshly for each wrap, so ss1, ss2, ct1 and
// ct2 differ for every call even when the same file key is wrapped to the
// same recipient twice. Any new caller must establish the same property, or
// carry its own nonce.
//
// For the code that encrypts the actual payload, which uses a counter nonce
// rather than a fixed one, see the
// github.com/andydixon/vault/internal/stream package.
func aeadEncrypt(key, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	return aead.Seal(nil, nonce, plaintext, nil), nil
}

var errIncorrectCiphertextSize = errors.New("encrypted value has unexpected length")

// aeadDecrypt decrypts a message of an expected fixed size.
//
// The message size is limited to mitigate multi-key attacks, where a ciphertext
// can be crafted that decrypts successfully under multiple keys. Short
// ciphertexts can only target two keys, which has limited impact.
func aeadDecrypt(key []byte, size int, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) != size+aead.Overhead() {
		return nil, errIncorrectCiphertextSize
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	return aead.Open(nil, nonce, ciphertext, nil)
}

// headerMAC computes the header authentication tag.
//
// INVARIANT (header authentication). The MAC covers the complete header
// except the MAC line itself: the intro line, every recipient stanza in
// order, and the footer prefix. Nothing that a decryptor acts upon is left
// unauthenticated, so a stanza cannot be added, removed, reordered or edited
// without detection by anyone who can recover the file key.
//
// INVARIANT (domain separation). The MAC key and the payload key are both
// HKDF-SHA-256 expansions of the same file key under distinct info strings
// ("header" and "payload"), so neither can be substituted for the other.
func headerMAC(fileKey []byte, hdr *format.Header) ([]byte, error) {
	h := hkdf.New(sha256.New, fileKey, nil, []byte("header"))
	hmacKey := make([]byte, 32)
	if _, err := io.ReadFull(h, hmacKey); err != nil {
		wipe(hmacKey)
		return nil, err
	}
	// The MAC key is derived per call and is of no use once the hash is
	// keyed, so it does not need to outlive this function.
	defer wipe(hmacKey)
	hh := hmac.New(sha256.New, hmacKey)
	if err := hdr.MarshalWithoutMAC(hh); err != nil {
		return nil, err
	}
	return hh.Sum(nil), nil
}

// streamKey derives the payload key.
//
// INVARIANT (payload key uniqueness). The 16-byte file nonce is fresh
// randomness written into every file and used here as the HKDF salt, so two
// encryptions never share a payload key even if a file key were somehow
// repeated. Combined with the STREAM counter nonce, no (key, nonce) pair is
// ever reused.
func streamKey(fileKey, nonce []byte) []byte {
	h := hkdf.New(sha256.New, fileKey, nonce, []byte("payload"))
	streamKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, streamKey); err != nil {
		panic("fury: internal error: failed to read from HKDF: " + err.Error())
	}
	return streamKey
}
