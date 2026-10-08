// Copyright 2026 The fury Authors.
// SPDX-License-Identifier: GPL-3.0-or-later

package pqcrypt

import (
	"bytes"
	"io"
	"testing"
)

// TestPQRoundTrip exercises the full Encrypt -> Decrypt path through the default
// post-quantum suite with a 256-bit file key.
func TestPQRoundTrip(t *testing.T) {
	id, err := GeneratePQIdentity()
	if err != nil {
		t.Fatal(err)
	}
	r := id.Recipient()

	plaintext := []byte("fury: post-quantum only, hard g like GIF")

	buf := &bytes.Buffer{}
	w, err := Encrypt(buf, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plaintext); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	out, err := Decrypt(bytes.NewReader(buf.Bytes()), id)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, plaintext)
	}
}

func TestPQFileKeyIs256Bit(t *testing.T) {
	if fileKeySize != 32 {
		t.Fatalf("fileKeySize = %d, want 32 (256-bit)", fileKeySize)
	}
}

// TestPQWrongIdentity confirms a different identity cannot decrypt.
func TestPQWrongIdentity(t *testing.T) {
	id, _ := GeneratePQIdentity()
	other, _ := GeneratePQIdentity()

	buf := &bytes.Buffer{}
	w, err := Encrypt(buf, id.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("secret"))
	w.Close()

	if _, err := Decrypt(bytes.NewReader(buf.Bytes()), other); err == nil {
		t.Fatal("decryption with wrong identity unexpectedly succeeded")
	}
}

// TestSuiteRegistry checks the default suite is registered and self-describing.
func TestSuiteRegistry(t *testing.T) {
	s := defaultSuite()
	if s.tag() != "frodo640shake+mlkem768" {
		t.Fatalf("unexpected default suite %q", s.tag())
	}
	if pqSuitesByID[s.id()] != s {
		t.Fatal("suite not registered by id")
	}
	if pqSuitesByTag[s.tag()] != s {
		t.Fatal("suite not registered by tag")
	}
}

// TestSeedDeterministic confirms an identity round-trips through its seed, which
// is what makes compact passphrase-wrapped identities possible.
func TestSeedDeterministic(t *testing.T) {
	id, err := GeneratePQIdentity()
	if err != nil {
		t.Fatal(err)
	}
	id2, err := newPQIdentityFromSeed(defaultSuite(), id.Seed())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(id.pub, id2.pub) || !bytes.Equal(id.priv, id2.priv) {
		t.Fatal("identity not deterministic from seed")
	}
}

func TestIdentityAndRecipientAccessorsReturnCopies(t *testing.T) {
	id, err := GeneratePQIdentity()
	if err != nil {
		t.Fatal(err)
	}

	seed := id.Seed()
	seed[0] ^= 0xff
	if id.seed[0] == seed[0] {
		t.Fatal("Seed returned mutable identity internals")
	}

	inputSeed := id.Seed()
	id2, err := newPQIdentityFromSeed(defaultSuite(), inputSeed)
	if err != nil {
		t.Fatal(err)
	}
	inputSeed[0] ^= 0xff
	if id2.seed[0] == inputSeed[0] {
		t.Fatal("newPQIdentityFromSeed retained caller-owned seed slice")
	}

	recipient := id.Recipient()
	pub := recipient.Bytes()
	pub[0] ^= 0xff
	if recipient.pub[0] == pub[0] {
		t.Fatal("Bytes returned mutable recipient internals")
	}

	recipient.pub[0] ^= 0xff
	if id.pub[0] == recipient.pub[0] {
		t.Fatal("Recipient returned mutable identity public-key internals")
	}
}
