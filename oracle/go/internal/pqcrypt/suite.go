// Copyright 2026 The fury Authors.
// SPDX-License-Identifier: GPL-3.0-or-later

package pqcrypt

import (
	"crypto/rand"
	"errors"
	"fmt"
)

// A pqSuite is a registered post-quantum KEM suite. Each suite wraps the file
// key to a recipient and unwraps it with the corresponding identity. Suites are
// self-describing: their stanza tag is written into the header, so a file made
// with one suite keeps decrypting even after newer suites are added and made the
// default. This is the "use the best now, add better later, still decrypt older"
// property.
//
// Recipient public keys and identity private keys are opaque byte slices whose
// layout is defined by the suite. Identities are derived deterministically from
// a compact master seed so they can be stored and passphrase-wrapped cheaply.
type pqSuite interface {
	// id is a stable numeric identifier embedded in recipient encodings.
	id() uint16
	// tag is the header stanza Type for this suite.
	tag() string
	// rank orders suites when picking a default; higher wins.
	rank() int
	// seedSize is the length of the master seed accepted by deriveKeypair.
	seedSize() int
	// deriveKeypair deterministically expands a master seed into a suite public
	// key and private key.
	deriveKeypair(seed []byte) (pub, priv []byte, err error)
	// wrap encapsulates fileKey to pub, returning one or more header stanzas.
	wrap(pub, fileKey []byte) ([]*Stanza, error)
	// unwrap recovers fileKey from a stanza using priv. It must return an error
	// wrapping ErrIncorrectIdentity if the stanza does not match.
	unwrap(priv []byte, s *Stanza) ([]byte, error)
	// publicKeySize is the expected length of a suite public key.
	publicKeySize() int
}

var (
	pqSuitesByTag = map[string]pqSuite{}
	pqSuitesByID  = map[uint16]pqSuite{}
)

// registerSuite adds a suite to the registry. It is called from suite files'
// init functions.
func registerSuite(s pqSuite) {
	if _, ok := pqSuitesByTag[s.tag()]; ok {
		panic("fury: duplicate suite tag " + s.tag())
	}
	if _, ok := pqSuitesByID[s.id()]; ok {
		panic(fmt.Sprintf("fury: duplicate suite id %#04x", s.id()))
	}
	pqSuitesByTag[s.tag()] = s
	pqSuitesByID[s.id()] = s
}

// defaultSuite returns the highest-ranked registered suite, used for key
// generation and encryption.
func defaultSuite() pqSuite {
	var best pqSuite
	for _, s := range pqSuitesByTag {
		if best == nil || s.rank() > best.rank() {
			best = s
		}
	}
	if best == nil {
		panic("fury: no PQ suites registered")
	}
	return best
}

// PQRecipient is a post-quantum public key. Messages encrypted to it can be
// decrypted with the corresponding [PQIdentity].
//
// It is anonymous: an observer can't tell from a message alone whether it is
// encrypted to a given recipient.
type PQRecipient struct {
	suite pqSuite
	pub   []byte
}

var _ Recipient = &PQRecipient{}
var _ RecipientWithLabels = &PQRecipient{}

func (r *PQRecipient) Wrap(fileKey []byte) ([]*Stanza, error) {
	return r.suite.wrap(r.pub, fileKey)
}

// WrapWithLabels returns a "postquantum" label so a PQRecipient can only be
// combined with other post-quantum recipients, never with a recipient type that
// would defeat its security.
func (r *PQRecipient) WrapWithLabels(fileKey []byte) ([]*Stanza, []string, error) {
	s, err := r.Wrap(fileKey)
	if err != nil {
		return nil, nil, err
	}
	return s, []string{"postquantum"}, nil
}

// SuiteID returns the numeric identifier of the recipient's suite.
func (r *PQRecipient) SuiteID() uint16 { return r.suite.id() }

// Bytes returns the raw suite public key.
func (r *PQRecipient) Bytes() []byte { return append([]byte(nil), r.pub...) }

// PQIdentity is a post-quantum private key, derived from a compact master seed,
// which can decrypt messages encrypted to the corresponding [PQRecipient].
type PQIdentity struct {
	suite pqSuite
	seed  []byte
	pub   []byte
	priv  []byte
}

var _ Identity = &PQIdentity{}

// GeneratePQIdentity randomly generates a new identity using the default suite.
func GeneratePQIdentity() (*PQIdentity, error) {
	s := defaultSuite()
	seed := make([]byte, s.seedSize())
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("failed to generate seed: %w", err)
	}
	id, err := newPQIdentityFromSeed(s, seed)
	wipe(seed)
	return id, err
}

// newPQIdentityFromSeed derives an identity from a suite and master seed.
func newPQIdentityFromSeed(s pqSuite, seed []byte) (*PQIdentity, error) {
	if len(seed) != s.seedSize() {
		return nil, fmt.Errorf("invalid seed size %d for suite %s", len(seed), s.tag())
	}
	seed = append([]byte(nil), seed...)
	pub, priv, err := s.deriveKeypair(seed)
	if err != nil {
		return nil, fmt.Errorf("failed to derive keypair: %w", err)
	}
	return &PQIdentity{suite: s, seed: seed, pub: pub, priv: priv}, nil
}

// usable reports whether the identity still holds its secret material. A
// closed identity, and one that was never fully initialised, both report
// false rather than panicking on a nil slice.
func (i *PQIdentity) usable() bool {
	return i != nil && i.suite != nil && len(i.seed) == i.suite.seedSize() && len(i.priv) != 0
}

// ErrIdentityClosed is returned by operations on an identity whose secret
// material has been cleared by Close.
var ErrIdentityClosed = errors.New("fury identity is closed or uninitialised")

// Close overwrites the secret material this identity owns: its master seed
// and its expanded private key. Repeated calls are safe, and a partially
// initialised identity closes without panicking. The public key is retained,
// so [PQIdentity.Recipient] keeps working on a closed identity.
//
// Explicit overwriting shortens the lifetime of buffers Fury knows about. It
// cannot guarantee removal from physical memory: the Go compiler and runtime
// may have copied a value during allocation, garbage collection, stack growth
// or escape analysis, and Fury has no way to find or clear those copies. Treat
// this as defence in depth, not as erasure.
func (i *PQIdentity) Close() {
	if i == nil {
		return
	}
	wipe(i.seed)
	wipe(i.priv)
	i.seed, i.priv = nil, nil
}

func (i *PQIdentity) Unwrap(stanzas []*Stanza) ([]byte, error) {
	if !i.usable() {
		return nil, ErrIdentityClosed
	}
	return multiUnwrap(i.unwrap, stanzas)
}

func (i *PQIdentity) unwrap(s *Stanza) ([]byte, error) {
	su, ok := pqSuitesByTag[s.Type]
	if !ok || su.tag() != i.suite.tag() {
		return nil, ErrIncorrectIdentity
	}
	fileKey, err := su.unwrap(i.priv, s)
	if err != nil {
		return nil, err
	}
	// Enforce the file key length centrally, so no future suite can feed a
	// wrong-sized key into the payload STREAM by forgetting its own check.
	if len(fileKey) != fileKeySize {
		return nil, fmt.Errorf("suite %s returned a file key of %d bytes, want %d", su.tag(), len(fileKey), fileKeySize)
	}
	return fileKey, nil
}

// Recipient returns the public [PQRecipient] corresponding to i. It remains
// valid after [PQIdentity.Close], because a public key is not secret.
func (i *PQIdentity) Recipient() *PQRecipient {
	return &PQRecipient{suite: i.suite, pub: append([]byte(nil), i.pub...)}
}

// Seed returns a copy of the compact master seed, or nil if the identity is
// closed.
//
// The returned slice is secret-equivalent: it regenerates both the private and
// the public key, so anything that can read it can decrypt everything the
// identity can. It must never be shared as a recipient, written unencrypted,
// logged, or passed to a subprocess.
//
// The copy is deliberate: it is never an alias into the identity's own buffer,
// so closing the identity does not clear it. From the moment it is returned it
// is the caller's responsibility to wipe it when finished and to keep its
// lifetime short.
func (i *PQIdentity) Seed() []byte {
	if !i.usable() {
		return nil
	}
	return append([]byte(nil), i.seed...)
}

// SuiteID returns the numeric identifier of the identity's suite.
func (i *PQIdentity) SuiteID() uint16 { return i.suite.id() }

// NewPQIdentityFromSeed derives an identity of the given suite from its master
// seed, as returned by [PQIdentity.Seed].
func NewPQIdentityFromSeed(suiteID uint16, seed []byte) (*PQIdentity, error) {
	s, ok := pqSuitesByID[suiteID]
	if !ok {
		return nil, fmt.Errorf("unknown suite id %#04x", suiteID)
	}
	return newPQIdentityFromSeed(s, seed)
}
