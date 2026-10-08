// Copyright 2026 The fury Authors.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Package fury implements post-quantum file encryption. It provides a
// post-quantum-only file format, hybrid KEM key agreement, and a 256-bit file key.
//
// For most use cases, generate a [PQIdentity] with [GeneratePQIdentity], obtain
// its public [PQRecipient] with [PQIdentity.Recipient], and use the [Encrypt]
// and [Decrypt] functions.
//
// fury encrypted files are binary and not malleable. For encoding them as text,
// use the github.com/andydixon/fury/armor package.
//
// # Cryptographic agility
//
// Key agreement is provided by registered suites (see the suite registry).
// Each suite embeds its identifier in the file, so files remain decryptable as
// newer, stronger suites are added and made the default. The default suite is a
// hybrid of FrodoKEM-640 and ML-KEM-768: the file key stays secret unless both
// KEMs are broken.
//
// # Key management
//
// fury does not have a global keyring; generate dedicated keys per task. Public
// recipients are shared as "fury1..." strings (or, being large, as files), or
// referenced by a short "furyfp1..." fingerprint. Private identities are always
// encrypted, with passphrase recovery and optional external unlock slots; there
// is no API to serialise an unencrypted private key.
package pqcrypt

import (
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"runtime"
	"slices"
	"sort"

	"github.com/andydixon/vault/internal/format"
	"github.com/andydixon/vault/internal/stream"
)

// An Identity is passed to [Decrypt] to unwrap an opaque file key from a
// recipient stanza. It can be for example a secret key like [HybridIdentity], a
// plugin, or a custom implementation.
type Identity interface {
	// Unwrap must return an error wrapping [ErrIncorrectIdentity] if none of
	// the recipient stanzas match the identity, any other error will be
	// considered fatal.
	//
	// Most fury API users won't need to interact with this method directly, and
	// should instead pass [Identity] implementations to [Decrypt].
	Unwrap(stanzas []*Stanza) (fileKey []byte, err error)
}

// ErrIncorrectIdentity is returned by [Identity.Unwrap] if none of the
// recipient stanzas match the identity.
var ErrIncorrectIdentity = errors.New("incorrect identity for recipient block")

// A Recipient is passed to [Encrypt] to wrap an opaque file key to one or more
// recipient stanza(s). It can be for example a public key like [HybridRecipient],
// a plugin, or a custom implementation.
type Recipient interface {
	// Most fury API users won't need to interact with this method directly, and
	// should instead pass [Recipient] implementations to [Encrypt].
	Wrap(fileKey []byte) ([]*Stanza, error)
}

// RecipientWithLabels can be optionally implemented by a [Recipient], in which
// case [Encrypt] will use WrapWithLabels instead of [Recipient.Wrap].
//
// Encrypt will succeed only if the labels returned by all the recipients
// (assuming the empty set for those that don't implement RecipientWithLabels)
// are the same.
//
// This can be used to ensure a recipient is only used with other recipients
// with equivalent properties (for example by setting a "postquantum" label) or
// to ensure a recipient is always used alone (by returning a random label, for
// example to preserve its authentication properties).
type RecipientWithLabels interface {
	WrapWithLabels(fileKey []byte) (s []*Stanza, labels []string, err error)
}

// A Stanza is a section of the fury header that encapsulates the file key as
// encrypted to a specific recipient.
//
// Most fury API users won't need to interact with this type directly, and should
// instead pass [Recipient] implementations to [Encrypt] and [Identity]
// implementations to [Decrypt].
type Stanza struct {
	Type string
	Args []string
	Body []byte
}

// fileKeySize is 32 bytes (256-bit) so the symmetric layer's post-quantum
// (Grover) security floor of ~128 bits matches the KEMs, rather than the 64-bit
// floor a 128-bit file key would impose. See suite.go and the payload STREAM.
const fileKeySize = 32
const streamNonceSize = 16

// maxAutoWorkers bounds the automatic worker count for parallel STREAM
// chunk encryption/decryption. ChaCha20-Poly1305 is memory-bandwidth-bound
// past a modest number of cores, so an unbounded runtime.NumCPU() on very
// large machines would just add goroutine/channel overhead for no benefit.
const maxAutoWorkers = 32

// MaxWorkers is the largest value [Options.Workers] will accept.
//
// The limit is set by what a worker actually costs, not by taste. Each worker
// may have two chunks in flight (see the stream package's pipeline depth), and
// a chunk is 64 KiB of plaintext plus its ciphertext buffer, so the pipeline
// holds roughly 256 KiB per worker: about 256 MiB at this limit, plus 1024
// goroutines and channels sized to match. That is already far past the point
// where throughput stops improving, and comfortably above the thread count of
// the largest machines currently shipping. A request beyond it is a
// configuration error rather than a tuning choice, so Fury rejects it instead
// of quietly attempting it or silently substituting another number.
const MaxWorkers = 1024

// Options configures [EncryptWithOptions] and [DecryptWithOptions] beyond
// the defaults used by [Encrypt] and [Decrypt].
type Options struct {
	// Workers controls how many goroutines seal or open STREAM chunks in
	// parallel. STREAM chunk nonces are a pure counter independent of chunk
	// content, so parallelising this work never changes the resulting
	// ciphertext or plaintext, only how fast it's produced.
	//
	// Valid values are 0 to [MaxWorkers]. Zero (the default) means
	// automatic: runtime.NumCPU(), capped at a value past which
	// ChaCha20-Poly1305 stops getting faster. One forces the sequential
	// code path. A negative value, or one above MaxWorkers, is rejected.
	Workers int
}

// ErrInvalidWorkers is returned when [Options.Workers] is outside 0 to
// [MaxWorkers].
var ErrInvalidWorkers = errors.New("fury: worker count out of range")

// Validate reports whether the options are usable. Every entry point that
// accepts [Options] calls it, so an out-of-range worker count is refused by
// the library itself and not only by the command-line tool.
func (o Options) Validate() error {
	if o.Workers < 0 {
		return fmt.Errorf("%w: %d is negative", ErrInvalidWorkers, o.Workers)
	}
	if o.Workers > MaxWorkers {
		return fmt.Errorf("%w: %d exceeds the maximum of %d", ErrInvalidWorkers, o.Workers, MaxWorkers)
	}
	return nil
}

func (o Options) workers() int {
	if o.Workers > 0 {
		return o.Workers
	}
	if n := runtime.NumCPU(); n < maxAutoWorkers {
		return n
	}
	return maxAutoWorkers
}

// encryptHdr wraps a file key to every recipient and authenticates the result.
//
// INVARIANT (no silent downgrade). All recipients must return identical label
// sets. A recipient that does not implement [RecipientWithLabels] contributes
// the empty set, so it can never be mixed with a "postquantum" recipient. Any
// future recipient type with weaker properties fails closed rather than
// quietly lowering the security of the whole file.
func encryptHdr(fileKey []byte, recipients ...Recipient) (*format.Header, error) {
	if len(recipients) == 0 {
		return nil, errors.New("no recipients specified")
	}

	hdr := &format.Header{}
	var labels []string
	for i, r := range recipients {
		stanzas, l, err := wrapWithLabels(r, fileKey)
		if err != nil {
			return nil, fmt.Errorf("failed to wrap key for recipient #%d: %w", i, err)
		}
		sort.Strings(l)
		if i == 0 {
			labels = l
		} else if !slices.Equal(labels, l) {
			return nil, incompatibleLabelsError(labels, l)
		}
		for _, s := range stanzas {
			hdr.Recipients = append(hdr.Recipients, (*format.Stanza)(s))
		}
	}
	if mac, err := headerMAC(fileKey, hdr); err != nil {
		return nil, fmt.Errorf("failed to compute header MAC: %v", err)
	} else {
		hdr.MAC = mac
	}
	return hdr, nil
}

// Encrypt encrypts a file to one or more recipients. Every recipient will be
// able to decrypt the file.
//
// Writes to the returned WriteCloser are encrypted and written to dst as a fury
// file. The caller must call Close on the WriteCloser when done for the last
// chunk to be encrypted and flushed to dst.
//
// The payload is sealed using multiple goroutines automatically; see
// [EncryptWithOptions] to control that.
func Encrypt(dst io.Writer, recipients ...Recipient) (io.WriteCloser, error) {
	return EncryptWithOptions(dst, Options{}, recipients...)
}

// EncryptWithOptions is like [Encrypt], with explicit [Options].
//
// INVARIANT (fresh file key). Every call generates a new 32-byte file key
// from crypto/rand. Nothing derives a file key from the plaintext, the
// recipients or a counter, so no two encryptions share one.
func EncryptWithOptions(dst io.Writer, opts Options, recipients ...Recipient) (io.WriteCloser, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	fileKey := make([]byte, fileKeySize)
	if _, err := rand.Read(fileKey); err != nil {
		return nil, fmt.Errorf("failed to generate file key: %w", err)
	}
	defer wipe(fileKey)

	hdr, err := encryptHdr(fileKey, recipients...)
	if err != nil {
		return nil, err
	}
	if err := hdr.Marshal(dst); err != nil {
		return nil, fmt.Errorf("failed to write header: %w", err)
	}

	nonce := make([]byte, streamNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	if _, err := dst.Write(nonce); err != nil {
		return nil, fmt.Errorf("failed to write nonce: %w", err)
	}

	key := streamKey(fileKey, nonce)
	w, err := stream.NewParallelEncryptWriter(key, dst, opts.workers())
	wipe(key)
	return w, err
}

func wrapWithLabels(r Recipient, fileKey []byte) (s []*Stanza, labels []string, err error) {
	if r, ok := r.(RecipientWithLabels); ok {
		return r.WrapWithLabels(fileKey)
	}
	s, err = r.Wrap(fileKey)
	return
}

func incompatibleLabelsError(l1, l2 []string) error {
	hasPQ1 := slices.Contains(l1, "postquantum")
	hasPQ2 := slices.Contains(l2, "postquantum")
	if hasPQ1 != hasPQ2 {
		return fmt.Errorf("incompatible recipients: can't mix post-quantum and classic recipients, or the file would be vulnerable to quantum computers")
	}
	return fmt.Errorf("incompatible recipients: %q and %q can't be mixed", l1, l2)
}

// NoIdentityMatchError is returned by [Decrypt] when none of the supplied
// identities match the encrypted file.
type NoIdentityMatchError struct {
	// Errors is a slice of all the errors returned to Decrypt by the Unwrap
	// calls it made. They all wrap [ErrIncorrectIdentity].
	Errors []error
	// StanzaTypes are the first argument of each recipient stanza in the
	// encrypted file's header.
	StanzaTypes []string
}

func (e *NoIdentityMatchError) Error() string {
	if len(e.Errors) == 1 {
		return "identity did not match any of the recipients: " + e.Errors[0].Error()
	}
	return "no identity matched any of the recipients"
}

// Decrypt decrypts a file encrypted to one or more identities.
// All identities will be tried until one successfully decrypts the file.
// Native, non-interactive identities are tried before any other identities.
//
// Decrypt returns a Reader reading the decrypted plaintext of the fury file read
// from src. If no identity matches the encrypted file, the returned error will
// be of type [NoIdentityMatchError].
//
// The payload is opened using multiple goroutines automatically; see
// [DecryptWithOptions] to control that.
func Decrypt(src io.Reader, identities ...Identity) (io.Reader, error) {
	return DecryptWithOptions(src, Options{}, identities...)
}

// DecryptWithOptions is like [Decrypt], with explicit [Options].
func DecryptWithOptions(src io.Reader, opts Options, identities ...Identity) (io.Reader, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	hdr, payload, err := format.Parse(src)
	if err != nil {
		return nil, fmt.Errorf("failed to read header: %w", err)
	}

	fileKey, err := decryptHdr(hdr, identities...)
	if err != nil {
		return nil, err
	}
	defer wipe(fileKey)

	nonce := make([]byte, streamNonceSize)
	if _, err := io.ReadFull(payload, nonce); err != nil {
		return nil, fmt.Errorf("failed to read nonce: %w", err)
	}

	key := streamKey(fileKey, nonce)
	r, err := stream.NewParallelDecryptReader(key, payload, opts.workers())
	wipe(key)
	return r, err
}

func decryptHdr(hdr *format.Header, identities ...Identity) ([]byte, error) {
	if len(identities) == 0 {
		return nil, errors.New("no identities specified")
	}
	slices.SortStableFunc(identities, func(a, b Identity) int {
		var aIsNative, bIsNative bool
		switch a.(type) {
		case *PQIdentity:
			aIsNative = true
		}
		switch b.(type) {
		case *PQIdentity:
			bIsNative = true
		}
		if aIsNative && !bIsNative {
			return -1
		}
		if !aIsNative && bIsNative {
			return 1
		}
		return 0
	})

	stanzas := make([]*Stanza, 0, len(hdr.Recipients))
	errNoMatch := &NoIdentityMatchError{}
	for _, s := range hdr.Recipients {
		errNoMatch.StanzaTypes = append(errNoMatch.StanzaTypes, s.Type)
		stanzas = append(stanzas, (*Stanza)(s))
	}
	var fileKey []byte
	// The unwrapped key is copied out below; clear this copy on every exit
	// path so it does not outlive the call. A closure is required: fileKey is
	// assigned inside the loop, and a bare defer would capture today's nil.
	defer func() { wipe(fileKey) }()
	for _, id := range identities {
		var err error
		fileKey, err = id.Unwrap(stanzas)
		if errors.Is(err, ErrIncorrectIdentity) {
			errNoMatch.Errors = append(errNoMatch.Errors, err)
			continue
		}
		if err != nil {
			return nil, err
		}

		break
	}
	if fileKey == nil {
		return nil, errNoMatch
	}

	if mac, err := headerMAC(fileKey, hdr); err != nil {
		return nil, fmt.Errorf("failed to compute header MAC: %v", err)
	} else if !hmac.Equal(mac, hdr.MAC) {
		return nil, errors.New("bad header MAC")
	}

	return append([]byte(nil), fileKey...), nil
}

// multiUnwrap is a helper that implements Identity.Unwrap in terms of a
// function that unwraps a single recipient stanza.
func multiUnwrap(unwrap func(*Stanza) ([]byte, error), stanzas []*Stanza) ([]byte, error) {
	for _, s := range stanzas {
		fileKey, err := unwrap(s)
		if errors.Is(err, ErrIncorrectIdentity) {
			// If we ever start returning something interesting wrapping
			// ErrIncorrectIdentity, we should let it make its way up through
			// Decrypt into NoIdentityMatchError.Errors.
			continue
		}
		if err != nil {
			return nil, err
		}
		return fileKey, nil
	}
	return nil, ErrIncorrectIdentity
}
