// Copyright 2026 The fury Authors.
// SPDX-License-Identifier: GPL-3.0-or-later

package stream

import (
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

// NewParallelDecryptReader is equivalent to [NewDecryptReader], except that
// chunks are opened by a pool of worker goroutines instead of inline on the
// calling goroutine.
//
// The sequential DecryptReader disambiguates a full-length final chunk by
// trying to open it with the non-last nonce first and, on authentication
// failure, retrying with the last-chunk nonce. That trick is inherently
// sequential (try, then fall back), so this reader instead keeps a single
// raw chunk of read-ahead: the one goroutine that reads from src (reads must
// stay sequential, there is only one underlying stream) always reads one
// chunk further than it has dispatched, so by the time chunk i is handed to
// the worker pool, whether it is the last chunk is already known for
// certain from the shape of the next read. Each worker then does exactly
// one Open call, with a predetermined nonce, no retry.
//
// For well-formed files this produces byte-for-byte identical plaintext and
// the same errors as NewDecryptReader. For adversarially malformed files,
// the accept/reject verdict is always the same, but the exact error message
// in some corner cases (a corrupted chunk that happens to be full-length)
// may differ, because the classification strategy differs; see the package
// tests for the cases this was checked against.
//
// workers <= 1 returns a plain [NewDecryptReader] with no pipeline overhead.
//
// The returned Reader starts background goroutines that run until the
// stream is fully consumed or a fatal error occurs; abandoning it before
// reading to EOF leaks those goroutines (bounded to a small multiple of
// workers) until they unblock or the process exits.
func NewParallelDecryptReader(key []byte, src io.Reader, workers int) (io.Reader, error) {
	if workers <= 1 {
		return NewDecryptReader(key, src)
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	depth := workers * pipelineDepthPerWorker
	r := &parallelDecryptReader{
		a:     aead,
		src:   src,
		jobs:  make(chan decJob, depth),
		order: make(chan chan decResult, depth),
	}
	r.wg.Add(workers)
	for i := 0; i < workers; i++ {
		go r.work()
	}
	go r.pump()
	return r, nil
}

type decJob struct {
	nonce      [chacha20poly1305.NonceSize]byte
	ciphertext []byte
	result     chan decResult
}

// decResult is either a successfully decrypted chunk (err == nil) or a
// terminal event: a decryption failure, a raw read error, or a trailing-data
// violation. There is no explicit "clean EOF" value: a clean end of stream
// is represented by the order channel closing with nothing left to receive.
type decResult struct {
	plaintext []byte
	err       error
}

type parallelDecryptReader struct {
	a   cipher.AEAD
	src io.Reader

	jobs  chan decJob
	order chan chan decResult
	wg    sync.WaitGroup

	unread []byte
	err    error
}

func (r *parallelDecryptReader) Read(p []byte) (int, error) {
	if len(r.unread) > 0 {
		n := copy(p, r.unread)
		r.unread = r.unread[n:]
		return n, nil
	}
	if r.err != nil {
		return 0, r.err
	}
	if len(p) == 0 {
		return 0, nil
	}

	ch, ok := <-r.order
	if !ok {
		r.err = io.EOF
		return 0, r.err
	}
	res := <-ch
	if res.err != nil {
		r.err = res.err
		return 0, r.err
	}

	r.unread = res.plaintext
	n := copy(p, r.unread)
	r.unread = r.unread[n:]
	return n, nil
}

// dispatch hands a raw chunk, whose classification is already known for
// certain, to the worker pool.
func (r *parallelDecryptReader) dispatch(index int64, ciphertext []byte, last bool) {
	nonce := nonceForChunk(index)
	if last {
		setLastChunkFlag(nonce)
	}
	ch := make(chan decResult, 1)
	r.order <- ch
	r.jobs <- decJob{nonce: *nonce, ciphertext: ciphertext, result: ch}
}

// emitDirect enqueues a terminal result produced by the pump goroutine
// itself (a read error, a malformed-stream error, or a trailing-data
// violation), without involving the worker pool.
func (r *parallelDecryptReader) emitDirect(res decResult) {
	ch := make(chan decResult, 1)
	r.order <- ch
	ch <- res
}

// work opens dispatched chunks. Unlike the sequential reader, there is no
// retry here: the pump goroutine has already determined, from the shape of
// the raw stream, whether each chunk is the last one.
func (r *parallelDecryptReader) work() {
	defer r.wg.Done()
	for j := range r.jobs {
		out := make([]byte, 0, ChunkSize)
		plaintext, err := r.a.Open(out, j.nonce[:], j.ciphertext, nil)
		if err != nil {
			j.result <- decResult{err: errors.New("failed to decrypt and authenticate payload chunk, file may be corrupted or tampered with")}
			continue
		}
		j.result <- decResult{plaintext: plaintext}
	}
}

type chunkKind int

const (
	chunkFull chunkKind = iota
	chunkShort
	chunkEOF
	chunkErr
)

type rawChunk struct {
	kind chunkKind
	data []byte
	err  error
}

// readRawChunk reads exactly one raw encChunkSize block from src into a
// freshly allocated buffer and classifies the read, mirroring the switch at
// the top of the sequential DecryptReader.readChunk.
func readRawChunk(src io.Reader) rawChunk {
	buf := make([]byte, encChunkSize)
	n, err := io.ReadFull(src, buf)
	switch {
	case err == nil:
		return rawChunk{kind: chunkFull, data: buf}
	case err == io.EOF:
		return rawChunk{kind: chunkEOF}
	case err == io.ErrUnexpectedEOF:
		return rawChunk{kind: chunkShort, data: buf[:n]}
	default:
		return rawChunk{kind: chunkErr, err: err}
	}
}

// pump is the single goroutine that reads raw chunks from src, in order,
// always staying one chunk ahead so that every dispatched chunk's
// last-chunk status is already certain. It closes r.jobs and r.order when
// the stream ends or a fatal error is found, which is what lets Read
// observe a clean end of stream (order closed with nothing left) versus an
// explicit terminal error (an emitDirect result).
func (r *parallelDecryptReader) pump() {
	defer close(r.jobs)
	defer close(r.order)

	first := readRawChunk(r.src)
	switch first.kind {
	case chunkErr:
		r.emitDirect(decResult{err: first.err})
		return
	case chunkEOF:
		// A message can't end without a marked chunk; this message is
		// truncated, exactly like the sequential reader's first read.
		r.emitDirect(decResult{err: io.ErrUnexpectedEOF})
		return
	case chunkShort:
		// This is chunk index 0: an empty chunk here is the valid
		// empty-plaintext-file case, not the "empty last chunk" error,
		// which can only apply to a later chunk.
		r.dispatch(0, first.data, true)
		r.probeTrailing()
		return
	}

	// first.kind == chunkFull: ambiguous until we see what follows it.
	pendingIndex := int64(0)
	pending := first.data
	for {
		next := readRawChunk(r.src)
		switch next.kind {
		case chunkErr:
			r.dispatch(pendingIndex, pending, false)
			r.emitDirect(decResult{err: next.err})
			return
		case chunkEOF:
			// Nothing follows: pending was a full-length final chunk. The
			// clean EOF we just observed is itself the trailing-data proof,
			// no separate probe needed.
			r.dispatch(pendingIndex, pending, true)
			return
		case chunkShort:
			r.dispatch(pendingIndex, pending, false)
			if len(next.data) == chacha20poly1305.Overhead {
				// A short chunk here is never index 0, so an empty one is
				// always the disallowed case.
				r.emitDirect(decResult{err: errors.New("last chunk is empty; encrypted payload is malformed")})
				return
			}
			r.dispatch(pendingIndex+1, next.data, true)
			r.probeTrailing()
			return
		case chunkFull:
			r.dispatch(pendingIndex, pending, false)
			pendingIndex++
			pending = next.data
			continue
		}
	}
}

// probeTrailing confirms there is no data after a short final chunk, exactly
// as the sequential DecryptReader.Read does after processing a last chunk.
func (r *parallelDecryptReader) probeTrailing() {
	var b [1]byte
	_, err := r.src.Read(b[:])
	switch {
	case err == nil:
		r.emitDirect(decResult{err: errors.New("trailing data after end of encrypted file")})
	case err != io.EOF:
		r.emitDirect(decResult{err: fmt.Errorf("non-EOF error reading after end of encrypted file: %w", err)})
	}
}
