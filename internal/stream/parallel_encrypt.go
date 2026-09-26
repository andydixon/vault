// Copyright 2026 The fury Authors.
// SPDX-License-Identifier: GPL-3.0-or-later

package stream

import (
	"bytes"
	"crypto/cipher"
	"errors"
	"io"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

// pipelineDepthPerWorker bounds how many chunks may be queued for, or
// awaiting collection from, a single worker at once. It caps the pipeline's
// memory use to a small multiple of ChunkSize regardless of input size.
const pipelineDepthPerWorker = 2

// NewParallelEncryptWriter is equivalent to [NewEncryptWriter], except that
// chunks are sealed by a pool of worker goroutines instead of inline on the
// calling goroutine. Its output is byte-for-byte identical to
// NewEncryptWriter's: STREAM chunk nonces are a pure counter, so sealing
// chunk i never depends on chunk i-1. Only the write order to dst must stay
// sequential, which a dedicated collector goroutine enforces.
//
// workers <= 1 returns a plain [NewEncryptWriter] with no pipeline overhead.
func NewParallelEncryptWriter(key []byte, dst io.Writer, workers int) (io.WriteCloser, error) {
	if workers <= 1 {
		return NewEncryptWriter(key, dst)
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	depth := workers * pipelineDepthPerWorker
	w := &parallelEncryptWriter{
		a:     aead,
		dst:   dst,
		jobs:  make(chan encJob, depth),
		order: make(chan chan []byte, depth),
		done:  make(chan struct{}),
	}
	w.wg.Add(workers)
	for i := 0; i < workers; i++ {
		go w.work()
	}
	go w.collect()
	return w, nil
}

type encJob struct {
	nonce     [chacha20poly1305.NonceSize]byte
	plaintext []byte
	result    chan []byte
}

type parallelEncryptWriter struct {
	a   cipher.AEAD
	dst io.Writer

	buf   bytes.Buffer
	index int64

	jobs  chan encJob
	order chan chan []byte
	wg    sync.WaitGroup
	done  chan struct{} // closed once the collector goroutine has returned

	mu  sync.Mutex
	err error
}

func (w *parallelEncryptWriter) getErr() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.err
}

func (w *parallelEncryptWriter) setErr(err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err == nil {
		w.err = err
	}
}

func (w *parallelEncryptWriter) Write(p []byte) (n int, err error) {
	if err := w.getErr(); err != nil {
		return 0, err
	}
	if len(p) == 0 {
		return 0, nil
	}

	total := len(p)
	for len(p) > 0 {
		room := ChunkSize - w.buf.Len()
		nn := min(len(p), room)
		w.buf.Write(p[:nn])
		p = p[nn:]

		// Only submit a chunk once we know more data is coming, so the very
		// last chunk (submitted from Close) is always the one that gets the
		// last-chunk-flag nonce, exactly like the sequential EncryptWriter.
		if w.buf.Len() == ChunkSize && len(p) > 0 {
			if err := w.submitChunk(false); err != nil {
				w.setErr(err)
				return 0, err
			}
		}
	}
	return total, nil
}

// Close flushes the last chunk and waits for every queued chunk to be
// sealed and written to dst, in order. It does not close the underlying
// Writer.
func (w *parallelEncryptWriter) Close() error {
	if err := w.getErr(); err != nil {
		return err
	}

	// submitChunk cannot fail here: we just confirmed there is no prior
	// error, and channel sends to w.jobs/w.order only block, they never
	// return an error.
	_ = w.submitChunk(true)

	close(w.jobs)
	close(w.order)
	w.wg.Wait()
	<-w.done

	if err := w.getErr(); err != nil {
		return err
	}
	w.setErr(errors.New("stream.Writer is already closed"))
	return nil
}

// submitChunk copies out the current buffer as a chunk of plaintext, assigns
// it the next sequential nonce, and hands it to the worker pool. last must be
// true only for the final call, made from Close.
func (w *parallelEncryptWriter) submitChunk(last bool) error {
	if err := w.getErr(); err != nil {
		return err
	}

	plaintext := append([]byte(nil), w.buf.Bytes()...)
	w.buf.Reset()

	nonce := nonceForChunk(w.index)
	if last {
		setLastChunkFlag(nonce)
	}
	w.index++

	result := make(chan []byte, 1)
	w.order <- result
	w.jobs <- encJob{nonce: *nonce, plaintext: plaintext, result: result}
	return nil
}

// work seals queued chunks. Seal cannot fail: the nonce is always the
// correct size, so the only possible failure in this pipeline is dst.Write,
// handled in collect.
func (w *parallelEncryptWriter) work() {
	defer w.wg.Done()
	for j := range w.jobs {
		ciphertext := w.a.Seal(make([]byte, 0, len(j.plaintext)+w.a.Overhead()), j.nonce[:], j.plaintext, nil)
		j.result <- ciphertext
	}
}

// collect writes sealed chunks to dst strictly in submission order, even
// though workers may finish sealing them in a different order.
func (w *parallelEncryptWriter) collect() {
	defer close(w.done)
	var failed bool
	for result := range w.order {
		ciphertext := <-result
		if failed {
			continue
		}
		if _, err := w.dst.Write(ciphertext); err != nil {
			w.setErr(err)
			failed = true
		}
	}
}
