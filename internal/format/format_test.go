// SPDX-License-Identifier: GPL-3.0-or-later

package format_test

import (
	"bufio"
	"bytes"
	"io"
	"testing"

	"github.com/andydixon/vault/internal/format"
)

func TestStanzaMarshal(t *testing.T) {
	s := &format.Stanza{
		Type: "test",
		Args: []string{"1", "2", "3"},
		Body: nil, // empty
	}
	buf := &bytes.Buffer{}
	s.Marshal(buf)
	if exp := "-> test 1 2 3\n\n"; buf.String() != exp {
		t.Errorf("wrong empty stanza encoding: expected %q, got %q", exp, buf.String())
	}

	buf.Reset()
	s.Body = []byte("AAA")
	s.Marshal(buf)
	if exp := "-> test 1 2 3\nQUFB\n"; buf.String() != exp {
		t.Errorf("wrong normal stanza encoding: expected %q, got %q", exp, buf.String())
	}

	buf.Reset()
	s.Body = bytes.Repeat([]byte("A"), format.BytesPerLine)
	s.Marshal(buf)
	if exp := "-> test 1 2 3\nQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB\n\n"; buf.String() != exp {
		t.Errorf("wrong 64 columns stanza encoding: expected %q, got %q", exp, buf.String())
	}
}

func FuzzMalleability(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		h, payload, err := format.Parse(bytes.NewReader(data))
		if err != nil {
			if h != nil {
				t.Error("h != nil on error")
			}
			if payload != nil {
				t.Error("payload != nil on error")
			}
			t.Skip()
		}
		w := &bytes.Buffer{}
		if err := h.Marshal(w); err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(w, payload); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(w.Bytes(), data) {
			t.Error("Marshal output different from input")
		}
	})
}

// FuzzStanza exercises the recipient-stanza reader directly. Parse reaches it
// only through a well-formed intro line, so fuzzing it on its own covers
// stanza shapes a whole-file seed cannot easily reach.
func FuzzStanza(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		reader := format.NewStanzaReader(bufio.NewReader(bytes.NewReader(data)))
		for range 64 {
			stanza, err := reader.ReadStanza()
			if err != nil {
				if stanza != nil {
					t.Fatal("stanza returned alongside an error")
				}
				return
			}
			if stanza == nil {
				t.Fatal("no stanza and no error")
			}
			// Parser limits must hold: nothing an attacker supplies may make
			// the reader materialise more than the stanza size limit.
			if len(stanza.Body) > format.MaxStanzaSize {
				t.Fatalf("stanza body of %d bytes exceeds the %d byte limit", len(stanza.Body), format.MaxStanzaSize)
			}
		}
	})
}
