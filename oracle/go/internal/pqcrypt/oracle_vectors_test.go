// SPDX-License-Identifier: GPL-3.0-or-later

// Test-only vector generator for the Rust port. It adds nothing to the
// production code: it only calls the frozen implementation and records what
// it computes. Run through oracle/gen-vectors.sh.

package pqcrypt

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/andydixon/vault/internal/format"
	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/frodo/frodo640shake"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"golang.org/x/crypto/hkdf"
)

type kemVector struct {
	Seed          string `json:"seed"`
	PubSHA256     string `json:"pub_sha256"`
	PrivSHA256    string `json:"priv_sha256"`
	EncapSeed     string `json:"encap_seed"`
	CtSHA256      string `json:"ct_sha256"`
	SharedSecret  string `json:"ss"`
	RejectFlipIdx int    `json:"reject_flip_index"`
	RejectSS      string `json:"reject_ss"`
}

type hybridVector struct {
	MasterSeed string `json:"master_seed"`
	FrodoSeed  string `json:"frodo_seed"`
	MLKEMSeed  string `json:"mlkem_seed"`
	PubSHA256  string `json:"pub_sha256"`
	PrivSHA256 string `json:"priv_sha256"`
	PubPrefix  string `json:"pub_prefix"`
}

type wrapVector struct {
	MasterSeed  string `json:"master_seed"`
	FrodoEncap  string `json:"frodo_encap_seed"`
	MLKEMEncap  string `json:"mlkem_encap_seed"`
	FileKey     string `json:"file_key"`
	KEK         string `json:"kek"`
	Header      string `json:"header_hex"` // full serialised header, MAC line included
	MAC         string `json:"mac"`
	Nonce       string `json:"nonce"`
	PayloadKey  string `json:"payload_key"`
	StanzaArg0  string `json:"stanza_arg0_sha256"`
	StanzaBody  string `json:"stanza_body"`
}

type headerCase struct {
	Input  string `json:"input_hex"`
	Accept bool   `json:"accept"`
	Rest   string `json:"rest_hex,omitempty"` // payload bytes after the header
}

func sum(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func pattern(n int, salt byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7) ^ salt
	}
	return b
}

func kemVectors(t *testing.T, s kem.Scheme, n int) []kemVector {
	var out []kemVector
	for i := range n {
		seed := pattern(s.SeedSize(), byte(i*31))
		pk, sk := s.DeriveKeyPair(seed)
		pkb, _ := pk.MarshalBinary()
		skb, _ := sk.MarshalBinary()
		es := pattern(s.EncapsulationSeedSize(), byte(i*17+5))
		ct, ss, err := s.EncapsulateDeterministically(pk, es)
		if err != nil {
			t.Fatal(err)
		}
		ss2, err := s.Decapsulate(sk, ct)
		if err != nil || !bytes.Equal(ss, ss2) {
			t.Fatal("decapsulation mismatch")
		}
		flip := (i * 997) % len(ct)
		bad := append([]byte(nil), ct...)
		bad[flip] ^= 0x01
		rss, err := s.Decapsulate(sk, bad)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, kemVector{
			Seed: hex.EncodeToString(seed), PubSHA256: sum(pkb), PrivSHA256: sum(skb),
			EncapSeed: hex.EncodeToString(es), CtSHA256: sum(ct), SharedSecret: hex.EncodeToString(ss),
			RejectFlipIdx: flip, RejectSS: hex.EncodeToString(rss),
		})
	}
	return out
}

func TestOracleVectors(t *testing.T) {
	dir := os.Getenv("VAULT_ORACLE_OUT")
	if dir == "" {
		t.Skip("set VAULT_ORACLE_OUT to write vectors")
	}
	suite := frodoMLKEM768{}
	frodo, ml := frodo640shake.Scheme(), mlkem768.Scheme()

	var hybrids []hybridVector
	for i := range 6 {
		master := pattern(32, byte(i*53+1))
		if i == 5 {
			master = bytes.Repeat([]byte{0xff}, 32)
		}
		r := hkdf.New(sha256.New, master, nil, []byte("fury/v1 seed-expand "+suite.tag()))
		fs := make([]byte, frodo.SeedSize())
		ms := make([]byte, ml.SeedSize())
		io.ReadFull(r, fs)
		io.ReadFull(r, ms)
		pub, priv, err := suite.deriveKeypair(master)
		if err != nil {
			t.Fatal(err)
		}
		hybrids = append(hybrids, hybridVector{
			MasterSeed: hex.EncodeToString(master), FrodoSeed: hex.EncodeToString(fs), MLKEMSeed: hex.EncodeToString(ms),
			PubSHA256: sum(pub), PrivSHA256: sum(priv), PubPrefix: hex.EncodeToString(pub[:64]),
		})
	}

	// A wrap with controlled encapsulation randomness, built from the real
	// deriveKEK, aeadEncrypt, header marshalling, headerMAC and streamKey.
	var wraps []wrapVector
	for i := range 3 {
		master := pattern(32, byte(i*53+1))
		id, err := NewPQIdentityFromSeed(suite.id(), master)
		if err != nil {
			t.Fatal(err)
		}
		pub := id.Recipient().Bytes()
		fpk, _ := frodo.UnmarshalBinaryPublicKey(pub[:frodo.PublicKeySize()])
		mpk, _ := ml.UnmarshalBinaryPublicKey(pub[frodo.PublicKeySize():])
		fe, me := pattern(16, byte(i+100)), pattern(32, byte(i+150))
		ct1, ss1, _ := frodo.EncapsulateDeterministically(fpk, fe)
		ct2, ss2, _ := ml.EncapsulateDeterministically(mpk, me)
		kek := suite.deriveKEK(ss1, ss2, ct1, ct2)
		fileKey := pattern(32, byte(i+200))
		body, _ := aeadEncrypt(kek, fileKey)
		st := &format.Stanza{Type: suite.tag(), Args: []string{format.EncodeToString(ct1), format.EncodeToString(ct2)}, Body: body}
		hdr := &format.Header{Recipients: []*format.Stanza{st}}
		mac, err := headerMAC(fileKey, hdr)
		if err != nil {
			t.Fatal(err)
		}
		hdr.MAC = mac
		var hb bytes.Buffer
		hdr.Marshal(&hb)
		// The real identity must open what was built.
		got, err := id.Unwrap([]*Stanza{(*Stanza)(st)})
		if err != nil || !bytes.Equal(got, fileKey) {
			t.Fatal("identity did not unwrap the vector")
		}
		nonce := pattern(16, byte(i+250))
		wraps = append(wraps, wrapVector{
			MasterSeed: hex.EncodeToString(master), FrodoEncap: hex.EncodeToString(fe), MLKEMEncap: hex.EncodeToString(me),
			FileKey: hex.EncodeToString(fileKey), KEK: hex.EncodeToString(kek), Header: hex.EncodeToString(hb.Bytes()),
			MAC: hex.EncodeToString(mac), Nonce: hex.EncodeToString(nonce), PayloadKey: hex.EncodeToString(streamKey(fileKey, nonce)),
			StanzaArg0: sum([]byte(st.Args[0])), StanzaBody: hex.EncodeToString(body),
		})
	}

	// Whole files from the real Encrypt, with fresh randomness, for the
	// first hybrid identity. Plaintexts are pattern(size, 0x5a).
	id, _ := NewPQIdentityFromSeed(suite.id(), pattern(32, 1))
	fdir := filepath.Join(dir, "fury")
	os.MkdirAll(fdir, 0o755)
	for _, size := range []int{0, 1, 65535, 65536, 65537, 131072, 200000} {
		var buf bytes.Buffer
		w, err := Encrypt(&buf, id.Recipient())
		if err != nil {
			t.Fatal(err)
		}
		w.Write(pattern(size, 0x5a))
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(fdir, "pattern-"+itoa(size)+".fury"), buf.Bytes(), 0o644)
	}

	// Header parser verdicts on valid and malformed headers.
	var cases []headerCase
	valid, _ := hex.DecodeString(wraps[0].Header)
	add := func(b []byte) {
		h, payload, err := format.Parse(bytes.NewReader(b))
		c := headerCase{Input: hex.EncodeToString(b), Accept: err == nil}
		if err == nil {
			rest, _ := io.ReadAll(payload)
			c.Rest = hex.EncodeToString(rest)
			var again bytes.Buffer
			h.Marshal(&again)
		}
		cases = append(cases, c)
	}
	for _, m := range headerMutations(valid) {
		add(m)
	}

	write(t, filepath.Join(dir, "crypto.json"), map[string]any{
		"provenance": "oracle/go at 4c1507c, internal/pqcrypt/oracle_vectors_test.go",
		"frodo640shake": kemVectors(t, frodo, 8),
		"mlkem768":      kemVectors(t, ml, 8),
		"hybrid":        hybrids,
		"wrap":          wraps,
		"header_cases":  cases,
	})
}

func itoa(n int) string { return string(appendInt(nil, n)) }

func appendInt(b []byte, n int) []byte {
	if n >= 10 {
		b = appendInt(b, n/10)
	}
	return append(b, byte('0'+n%10))
}

// headerMutations returns valid headers plus a range of malformed ones.
func headerMutations(valid []byte) [][]byte {
	s := string(valid)
	introEnd := bytes.IndexByte(valid, '\n') + 1
	footer := bytes.LastIndex(valid, []byte("\n---")) + 1
	lines := bytes.SplitAfter(valid, []byte("\n"))
	join := func(ls [][]byte) []byte { return bytes.Join(ls, nil) }
	var out [][]byte
	push := func(b []byte) { out = append(out, append([]byte(nil), b...)) }
	push(valid)
	push(append(append([]byte(nil), valid...), []byte("payload\x00\x01")...))
	push([]byte(""))
	push([]byte("fury-encryption.org/v1\n--- " + s[len(s)-44:]))   // no stanzas
	push([]byte("fury-encryption.org/v2\n" + s[introEnd:]))         // wrong intro
	push([]byte("fury-encryption.org/v1" + s[introEnd:]))           // intro without newline
	push(valid[:footer])                                            // no footer
	push(valid[:len(valid)-1])                                      // footer without newline
	push(append(append([]byte(nil), valid[:len(valid)-1]...), '=', '\n')) // padded MAC
	push([]byte(s[:footer] + "---  " + s[footer+4:]))               // double space
	push([]byte(s[:footer] + "---x " + s[footer+4:]))               // bad footer prefix
	push([]byte(s[:footer] + "--- " + s[footer+4:len(s)-2] + "\n")) // short MAC
	push([]byte(s[:footer] + "--- " + s[footer+4:len(s)-1] + " x\n"))
	// Stanza line edits.
	stanza := lines[1]
	for _, edit := range []string{"-> \n", "->\n", "->  x\n", "-> x\x7f\n", "-> x é\n", "-x a\n", "-> x  y\n", "-> x\r\n"} {
		ls := append([][]byte(nil), lines...)
		ls[1] = []byte(edit)
		push(join(ls))
		_ = stanza
	}
	// Body edits: the body is the two lines after the stanza line.
	body := 2
	for _, edit := range []string{"\n", "AAAA\n", "AAAA=\n", "A\n", "AB\n", "AAB\n", "AA==\n", " AAAA\n", "AAAA\r\n",
		string(bytes.Repeat([]byte("A"), 64)) + "\n", string(bytes.Repeat([]byte("A"), 68)) + "\n", string(bytes.Repeat([]byte("A"), 65)) + "\n"} {
		ls := append([][]byte(nil), lines...)
		ls[body] = []byte(edit)
		push(join(ls))
	}
	{
		// Drop the empty line that ends a 48-byte body: the stanza then runs
		// into the footer.
		ls := append([][]byte(nil), lines...)
		ls = append(ls[:3], ls[4:]...)
		push(join(ls))
	}
	{
		// A second, foreign stanza ahead of the real one.
		ls := append([][]byte(nil), lines[:1]...)
		ls = append(ls, []byte("-> other-suite arg\n"), []byte("AAAA\n"))
		ls = append(ls, lines[1:]...)
		push(join(ls))
	}
	// The 1 MiB stanza and 16 MiB header limits are exercised by the Rust
	// tests directly; vectors that size would bloat the repository.
	return out
}

func write(t *testing.T, path string, v any) {
	b, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
