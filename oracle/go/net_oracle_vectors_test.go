// SPDX-License-Identifier: GPL-3.0-or-later

// Test-only vector generator for the Rust port's URL handling and mirror
// link mapping; see oracle/gen-vectors.sh.

package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestOracleNetVectors(t *testing.T) {
	dir := os.Getenv("VAULT_ORACLE_OUT")
	if dir == "" {
		t.Skip("set VAULT_ORACLE_OUT to write vectors")
	}
	type parsed struct {
		Input    string `json:"input"`
		Err      bool   `json:"err"`
		String   string `json:"string,omitempty"`
		Scheme   string `json:"scheme,omitempty"`
		Host     string `json:"host,omitempty"`
		Hostname string `json:"hostname,omitempty"`
		Path     string `json:"path,omitempty"`
		RawQuery string `json:"raw_query,omitempty"`
		Fragment string `json:"fragment,omitempty"`
		Local    string `json:"local_path,omitempty"`
		Key      string `json:"key,omitempty"`
	}
	describe := func(in string, u *url.URL, err error) parsed {
		if err != nil {
			return parsed{Input: in, Err: true}
		}
		return parsed{Input: in, String: u.String(), Scheme: u.Scheme, Host: u.Host, Hostname: u.Hostname(), Path: u.Path,
			RawQuery: u.RawQuery, Fragment: u.Fragment, Local: localPath(u), Key: key(u)}
	}
	refs := []string{
		"", "a", "a/b", "./a", "../a", "../../../../a", "/a/./b/../c", "/", "//other.example/x", "//OTHER.example:8080",
		"?q=1", "?", "#frag", "a#f", "a?x=1&y=2#f", "/sp ace", "/%41%2fb", "/%zz", "/caf%C3%A9", "/café", "http://H.Example:80/A",
		"https://x/a/b/../../..", "HTTP://x", "mailto:a@b", "javascript:alert(1)", "ftp://x/y", "x:y", "a:b/c", "/a?b?c", "a/..",
		"a/.", ".", "..", "/a//b", "https://user:pw@x/p", "http://[::1]:8080/v6", "http://x:port/", "http://x:/p", "/a%20b?c%20d#e%20f",
		"http://x/\x01", "/a+b", "/q?a+b=c d", "#", "?#", "/p#a%23b", "//x/?", "http://x?only",
	}
	bases := []string{"http://h.example/dir/page.html?q=1#top", "https://h.example", "http://h.example:8080/a/b/", "http://h.example/a/b"}
	var parses []parsed
	for _, r := range refs {
		u, err := url.Parse(r)
		parses = append(parses, describe(r, u, err))
	}
	type resolved struct {
		Base   string `json:"base"`
		Ref    string `json:"ref"`
		Result parsed `json:"result"`
	}
	var resolves []resolved
	for _, b := range bases {
		bu, err := url.Parse(b)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range refs {
			u, err := bu.Parse(r)
			resolves = append(resolves, resolved{Base: b, Ref: r, Result: describe(r, u, err)})
		}
	}
	rels := [][2]string{{"index.html", "sub/p.html"}, {"sub/p.html", "index.html"}, {"sub/p.html", "img/a.png"}, {"a/b/c.html", "a/b/d.html"},
		{"a/b/c.html", "a/x/y/z.css"}, {"x.html", "x.html"}, {"a/b/", "a/c"}, {"s.css", "img/a.png"}, {"a/b/c", "a"}}
	var relOut [][3]string
	for _, p := range rels {
		relOut = append(relOut, [3]string{p[0], p[1], relative(p[0], p[1])})
	}
	escapes := map[string]string{}
	for _, s := range []string{"a=1&b=2", "x y", "é/?#", "~-_.!*'()", "a+b"} {
		escapes[s] = url.QueryEscape(s)
	}
	times := map[string]any{}
	for _, s := range []string{"Mon, 02 Jan 2006 15:04:05 GMT", "Monday, 02-Jan-06 15:04:05 GMT", "Mon Jan  2 15:04:05 2006", "Tue, 15 Nov 1994 08:12:31 GMT", "bogus", "Mon, 02 Jan 2006 15:04:05 UTC", "Mon Jan 12 15:04:05 2006"} {
		if tm, err := http.ParseTime(s); err == nil {
			times[s] = tm.Unix()
		} else {
			times[s] = nil
		}
	}
	b, _ := json.MarshalIndent(map[string]any{
		"provenance":   "oracle/go at 4c1507c, net_oracle_vectors_test.go",
		"parse":        parses,
		"resolve":      resolves,
		"relative":     relOut,
		"query_escape": escapes,
		"http_time":    times,
	}, "", " ")
	if err := os.WriteFile(filepath.Join(dir, "net.json"), append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
