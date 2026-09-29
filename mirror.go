// Copyright 2026 The vault Authors.
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
)

var (
	// Attribute values in HTML, and url(...) in CSS: group 1 is everything
	// up to the URL, group 2 is the URL.
	htmlURLs = regexp.MustCompile(`(?i)(\b(?:href|src|action|poster)\s*=\s*["'])([^"']*)`)
	cssURLs  = regexp.MustCompile(`(?i)(url\(\s*["']?)([^"')\s]+)`)
)

// mirror crawls the site at rawURL, one request at a time, staying on its
// host, and adds every page and asset beneath dest/host. Links in HTML and
// CSS that point into the mirror are rewritten to relative paths, so the
// copy browses correctly once fetched out of the vault. A page that fails
// is reported and skipped.
// ponytail: regex rewriting, so links built by scripts or in srcset are left
// as they were; swap in golang.org/x/net/html if that matters.
func mirror(s *store, cat map[string][]*record, rawURL, dest string) error {
	start, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	host := strings.ToLower(start.Host)
	root := path.Join(dest, host)
	seen := map[string]bool{}
	queue := []*url.URL{start}
	seen[key(start)] = true

	for len(queue) > 0 {
		u := queue[0]
		queue = queue[1:]
		err := mirrorOne(s, cat, u, host, root, func(l *url.URL) {
			if k := key(l); !seen[k] {
				seen[k] = true
				queue = append(queue, l)
			}
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "skipping %s: %v\n", u, err)
		}
	}
	return nil
}

// key identifies a page independent of its fragment.
func key(u *url.URL) string {
	c := *u
	c.Fragment = ""
	return c.String()
}

// localPath is where u lives inside the mirror, relative to its root.
func localPath(u *url.URL) string {
	p := strings.TrimPrefix(u.Path, "/")
	if p == "" || strings.HasSuffix(p, "/") {
		p += "index.html"
	}
	if u.RawQuery != "" {
		p += "_" + url.QueryEscape(u.RawQuery)
	}
	return p
}

// relative gives the link from the file "from" to the file "to", both
// slash-separated paths relative to the same root.
func relative(from, to string) string {
	f := strings.Split(path.Dir(from), "/")
	t := strings.Split(to, "/")
	if f[0] == "." {
		f = nil
	}
	for len(f) > 0 && len(t) > 1 && f[0] == t[0] {
		f, t = f[1:], t[1:]
	}
	return strings.Repeat("../", len(f)) + strings.Join(t, "/")
}

func mirrorOne(s *store, cat map[string][]*record, u *url.URL, host, root string, enqueue func(*url.URL)) error {
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", chromeUA)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	self := localPath(u)
	// rewrite maps a link found in the page to a relative one, queueing it.
	rewrite := func(re *regexp.Regexp, text string) string {
		return re.ReplaceAllStringFunc(text, func(m string) string {
			sub := re.FindStringSubmatch(m)
			l, err := u.Parse(html.UnescapeString(sub[2]))
			if err != nil || (l.Scheme != "http" && l.Scheme != "https") || strings.ToLower(l.Host) != host {
				return m
			}
			frag := l.Fragment
			l.Fragment = ""
			if l.Path == "" && l.RawQuery == "" {
				l.Path = "/"
			}
			enqueue(l)
			r := relative(self, localPath(l))
			if frag != "" {
				r += "#" + frag
			}
			return sub[1] + r
		})
	}
	switch ct := strings.ToLower(resp.Header.Get("Content-Type")); {
	case strings.HasPrefix(ct, "text/html"):
		body = []byte(rewrite(cssURLs, rewrite(htmlURLs, string(body))))
	case strings.HasPrefix(ct, "text/css"):
		body = []byte(rewrite(cssURLs, string(body)))
	}

	tmp, err := os.CreateTemp("", "vault-mirror-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	if _, err := tmp.Write(body); err != nil {
		return err
	}
	return addOne(s, cat, tmp.Name(), path.Join(root, self), false)
}
