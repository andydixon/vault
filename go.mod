module github.com/andydixon/vault

// Go 1.26.6 or newer is a security requirement inherited from the crypto
// library: the standard-library fixes it relies on exist only from that
// release.
go 1.26.6

require (
	github.com/cloudflare/circl v1.6.4
	golang.org/x/crypto v0.53.0
	golang.org/x/sys v0.46.0
	golang.org/x/term v0.44.0
)
