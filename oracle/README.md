# Go oracle (test-only)

`oracle/go` is a frozen copy of the Go implementation of vault, taken from
commit `4c1507c` ("Add unlock --idle, and packaging/repo.sh for
repo.dixon.cx"), the last Go release on `master`. It is kept as the
reference that the Rust implementation is checked against. It is **not**
part of the shipped product: release builds, packages and the `vault`
binary contain no Go code and need no Go toolchain.

Provenance:

- Every file under `oracle/go` is byte-identical to the same path at the
  repository root at `4c1507c`, except the three added test files below.
- `oracle_vectors_test.go`, `internal/pqcrypt/oracle_vectors_test.go` and
  `internal/stream/oracle_vectors_test.go` are test-only generators. They
  call the frozen code and write what it computes; they skip themselves
  unless `VAULT_ORACLE_OUT` is set, and add nothing to the oracle binary.
- Dependencies are pinned by `go.mod`/`go.sum`: CIRCL v1.6.4,
  golang.org/x/crypto v0.53.0, x/sys v0.46.0, x/term v0.44.0. The module
  needs Go 1.26.6 or newer.

Check the copy is still faithful:

```sh
git diff --stat 4c1507c HEAD -M -- oracle/go   # renames only, plus the generators
```

Use:

```sh
oracle/gen-vectors.sh          # rewrite tests/vectors from the oracle
(cd oracle/go && go build -o ../../target/vault-go .)   # build the oracle CLI
(cd oracle/go && go test ./...)                          # its own test-suite
```

`cargo test` builds the oracle binary itself for the interoperability tests
when `go` is on `PATH` (or uses `$VAULT_GO_ORACLE`), and reports them as
skipped otherwise.

All passphrases, seeds and plaintexts in the vectors are synthetic and
public (`oracle-real passphrase`, `oracle-decoy passphrase`, fixed byte
patterns). Never commit real keys or real vault contents.
