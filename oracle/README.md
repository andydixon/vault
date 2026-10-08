# Go oracle (test-only)

`oracle/go` is a frozen copy of the Go implementation of vault, taken from
commit `4c1507c` ("Add unlock --idle, and packaging/repo.sh for
repo.dixon.cx"), the last Go release on `master`. It is kept as the
reference that the Rust implementation is checked against. It is **not**
part of the shipped product: release builds, packages and the `vault`
binary contain no Go code and need no Go toolchain.

Provenance:

- All 32 Go sources and `go.mod`/`go.sum` under `oracle/go` are
  byte-identical to the same paths at the repository root at `4c1507c`.
- The only additions are test files whose names contain `oracle`
  (`*oracle_vectors_test.go`, `oracle_decrypt_test.go`,
  `*oracle_bench_test.go`). They call the frozen code and record what it
  computes; they skip themselves unless `VAULT_ORACLE_OUT` or
  `VAULT_ORACLE_DECRYPT` is set (benchmarks run only with `-bench`), and add
  nothing to the oracle binary.
- Dependencies are pinned by `go.mod`/`go.sum`: CIRCL v1.6.4,
  golang.org/x/crypto v0.53.0, x/sys v0.46.0, x/term v0.44.0. The module
  needs Go 1.26.6 or newer.

Check the copy is still faithful:

```sh
for f in $(git ls-tree -r --name-only 4c1507c | grep -E '\.go$|^go\.(mod|sum)$'); do
	cmp <(git show 4c1507c:$f) oracle/go/$f || echo "DIFFERS: $f"
done
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
