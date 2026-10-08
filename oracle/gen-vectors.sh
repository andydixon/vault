#!/usr/bin/env bash
# Regenerate the Go-oracle vectors and fixtures in tests/vectors.
#
# Everything is computed by the frozen Go implementation in oracle/go (see
# oracle/README.md); nothing comes from the Rust code under test. Key files
# and ciphertexts use fresh randomness, so regenerating changes them; the
# deterministic vectors (*.json fields derived from fixed seeds) do not.
set -euo pipefail
cd "$(dirname "$0")/.."
out=$PWD/tests/vectors
mkdir -p "$out"
(cd oracle/go && VAULT_ORACLE_OUT=$out go test -count=1 -run '^TestOracleVectors$' ./ ./internal/pqcrypt ./internal/stream)
(cd oracle/go && VAULT_ORACLE_OUT=$out go test -count=1 -run '^TestOracleNetVectors$' ./)
echo "vectors written to $out"
