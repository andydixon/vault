# Benchmarks: Go 0.5 against Rust 0.6

Measured on 2026-10-08 on one machine: Intel Core i7-7700 (4 cores, 8
threads), 31 GiB RAM, ext4 on a two-disk RAID 1 (`/dev/md2`), Linux 7.0.
Both binaries were built from this tree: the Go oracle (`oracle/go`, Go
1.27.1, `CGO_ENABLED=0`) and the Rust release build (Rust 1.99.0, LTO).

**Limitation:** the machine was shared. Other users' Docker builds kept the
load average between 4 and 12 throughout, so absolute times are noisy.
Go and Rust were run alternately under the same conditions, and every
figure is a median with its spread, but small differences mean nothing.
Page caches were warm (dropping them needs root), so cold-cache numbers
were not measured.

## Primitives

`cargo bench --bench micro` and
`(cd oracle/go && go test -run XXX -bench Oracle -benchtime 2s ./ ./internal/pqcrypt ./internal/stream)`,
run alternately twice (load 4.4 to 5.4). Medians in milliseconds; the Rust
harness's p10 to p90 range is in brackets.

| Operation | Go | Rust |
| --- | --- | --- |
| Derive hybrid identity from seed | 5.6 | 3.0 (2.9 to 4.6) |
| Wrap file key (both encapsulations) | 7.4 to 8.0 | 3.1 (3.0 to 4.8) |
| Unwrap file key (both decapsulations) | 7.6 to 8.3 | 3.1 (3.0 to 3.6) |
| Encrypt and decrypt one 4 MiB object | 19.9 to 20.1 | 19.0 to 19.5 |
| STREAM seal and open, 64 MiB, streaming API | 89 to 92 | 187 to 188 |
| Unlock key file (Argon2id for both slots) | 121 to 125 | 129 (125 to 147) |

- The FrodoKEM port is about twice as fast as CIRCL's Go code, mostly from
  multiplying A row by row instead of walking it by column.
- ChaCha20-Poly1305 is slower: RustCrypto reaches about 1.2 GB/s on this CPU
  (`cargo bench --bench aead_probe`), Go's assembly about twice that. The
  64 MiB row uses the streaming reader and writer, which copy through
  64 KiB buffers. The vault itself uses the in-memory path (`seal_all`
  0.85 GB/s, `open_all` 1.4 GB/s), and per 4 MiB object the two are
  level because the KEM work is cheaper.
- Unlock takes 180 ms with Argon2id lanes computed in turn. Computing the
  four lanes in parallel (argon2's `parallel` feature) brings it to 129 ms,
  close to Go. The parameters are unchanged.

## End to end

`RUNS=3 BIG_MB=1024 SMALL=500 scripts/bench.sh` (load 8 to 13). Every step
includes unlocking the key. The 1 GiB file and the 500 small files (1 to
16 KiB each) are each added to a fresh vault. The reads use one vault
holding both, plus filler. Times are medians of 3 (min to max).

| Step | Go | Rust |
| --- | --- | --- |
| add 1 GiB file | 41.7 s (32.0 to 50.3) | 29.6 s (28.5 to 31.0) |
| add 500 small files | 123.9 s (113.3 to 156.2) | 79.0 s (77.3 to 133.3) |
| get 1 GiB file | 9.8 s (8.8 to 10.0) | 16.2 s (15.5 to 16.7) |
| list (about 530 records) | 4.95 s (4.89 to 5.20) | 0.74 s (0.71 to 0.77) |
| get one small file | 5.24 s (4.88 to 6.00) | 0.74 s (0.70 to 0.81) |
| Peak RSS | 137 to 140 MiB | 132 MiB |
| Peak threads | 18 | 17 |
| Binary size | 11.5 MB | 3.5 MB (static musl: 3.4 MB) |

- **Catalogue reads** (`list`, and every command that looks a name up) are
  about 6 times faster. Records are decrypted in parallel on the worker pool
  (bounded at twice the worker count in flight), and each FrodoKEM
  decapsulation is cheaper.
- **Adds** are faster. Both implementations fsync every object, its shard
  directory and every record. Rust overlaps up to eight objects' encryption
  and syncs on the pool.
- **`get` of a large file is slower, on purpose.** Rust fsyncs the output
  file before giving it its name, so a crash just after `get` cannot leave
  the name pointing at an empty or partial file. Go did not. On an idle
  rerun (load about 8, output on the same disk), Go took 3.6 s and Rust
  15.5 s. Of Rust's time, 13.3 s was the single `fsync` of 1 GiB of
  freshly written data (measured with `strace -T`). The other 2 s or so is
  unlock, decryption and writing. This is the cost of the
  durability barrier on this RAID 1 array, and it scales with the disk's
  write speed.
- Peak memory is dominated by Argon2id: 64 MiB for each of the two slots,
  computed at the same time in both implementations. Rust's object pipeline
  adds at most eight 4 MiB plaintext buffers and their ciphertexts. Peak
  threads: Rust has 8 workers, 8 Argon2 threads while unlocking, and the
  main thread.

Reproduce with `scripts/bench.sh` (it builds both binaries, creates
synthetic data in `target/bench`, and prints the tables' numbers) and the
two micro-benchmark commands above.
