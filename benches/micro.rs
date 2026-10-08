// SPDX-License-Identifier: GPL-3.0-or-later

//! The Rust side of scripts/bench.sh: the same operations as the Go
//! oracle's Benchmark* functions, timed as the median of repeated runs.
//! Run with `cargo bench --bench micro`.

use std::hint::black_box;
use std::io::{Read, Write};
use std::time::{Duration, Instant};
use vault::crypto::{fury, kem, stream};

fn pattern(n: usize, salt: u8) -> Vec<u8> {
    (0..n).map(|i| (i.wrapping_mul(7) as u8) ^ salt).collect()
}

/// Runs `f` until about two seconds have passed (at least 5 times) and
/// prints the median and the spread.
fn bench(name: &str, bytes: usize, mut f: impl FnMut()) {
    f(); // warm up
    let mut times = Vec::new();
    let start = Instant::now();
    while times.len() < 5 || (start.elapsed() < Duration::from_secs(2) && times.len() < 10_000) {
        let t = Instant::now();
        f();
        times.push(t.elapsed());
    }
    times.sort();
    let med = times[times.len() / 2];
    let (lo, hi) = (times[times.len() / 10], times[times.len() * 9 / 10]);
    let rate = if bytes > 0 {
        format!("  {:.0} MB/s", bytes as f64 / med.as_secs_f64() / 1e6)
    } else {
        String::new()
    };
    println!(
        "{name:<24} median {:>10.3} ms  (p10 {:.3}, p90 {:.3}, n={}){rate}",
        med.as_secs_f64() * 1e3,
        lo.as_secs_f64() * 1e3,
        hi.as_secs_f64() * 1e3,
        times.len()
    );
}

fn main() {
    let seed = pattern(32, 1);
    bench("derive", 0, || {
        black_box(kem::Identity::from_suite_seed(kem::SUITE_ID, &seed).unwrap());
    });
    let id = kem::Identity::from_suite_seed(kem::SUITE_ID, &seed).unwrap();
    let r = id.recipient();
    let fk: [u8; 32] = pattern(32, 2).try_into().unwrap();
    bench("wrap", 0, || {
        black_box(r.wrap(&fk, &mut vault::rng::os()));
    });
    let st = r.wrap(&fk, &mut vault::rng::os());
    bench("unwrap", 0, || {
        black_box(id.unwrap(std::slice::from_ref(&st)).unwrap());
    });
    let pt = pattern(4 << 20, 3);
    bench("object 4MiB", pt.len(), || {
        let mut ct = Vec::new();
        fury::encrypt_to(&mut ct, &r, &pt, &mut vault::rng::os());
        black_box(fury::decrypt_bounded(&ct[..], &id, pt.len()).unwrap());
    });
    let key = [0u8; 32];
    let big = vec![0u8; 64 << 20];
    bench("stream 64MiB", big.len(), || {
        let mut w = stream::StreamWriter::new(&key, Vec::with_capacity(big.len() + (1 << 16)));
        w.write_all(&big).unwrap();
        let ct = w.finish().unwrap();
        let mut out = Vec::with_capacity(big.len());
        stream::StreamReader::new(&key, &ct[..]).read_to_end(&mut out).unwrap();
        black_box(out);
    });
    let body = vault::keyfile::new_body(b"bench", b"", &mut vault::rng::os());
    bench("unlock", 0, || {
        black_box(vault::keyfile::unlock_body(&body, b"bench").unwrap());
    });
}
