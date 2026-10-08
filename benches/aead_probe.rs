use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use std::time::Instant;
fn main() {
    let c = ChaCha20Poly1305::new(&Key::from([1u8; 32]));
    let mut buf = vec![0u8; 64 * 1024];
    let n = 1024; // 64 MiB
    let t = Instant::now();
    for i in 0..n {
        let mut nb = [0u8; 12];
        nb[3..11].copy_from_slice(&(i as u64).to_be_bytes());
        std::hint::black_box(c.encrypt_inout_detached(&Nonce::from(nb), &[], buf.as_mut_slice().into()).unwrap());
    }
    let s = t.elapsed().as_secs_f64();
    println!("raw seal: {:.0} MB/s", (n * 65536) as f64 / s / 1e6);
    let key = [1u8; 32];
    let data = vec![0u8; 64 << 20];
    let t = Instant::now();
    let mut out = Vec::with_capacity(data.len() + (1 << 20));
    vault::crypto::stream::seal_all(&key, &data, &mut out);
    println!("seal_all: {:.0} MB/s", data.len() as f64 / t.elapsed().as_secs_f64() / 1e6);
    let t = Instant::now();
    let n = vault::crypto::stream::open_all(&key, &mut out).unwrap();
    println!("open_all: {:.0} MB/s ({n})", data.len() as f64 / t.elapsed().as_secs_f64() / 1e6);
}
