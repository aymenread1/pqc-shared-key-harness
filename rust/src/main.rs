// Rust portable harness: shared ML-KEM key across threads.
// Author: Ayman Alsadig Mohamed Suliman
// Cargo.toml deps:  ml-kem = "0.2"   rand = "0.8"
// RUN (invariant only):  cargo run --release
// RUN under the thread sanitizer (nightly + rust-src):
//   RUSTFLAGS="-Zsanitizer=thread" cargo +nightly run --release -Zbuild-std \
//     --target x86_64-unknown-linux-gnu
// THREADS / OPS env vars override the defaults 16 / 500.
// Invariant: every encapsulation decapsulates to the same shared secret.
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{KemCore, MlKem768};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::thread;

fn env_usize(name: &str, def: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&v| v > 0)
        .unwrap_or(def)
}

fn main() {
    let mut rng = rand::thread_rng();
    let (dk, ek) = MlKem768::generate(&mut rng);
    let dk = Arc::new(dk); // shared decapsulation key
    let ek = Arc::new(ek); // shared encapsulation key
    let mism = Arc::new(AtomicU64::new(0));
    let fail = Arc::new(AtomicU64::new(0));
    let (g, n) = (env_usize("THREADS", 16), env_usize("OPS", 500));
    let mut handles = vec![];
    for _ in 0..g {
        let (dk, ek, mism, fail) = (dk.clone(), ek.clone(), mism.clone(), fail.clone());
        handles.push(thread::spawn(move || {
            let mut rng = rand::thread_rng();
            for _ in 0..n {
                let (ct, ss1) = match ek.encapsulate(&mut rng) {
                    Ok(v) => v,
                    Err(_) => { fail.fetch_add(1, Ordering::Relaxed); continue; }
                };
                match dk.decapsulate(&ct) {
                    Ok(ss2) if ss2 == ss1 => {}
                    Ok(_) => { mism.fetch_add(1, Ordering::Relaxed); }
                    Err(_) => { fail.fetch_add(1, Ordering::Relaxed); }
                }
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let (m, f) = (mism.load(Ordering::Relaxed), fail.load(Ordering::Relaxed));
    println!("shared-key ML-KEM-768: {g} threads x {n} ops, mismatch={m} fail={f}");
    assert!(m == 0 && f == 0, "INVARIANT VIOLATION (also read the TSan output)");
}
