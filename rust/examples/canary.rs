// Positive control for ThreadSanitizer: a deliberate data race.
// Under -Zsanitizer=thread this MUST print "WARNING: ThreadSanitizer: data race".
static mut SHARED: u64 = 0;

fn main() {
    let hs: Vec<_> = (0..4)
        .map(|_| {
            std::thread::spawn(|| {
                for _ in 0..1000 {
                    unsafe {
                        let p = std::ptr::addr_of_mut!(SHARED);
                        *p += 1; // unsynchronised read-modify-write
                    }
                }
            })
        })
        .collect();
    for h in hs {
        h.join().unwrap();
    }
    println!("canary done: {}", unsafe { *std::ptr::addr_of!(SHARED) });
}
