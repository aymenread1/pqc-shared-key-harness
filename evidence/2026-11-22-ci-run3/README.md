# CI run #3 — measured numbers (copied from the job summary)

Run: https://github.com/aymenread1/pqc-shared-key-harness/actions/runs/45052840281 (commit d2456a0)
Host: Linux 7.0.0-1017-azure x86_64, 4 CPU · THREADS=32 OPS=2000 RUNS=5 · all 13 stages PASS.

## Documented-safe pattern (shared key, 320,000 ops per library and algorithm)
- Go crypto/mlkem ML-KEM-768 (-race): 5 x (32 goroutines x 2000), 0 mismatch, 0 fail
- Go CIRCL ML-DSA-65 (-race): 5 x (32 x 2000), 0 bad; ML-KEM-768: 0 mismatch, 0 fail
- C liboqs 0.14.0 (TSan, shared OQS_SIG/OQS_KEM objects + keys): ML-DSA-65 ok=64000/64000 x5; ML-KEM-768 ok=64000/64000 x5
- Rust ml-kem 0.2.3 ML-KEM-768 (stable + TSan): 0 mismatch, 0 fail x5 each
- Java BC 1.81 ML-DSA: 64000/64000 x5, verifyFail=0 opFail=0
- JCStress BC 1.81 ML-DSA shared key: PASS
- Positive controls (Go, C, Rust TSan canaries): all caught

## Misuse: ONE BC 1.81 ML-DSA JCA Signature object shared by 8 threads, no lock (300 iterations, 2400 ops per run)
| msg bytes | run | ok | loud | invalid | crossValid | mixedValid | of which empty msg |
|---|---|---|---|---|---|---|---|
| 32 | 1 | 2381 | 11 | 7 | 1 | 0 | 0 |
| 32 | 2 | 2378 | 12 | 8 | 0 | 2 | 1 |
| 32 | 3 | 2376 | 12 | 9 | 0 | 3 | 2 |
| 32 | 4 | 2379 | 11 | 8 | 0 | 2 | 2 |
| 32 | 5 | 2381 | 10 | 8 | 0 | 1 | 1 |
| 65536 | 1 | 211 | 1409 | 690 | 2 | 88 | 88 |
| 65536 | 2 | 249 | 1406 | 664 | 0 | 81 | 81 |
| 65536 | 3 | 205 | 1404 | 700 | 0 | 91 | 91 |
| 65536 | 4 | 251 | 1396 | 674 | 0 | 79 | 79 |
| 65536 | 5 | 205 | 1421 | 688 | 0 | 86 | 86 |
| 65536 locked (control) | 1-5 | 2400 | 0 | 0 | 0 | 0 | 0 |

Exceptions observed (first per run): IllegalStateException "attempt to absorb while squeezing",
"attempt to absorb with odd length queue", ArrayIndexOutOfBoundsException "arraycopy: length -168 is
negative", "Index 536870778 out of bounds for length 192", "last source index 302 out of bounds for byte[192]".
These are corrupted internal SHAKE/Keccak sponge states, i.e. per-call hashing state lives inside the
shared object.
