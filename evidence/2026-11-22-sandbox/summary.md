# Harness run 2026-11-22T13:01:16Z

Host: Linux 6.18.44-fc-v726 x86_64, 2 CPU · THREADS=16 OPS=500 RUNS=3

| Stage | Result | Log |
|---|---|---|
| Go go1.24.7 crypto/mlkem ML-KEM-768 (-race) | PASS | go.log |
| Go race-detector positive control (canary must be caught) | PASS | go-canary.log |
| Rust 1.97.0 ml-kem ML-KEM-768 (invariant) | PASS | rust.log |
| Rust TSan | SKIPPED | nightly toolchain not installed |
| Java BC 1.78.1 ML-DSA (invariant) | **FAIL** | java-ML-DSA.log |
| Java BC 1.78.1 DILITHIUM3 (invariant) | PASS | java-DILITHIUM3.log |
| Java BC 1.78.1 MLDSA65-Ed25519-SHA512 (invariant) | PASS | java-MLDSA65-Ed25519-SHA512.log |
| JCStress | SKIPPED | jcstress-core jar not in java/lib |
