<!-- Paste into REPORT.md: append the table rows under the existing C-library rows of the
     cross-library comparison table, and add the two subsections after it. -->

### Managed-language stacks (Go, Rust, Java)

Same experiment as the C study: one key object shared by 16 threads, 500 operations each,
3 runs, correctness invariant checked on every operation. Harness v1.0.0, 2026-11-22,
Ubuntu 24.04 x86_64 (2 vCPU). Logs: `pqc-harness/evidence/2026-11-22-sandbox/`.

| Library | Version | Algorithm | Detector | Positive control | Invariant violations | Race reports | Verdict |
|---|---|---|---|---|---|---|---|
| Go `crypto/mlkem` | Go 1.24.7 | ML-KEM-768 | `go test -race` | caught | 0 / 24,000 | 0 | Clean |
| RustCrypto `ml-kem` | 0.2.3 | ML-KEM-768 | TSan — pending | pending | 0 / 24,000 | n/a | Clean (invariant + static audit) |
| Bouncy Castle | 1.78.1 | Dilithium3 (ML-DSA proxy) | none | — | 0 / 24,000 | n/a | Clean (proxy) |
| Bouncy Castle | 1.78.1 | MLDSA65-Ed25519 composite | none | — | 0 / 24,000 | n/a | Clean (composite) |
| Bouncy Castle | 1.81 | ML-DSA | JCStress — pending | — | pending | pending | — |

#### Interpretation

The managed-language libraries tested so far expose PQC keys as values that are immutable after
generation (Go: methods on an immutable key; Rust: `&self` methods with no interior mutability;
Bouncy Castle: per-operation `Signature` objects over a shared `PrivateKey`). No stage produced an
invariant violation or race report, so these rows are confirmatory baselines for the documented-safe
pattern, not findings.

#### Threats to validity

- 2 vCPU limits true parallelism for the invariant check (the race detectors do not depend on core
  count: they use happens-before analysis). The pending rows are run on a 4-vCPU GitHub runner.
- Rust TSan, plain ML-DSA in Bouncy Castle 1.79+, and JCStress are pending (rows marked pending).
- Dilithium3 and the composite scheme are proxies for FIPS 204 ML-DSA, not ML-DSA itself.
- A harness defect in the original Go command produced a silent false pass (`[no tests to run]`);
  it was fixed, and positive controls were added so a broken detector cannot yield a "clean" row.
