<!-- Paste into REPORT.md: append the table rows under the existing C-library rows of the
     cross-library comparison table, and add the two subsections after it. -->

### Managed-language stacks (Go, Rust, Java)

Same experiment as the C study: one key object shared by many threads, correctness invariant
checked on every operation. Harness v1.0.0 (github.com/aymenread1/pqc-shared-key-harness), pinned
Docker image, GitHub Actions `ubuntu-24.04` runner (x86_64, 4 vCPU), 32 threads × 2,000 operations
× 5 runs = 320,000 operations per stage, 2026-11-22 (run #2; all seven stages passed). Each race-detector stage is paired with a
positive control (a deliberate data race) that must be caught.

| Library | Version | Algorithm | Detector | Positive control | Invariant violations | Race reports | Verdict |
|---|---|---|---|---|---|---|---|
| Go `crypto/mlkem` | Go 1.24.7 | ML-KEM-768 | `go test -race` | caught | 0 / 320,000 | 0 | Clean |
| RustCrypto `ml-kem` | 0.2.3 | ML-KEM-768 | ThreadSanitizer | caught | 0 / 320,000 | 0 | Clean |
| Bouncy Castle | 1.81 | ML-DSA | none (invariant) | — | 0 / 320,000 | n/a | Clean |
| Bouncy Castle | 1.81 | ML-DSA | JCStress 0.16 | — | 0 FORBIDDEN outcomes | n/a | Clean |

#### Interpretation

The managed-language libraries expose PQC keys as values that are immutable after generation
(Go: methods on an immutable key; Rust: `&self` methods with no interior mutability; Bouncy Castle:
per-operation `Signature` objects over a shared `PrivateKey`). No stage produced an invariant
violation or race report, so these rows are confirmatory baselines for the documented-safe pattern,
not findings.

#### Threats to validity

- Bouncy Castle has no race detector; Java evidence is the invariant run plus JCStress.
- A 4-vCPU runner bounds true parallelism for the invariant checks; the race detectors are
  happens-before based and do not depend on core count.
- The original Go command produced a silent false pass (`[no tests to run]`); it was fixed, and
  positive controls ensure a broken detector cannot yield a "clean" row.
