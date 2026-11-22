# Results — shared PQC key across threads

Two environments, same harness (v1.0.0):

- **CI (main result):** GitHub Actions, `ubuntu-24.04` runner, Linux x86_64, **4 vCPU**, pinned Docker
  image · **32 threads × 2000 ops × 5 runs = 320,000 operations per stage** ·
  runs [#1](https://github.com/aymenread1/pqc-shared-key-harness/actions/runs/45027833600) and
  [#2](https://github.com/aymenread1/pqc-shared-key-harness/actions/runs/45029276655), 2026-11-22.
- **Sandbox (first pass):** Ubuntu 24.04, 2 vCPU, no nightly, Bouncy Castle 1.78.1 only · 16 × 500 × 3 ·
  logs in `evidence/2026-11-22-sandbox/`.

## Rows for the REPORT.md comparison table (CI)

| Stack | Library / version | Algorithm | Race detection | Positive control | Invariant (320,000 ops) | Verdict |
|---|---|---|---|---|---|---|
| Go 1.24.7 | `crypto/mlkem` (stdlib) | ML-KEM-768 | `go test -race`: no reports | canary caught | 0 violations | **Clean** |
| Rust 1.97.0 | RustCrypto `ml-kem` 0.2.3 | ML-KEM-768 | — (stable build) | — | 0 violations | **Clean** |
| Rust nightly-2026-05-01 | RustCrypto `ml-kem` 0.2.3 | ML-KEM-768 | ThreadSanitizer: no reports | canary caught | 0 violations | **Clean** |
| Java 21 | Bouncy Castle **1.81** | **ML-DSA** (FIPS 204) | none (invariant only) | — | 0 verifyFail, 0 opFail | **Clean** |
| Java 21 | Bouncy Castle 1.81 + JCStress 0.16 | ML-DSA | JCStress interleavings: no FORBIDDEN outcome | — | test passed (0 failed, 0 errors) | **Clean** |

**Run #2: all 7 stages PASS.** Run #1: the same 6 stages PASS, JCStress failed (harness defect, see
note). The positive controls prove both race detectors were active. These are confirmatory baselines for the documented-safe pattern, not findings.

**JCStress note.** Run #1 failed at the JCStress stage before running any test (harness defect, not a
library result; most likely the test class in the default package). Fixed in run #2 by moving the test
to package `pqc.jcstress`; in run #2 JCStress ran for about 11 minutes and passed (the runner requires
the summary line to show at least one test passed with 0 failed, 0 soft and 0 hard errors).

## Sandbox rows (first pass, superseded by CI)

| Stack | Library / version | Algorithm | Result |
|---|---|---|---|
| Go 1.24.7 | `crypto/mlkem` | ML-KEM-768 | 0 mismatch / 24,000; `-race` clean; canary caught |
| Rust 1.97.0 | `ml-kem` 0.2.3 | ML-KEM-768 | 0 mismatch / 24,000 (no TSan) |
| Java 21.0.13 | Bouncy Castle 1.78.1 | ML-DSA | not runnable (`NoSuchAlgorithmException`, needs 1.79+) |
| Java 21.0.13 | Bouncy Castle 1.78.1 | Dilithium3 / MLDSA65-Ed25519 | 0 failures / 24,000 each (proxies) |

## Harness defects found and fixed (v1.0.0)

| # | Defect in the original | Effect | Fix |
|---|---|---|---|
| 1 | Go: documented `-run TestSharedKey` did not match `TestSharedDecapsulationKey` | **Silent false pass** (`[no tests to run]`, exit 0) | Test renamed `TestSharedKeyMLKEM768`; runner also fails on "no tests to run" and checks all G×N ops ran |
| 2 | Java header said BC "1.78+" | 1.78.x has no plain `ML-DSA` | Header says 1.79+; Docker pins 1.81; algorithm is a CLI argument |
| 3 | Java `try` wrapped the whole loop | First exception ended the thread; failures under-counted | `try/catch` per operation; prints first stack trace; asserts G×N ops ran |
| 4 | Rust unused import; `unwrap()` inside threads | Warning; a failure would panic instead of being counted | Import removed; errors counted in `fail` |
| 5 | No proof the race detector was active | A clean run could not be distinguished from a broken detector | Go and Rust canaries (deliberate data races) that **must** be caught |
| 6 | No JCStress test (README said "add separately") | Java had no race coverage | `java/jcstress/BcSharedKeyStress.java` (in package `pqc.jcstress`) |
| 7 | Runner hid failing logs in files only | CI failure reason invisible in the job log | Runner prints the last 60 lines of any failing stage |

## Rust static audit

`ml-kem` 0.2.3: `encapsulate`/`decapsulate` take `&self`; no `UnsafeCell`, `Cell`, `RefCell`,
`Mutex`, atomics or `static mut` in the crate. Its `unsafe` blocks (`src/util.rs`) are local
`ptr::read` array splits over borrowed data. Consistent with the clean TSan run.

## Notes on validity

- Race detectors (`-race`, TSan) are happens-before based; core count does not weaken them. 4 vCPU
  gives real parallelism for the invariant checks.
- Bouncy Castle has no race detector; the invariant run plus JCStress is the Java evidence.
