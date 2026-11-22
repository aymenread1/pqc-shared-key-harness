# Results — shared PQC key across threads

**Run:** 2026-11-22 · Ubuntu 24.04 x86_64, **2 vCPU** · 16 threads × 500 ops × 3 runs per stage ·
logs in `evidence/2026-11-22-sandbox/`. Produced with `./run-all.sh` after the harness fixes below.

## Rows for the REPORT.md comparison table

| Stack | Library / version | Algorithm | Race detection | Positive control | Invariant (3 runs) | Verdict |
|---|---|---|---|---|---|---|
| Go 1.24.7 | `crypto/mlkem` (stdlib) | ML-KEM-768 | `-race`: no reports | canary caught (`DATA RACE`) | 0 mismatch, 0 fail | **Clean** — confirmatory baseline |
| Rust 1.97.0 | RustCrypto `ml-kem` 0.2.3 | ML-KEM-768 | TSan **pending** (nightly not available here) | written, pending | 0 mismatch, 0 fail | Clean on invariant; static audit: no shared mutable state |
| Java 21.0.13 | Bouncy Castle 1.78.1 | ML-DSA (plain FIPS 204) | — | — | **not runnable**: `NoSuchAlgorithmException` | Needs BC 1.79+ (pending) |
| Java 21.0.13 | Bouncy Castle 1.78.1 | Dilithium3 (round-3 precursor of ML-DSA-65) | none | — | 0 verifyFail, 0 opFail, 8000/8000 ran | Clean — **proxy only** |
| Java 21.0.13 | Bouncy Castle 1.78.1 | Composite MLDSA65-Ed25519-SHA512 | none | — | 0 verifyFail, 0 opFail, 8000/8000 ran | Clean — composite, draft-era ML-DSA |
| Java 21 | BC 1.81 + JCStress 0.16 | ML-DSA | JCStress **pending** | — | — | Run via Docker image |

No invariant violation and no race report in any stage that ran. These are baselines, not findings.

## Harness defects found and fixed (v1.0.0)

| # | Defect in the original | Effect | Fix |
|---|---|---|---|
| 1 | Go: documented `-run TestSharedKey` did not match `TestSharedDecapsulationKey` | **Silent false pass** (`[no tests to run]`, exit 0) | Test renamed `TestSharedKeyMLKEM768`; runner also fails on "no tests to run" and checks all G×N ops ran |
| 2 | Java header said BC "1.78+" | 1.78.x has no plain `ML-DSA` | Header says 1.79+; Docker pins 1.81; algorithm is a CLI argument |
| 3 | Java `try` wrapped the whole loop | First exception ended the thread; failures under-counted | `try/catch` per operation; prints first stack trace; asserts G×N ops ran |
| 4 | Rust unused import; `unwrap()` inside threads | Warning; a failure would panic instead of being counted | Import removed; errors counted in `fail` |
| 5 | No proof the race detector was active | A clean run could not be distinguished from a broken detector | Go and Rust canaries (deliberate data races) that **must** be caught |
| 6 | No JCStress test (README said "add separately") | Java had no race coverage | `java/jcstress/BcSharedKeyStress.java` |

## Rust static audit (pending TSan)

`ml-kem` 0.2.3: `encapsulate`/`decapsulate` take `&self`; no `UnsafeCell`, `Cell`, `RefCell`,
`Mutex`, atomics or `static mut` in the crate. Its `unsafe` blocks (`src/util.rs`) are local
`ptr::read` array splits over borrowed data. Keys are therefore `Sync` with no interior
mutability, consistent with the clean run. TSan is still required for the paper.

## What was and was not verified here

- Core count: the detectors are happens-before based, so 2 vCPU does not weaken the `-race`/TSan
  result; it only lowers the chance the invariant check observes corruption. 4 vCPU (GitHub runner) is sufficient.
- Verified: Go, Rust (stable) and Java (BC 1.78.1) stages; Go positive control; runner exit codes
  (0 on all-pass, 1 when any stage fails); JCStress test compiled with `-Xlint:all` against API
  stubs and its actor/arbiter logic run once with Dilithium3.
- **Not verified here** (Maven Central, static.rust-lang.org and the Docker daemon are unavailable
  in this sandbox): the Docker image build, BC 1.81 plain ML-DSA, Rust TSan + its canary, the real
  JCStress run. First `docker build` on a connected machine is the check for these.
