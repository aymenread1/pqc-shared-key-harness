# Shared-key concurrency harnesses for PQC libraries

Each harness tests one thing: **a single post-quantum key object shared by many threads**.
It checks a correctness invariant (KEM shared secret matches / signature verifies) and,
where the language has one, runs under a race detector. A positive control (a deliberate
data race) proves the detector is actually active in the environment that produced the result.

| Path | Stack | Algorithm | Race detection | Positive control |
|---|---|---|---|---|
| `go/mlkem_race_test.go` | Go 1.24+ `crypto/mlkem` | ML-KEM-768 | `go test -race` | `go/canary_test.go` (build tag `canary`) |
| `rust/src/main.rs` | RustCrypto `ml-kem` 0.2 | ML-KEM-768 | ThreadSanitizer (nightly) | `rust/examples/canary.rs` |
| `java/BcSharedKeyTest.java` | Bouncy Castle 1.79+ | ML-DSA (any BC signature alg via argument) | none — invariant only | — |
| `java/jcstress/BcSharedKeyStress.java` | Bouncy Castle 1.79+ + JCStress 0.16 | ML-DSA | JCStress interleavings | — |

## Run — one command, fully pinned (recommended)

```sh
docker build -t pqc-harness .
docker run --rm -v "$PWD/results:/harness/results" pqc-harness
```

Pinned: Ubuntu 24.04, Go 1.24.7, Rust 1.97.0 + `nightly-2026-05-01`, OpenJDK 21,
Bouncy Castle 1.81, JCStress 0.16, `ml-kem` 0.2.3 (via `rust/Cargo.lock`).
In the image `RUST_TSAN=1` and `JCSTRESS=1`, so a missing stage is a **failure**, not a skip.
Change versions with `--build-arg GO_VERSION=… RUST_NIGHTLY=…` or `java/pom.xml`.

## Run — on your own machine

```sh
(cd java && mvn -q dependency:copy-dependencies -DoutputDirectory=lib)   # BC + JCStress jars
./run-all.sh
```

Knobs (environment variables): `THREADS` (16), `OPS` (500), `RUNS` (3),
`JAVA_ALGS` ("ML-DSA"; space-separated, e.g. `"ML-DSA DILITHIUM3"`),
`RUST_NIGHTLY` ("nightly"), `RUST_TSAN` / `JCSTRESS` (`auto` | `1` | `0`),
`JCSTRESS_MODE` (`sanity` | `quick` | `default` | `tough`).
Core count: the race detectors (`-race`, TSan) use happens-before analysis, so they flag an
unsynchronised access even on 2 cores. More cores only raise the chance that the *invariant*
check sees real corruption. 4+ cores is enough; `.github/workflows/harness.yml` runs everything
free on a GitHub-hosted runner (4 vCPU for public repositories).

Output: `results/<UTC timestamp>/summary.md` plus one log per stage.
Exit code 0 only if every stage that ran passed.

## Reading the results

- **PASS** on a harness = confirmatory baseline for the documented-safe pattern, not a discovery.
- **FAIL** on a harness = a candidate finding. Reproduce it, read the library's own threading
  documentation, and disclose responsibly before publishing.
- **FAIL** on a positive control = the race detector is not working; discard that run.

`evidence/2026-11-22-sandbox/` holds the logs from the first run (2 vCPU, no nightly,
Bouncy Castle 1.78.1 only); see `RESULTS.md`.

## License and citation

MIT — see `LICENSE`. Citation metadata in `CITATION.cff`.
Author: Ayman Alsadig Mohamed Suliman.
