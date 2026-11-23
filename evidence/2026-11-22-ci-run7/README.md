# CI run 7 (GitHub Actions run 45069564563), 22 Nov 2026

Inputs: THREADS=32 OPS=2000 RUNS=5 JCSTRESS_MODE=default; misuse stages 8 threads x 300 ops; sweep 3 runs per cell.
Result: every stage PASS (28 stages), including the scanner unit tests, all positive controls and JCStress.
Toolchains: Go 1.24.7, Rust 1.97.0 + nightly-2026-05-01, liboqs 0.14.0 (TSan), OpenSSL 3.5.4 (TSan),
Bouncy Castle 1.81 (pinned) and 1.87 (newest) on Java 21.0.13.1, JDK 25.0.5.1 own provider (SUN).

## Documented pattern (RQ1)
OpenSSL 3.5.4 shared EVP_PKEY, private ctx: 5 x 64,000 ML-DSA-65 and 5 x 64,000 ML-KEM-768, all correct, 0 TSan reports.
Go, CIRCL, liboqs, Rust and Bouncy Castle invariant stages repeat run 3: all PASS.

## One Signature object shared without a lock (RQ2), pooled; "unrequested" = valid on another caller's message, the empty message or a concatenation

| Provider | Mode | Threads | Msg bytes | Runs | Ops | Correct % | Exception % | Invalid % | Valid on another caller's message | Valid on unrequested message % (95% CI) | of which empty |
|---|---|---|---|---|---|---|---|---|---|---|---|
| BC 1.81 | shared | 8 | 32 | 8 | 19200 | 99.06 | 0.52 | 0.33 | 3 | 0.09 (0.06–0.15) | 9 |
| BC 1.81 | shared | 8 | 65536 | 8 | 19200 | 9.99 | 54.66 | 30.82 | 2 | 4.53 (4.25–4.83) | 868 |
| BC 1.81 | locked | 8 | 65536 | 5 | 12000 | 100.00 | 0.00 | 0.00 | 0 | 0.00 (0.00–0.03) | 0 |
| BC 1.87 | shared | 8 | 32 | 5 | 12000 | 95.65 | 3.47 | 0.78 | 4 | 0.11 (0.06–0.19) | 8 |
| BC 1.87 | shared | 8 | 65536 | 5 | 12000 | 9.51 | 56.27 | 29.78 | 0 | 4.43 (4.08–4.82) | 532 |
| BC 1.87 | locked | 8 | 65536 | 5 | 12000 | 100.00 | 0.00 | 0.00 | 0 | 0.00 (0.00–0.03) | 0 |
| JDK 25 (SUN) | shared | 8 | 32 | 8 | 19200 | 99.49 | 0.00 | 0.00 | 13 | 0.51 (0.41–0.62) | 46 |
| JDK 25 (SUN) | shared | 8 | 65536 | 8 | 19200 | 90.50 | 0.00 | 0.03 | 110 | 9.47 (9.07–9.90) | 1496 |
| JDK 25 (SUN) | locked | 8 | 65536 | 5 | 12000 | 100.00 | 0.00 | 0.00 | 0 | 0.00 (0.00–0.03) | 0 |

(8-thread rows pool the 5 main runs and the 3 sweep runs of the same cell.)

OpenSSL 3.5.4, one EVP_PKEY_CTX shared by 8 threads (ML-DSA-65, TSan build): run 3 of 5 never returned and was killed
after 300 s; 77 ThreadSanitizer reports; the one run whose result line was not interleaved with TSan output gave
2,400 calls: 0 correct, 2,397 errors, 3 invalid signatures, 0 valid on a wrong message.

## Dose-response sweep (3 runs per cell)

| Provider | Threads | Msg bytes | Ops | Not correct % | Valid unrequested % | empty |
|---|---|---|---|---|---|---|
| BC 1.81 | 2 | 32 | 1800 | 4.00 | 0.11 | 1 |
| BC 1.81 | 2 | 1024 | 1800 | 20.11 | 0.44 | 5 |
| BC 1.81 | 2 | 65536 | 1800 | 93.78 | 0.22 | 2 |
| BC 1.81 | 4 | 32 | 3600 | 2.78 | 0.08 | 2 |
| BC 1.81 | 4 | 1024 | 3600 | 14.47 | 0.44 | 12 |
| BC 1.81 | 4 | 65536 | 3600 | 95.00 | 0.78 | 27 |
| BC 1.81 | 8 | 1024 | 7200 | 6.79 | 0.74 | 51 |
| BC 1.81 | 16 | 32 | 14400 | 0.42 | 0.06 | 7 |
| BC 1.81 | 16 | 1024 | 14400 | 3.57 | 0.92 | 130 |
| BC 1.81 | 16 | 65536 | 14400 | 86.26 | 7.21 | 1034 |
| JDK 25 | 2 | 32 | 1800 | 2.17 | 2.17 | 15 |
| JDK 25 | 2 | 1024 | 1800 | 2.22 | 2.22 | 20 |
| JDK 25 | 2 | 65536 | 1800 | 22.67 | 22.67 | 346 |
| JDK 25 | 4 | 32 | 3600 | 0.78 | 0.78 | 16 |
| JDK 25 | 4 | 1024 | 3600 | 0.92 | 0.89 | 13 |
| JDK 25 | 4 | 65536 | 3600 | 15.50 | 15.47 | 467 |
| JDK 25 | 8 | 1024 | 7200 | 0.50 | 0.50 | 17 |
| JDK 25 | 16 | 32 | 14400 | 0.22 | 0.20 | 18 |
| JDK 25 | 16 | 1024 | 14400 | 0.19 | 0.19 | 14 |
| JDK 25 | 16 | 65536 | 14400 | 6.08 | 6.08 | 719 |

## Bank demo (8 tellers x 200 ISO 20022-like orders of 4 KB)

| Provider | Vulnerable: correct | error | rejected | other customer's order | unrequested (empty) | time | Fixed: correct | time |
|---|---|---|---|---|---|---|---|---|
| BC 1.81 | 921 | 334 | 316 | 0 | 29 (29) | 1,895 ms | 1600/1600 | 716 ms |
| BC 1.87 | 885 | 407 | 283 | 2 | 23 (23) | 1,805 ms | 1600/1600 | 664 ms |
| JDK 25 | 1590 | 0 | 0 | 0 | 10 (3) | 768 ms | 1600/1600 | 370 ms |
