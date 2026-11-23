# Prevalence of thread-shared JCA engine objects in public Java code

Frozen sampling frame: `repos-2026-11-22.txt` (GitHub repository search, 22 Nov 2026).
Scanner: `scanner/pqc_share_scan.py` (with import resolution; 14 unit tests). Runner: `run_prevalence.py`.
Triage context: `triage_context.py`; verdicts: `triage/triage.csv` (one reviewer, preliminary; a second reviewer is planned).
Data: `out/repos.csv` (every repository and its counts) and `out/findings.csv` (every finding with the commit scanned, first 12 hex digits; test code flagged).

## Corpus

| Frame | Definition | Scanned | Use JCA engines (any `getInstance`) | Already use a PQC algorithm |
|---|---|---|---|---|
| top | 200 most-starred non-archived Java repositories (stars > 3000) | 198 (2 skipped: > 3 GB) | 111 | 6 |
| crypto | top results of 14 security queries (bouncycastle, digital signature, PKI, JWT, PDF signature, payment, cryptography, XAdES, ZATCA, e-invoice, keystore, encryption library, blockchain wallet, SAML), deduplicated | 312 | 168 | 8 |
| total | | 510 repositories, 631,703 Java files | 279 | 14 |

## Findings in non-test code

| Tier | Findings | Repositories |
|---|---|---|
| HIGH (static field, singleton field or singleton `@Bean`) | 21 | 18 |
| MEDIUM (plain instance field) | 283 | 74 |

## Triage of all 21 HIGH findings

| Verdict | Findings |
|---|---|
| Shared and unprotected, reachable from concurrent callers (web servers, libraries, frameworks, apps) | 9 |
| Shared and unprotected, concurrency not evident (CLI tool, sample/educational code) | 4 |
| Protected by the wrong lock (synchronized instance method guarding a static digest) | 1 |
| Protected correctly (synchronized) | 2 |
| Safe by design (prototype that is cloned per use) | 4 |
| Only initialised in the file (use not established) | 1 |

- Shared and not (correctly) protected: 14 of 21 HIGH findings, precision 66.7% (95% CI 45.4 to 82.8).
- Repositories with at least one such object: 13 of 510 (2.55%, 95% CI 1.50 to 4.31); 13 of the 279 that use JCA engines (4.66%, 2.74 to 7.81).
- Types involved: 7 `MessageDigest`, 7 `Cipher`. No HIGH finding involves `Signature` or a post-quantum algorithm.

## MEDIUM: random sample of 40 (seed 20261122)

| Verdict | Findings |
|---|---|
| Confined by design (stream, session or SPI object owned by one caller) | 31 |
| Possibly shared, needs deeper review (e.g. authentication plug-in instance serving concurrent requests) | 6 |
| Protected (synchronized) | 3 |

## Early post-quantum adopters

14 repositories already name ML-DSA, ML-KEM, SLH-DSA or HSS/LMS (Keycloak, Quarkus, Vert.x, GraalVM, OpenJDK, Conscrypt,
Amazon Corretto Crypto Provider, Keyfactor SignServer and EJBCA, Dogtag PKI, Demoiselle Signer, KeyStore Explorer, Peergos,
Baeldung tutorials). None has a HIGH finding on a `Signature`. Dogtag's signed audit log keeps one streaming `Signature`
in a logger shared by all threads and guards every update and sign with `synchronized`: the safe version of the exact
pattern that fails silently without the lock.

## Reading

The anti-pattern is uncommon but real, and it lives where migrations happen: static crypto utility classes
(`EncryptUtils`, `MD5Utils`, `Hash`) in web applications and libraries. Today these hold digests and ciphers; a migration
that swaps the algorithm string inside the same utility moves ML-DSA into the failure mode measured in Section 5.
