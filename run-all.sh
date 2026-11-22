#!/usr/bin/env bash
# Runs every harness, writes logs to results/<timestamp>/ and prints a summary table.
# Env: THREADS (16) OPS (500) RUNS (3) JAVA_ALGS ("ML-DSA") RUST_TSAN (auto|0|1) JCSTRESS (auto|0|1)
#      RUST_NIGHTLY (toolchain name, default "nightly") JCSTRESS_MODE (sanity|quick|default|tough; default "default")
#      LIBOQS (auto|0|1) LIBOQS_PREFIX (/opt/liboqs-tsan) CIRCL (auto|0|1)
#      OPENSSL (auto|0|1) OPENSSL_PREFIX (/opt/openssl-tsan) JDK25 (auto|0|1) JDK25_HOME (/opt/jdk25)
#      MISUSE_SIZES ("32 65536") message sizes for the shared-Signature misuse study
#      SWEEP_THREADS ("2 4 8 16") SWEEP_SIZES ("32 1024 65536") SWEEP_RUNS (3) misuse dose-response sweep
#      auto = run if the tool is present, else SKIPPED; 1 = missing tool is a FAIL; 0 = never run
# Exit code: 0 = every stage that ran passed; 1 = any stage failed. Skipped stages are listed.
set -uo pipefail
cd "$(dirname "$0")" || exit 1
ROOT=$PWD
export THREADS=${THREADS:-16} OPS=${OPS:-500}
RUNS=${RUNS:-3}
JAVA_ALGS=${JAVA_ALGS:-ML-DSA}
NIGHTLY=${RUST_NIGHTLY:-nightly}
JCSTRESS_MODE=${JCSTRESS_MODE:-default}
LIBOQS_PREFIX=${LIBOQS_PREFIX:-/opt/liboqs-tsan}
MISUSE_SIZES=${MISUSE_SIZES:-32 65536}
OPENSSL_PREFIX=${OPENSSL_PREFIX:-/opt/openssl-tsan}
JDK25_HOME=${JDK25_HOME:-/opt/jdk25}
SWEEP_THREADS=${SWEEP_THREADS:-2 4 8 16}
SWEEP_SIZES=${SWEEP_SIZES:-32 1024 65536}
SWEEP_RUNS=${SWEEP_RUNS:-3}
OUT="$ROOT/results/$(date -u +%Y%m%dT%H%M%SZ)"; mkdir -p "$OUT"
SUMMARY="$OUT/summary.md"; DETAILS="$OUT/details.txt"; FAILED=0; : > "$DETAILS"
row() { printf '| %s | %s | %s |\n' "$1" "$2" "$3" | tee -a "$SUMMARY"; }

{
  echo "# Harness run $(date -u +%FT%TZ)"
  echo
  echo "Host: $(uname -srm), $(nproc) CPU · THREADS=$THREADS OPS=$OPS RUNS=$RUNS"
  echo
  echo '| Stage | Result | Log |'
  echo '|---|---|---|'
} > "$SUMMARY"

stage() { # name logfile cmd...
  local name=$1 log=$2; shift 2
  local rc=0; ( "$@" ) >"$OUT/$log" 2>&1 || rc=1
  # keep the measured numbers visible in the CI summary, not only inside the log files
  grep -hE '^RESULT|^SPI |^DEMO_JSON|shared-key [A-Za-z]|INVARIANT|CONTROL|HARNESS ERROR|first exception' "$OUT/$log" \
    | sed "s/^ *//; s/^/[$log] /" | tee -a "$DETAILS" || true
  if [ "$rc" = 0 ]; then row "$name" PASS "$log"
  else
    row "$name" "**FAIL**" "$log"; FAILED=1
    # show why in the console too (CI job logs), not only in the log file
    echo "----- last 60 lines of $log -----"; tail -n 60 "$OUT/$log"; echo "----- end $log -----"
  fi
}

# ---- Go ----------------------------------------------------------------------
if command -v go >/dev/null; then
  go_run() {
    cd "$ROOT/go" && go version && go test -race -count="$RUNS" -run TestSharedKey -v ./... || return 1
    # guard against a silent "no tests to run" pass
    ! grep -q 'no tests to run' "$OUT/go.log"
  }
  stage "Go $(go env GOVERSION) crypto/mlkem ML-KEM-768 (-race)" go.log go_run
  # positive control: the deliberately racy canary MUST be caught, otherwise -race is not working
  go_canary() {
    cd "$ROOT/go" && ! go test -race -tags canary -run TestCanary -count=1 ./... \
      && grep -q 'WARNING: DATA RACE' "$OUT/go-canary.log"
  }
  stage "Go race-detector positive control (canary must be caught)" go-canary.log go_canary
else row "Go" SKIPPED "go not installed"; fi

# ---- Go: Cloudflare CIRCL (second Go library) ----------------------------------
want_circl=${CIRCL:-auto}
if [ "$want_circl" != 0 ] && command -v go >/dev/null && [ -d "$ROOT/go-circl" ]; then
  circl_run() {
    cd "$ROOT/go-circl" && go test -race -count="$RUNS" -run TestSharedKey -v ./... || return 1
    ! grep -q 'no tests to run' "$OUT/go-circl.log"
  }
  stage "Go CIRCL ML-DSA-65 + ML-KEM-768 (-race)" go-circl.log circl_run
elif [ "$want_circl" = 1 ]; then row "Go CIRCL" "**FAIL**" "go or go-circl/ missing"; FAILED=1
else row "Go CIRCL" SKIPPED "disabled or go missing"; fi

# ---- C: liboqs under ThreadSanitizer --------------------------------------------
want_oqs=${LIBOQS:-auto}
if [ "$want_oqs" != 0 ] && [ -f "$LIBOQS_PREFIX/include/oqs/oqs.h" ] && command -v cc >/dev/null; then
  C_FLAGS=(-fsanitize=thread -O1 -g -I"$LIBOQS_PREFIX/include" -L"$LIBOQS_PREFIX/lib" -L"$LIBOQS_PREFIX/lib64")
  oqs_run() {
    cd "$ROOT/c" && cc "${C_FLAGS[@]}" liboqs_shared_key.c -o liboqs_shared_key -loqs -lpthread || return 1
    for _ in $(seq "$RUNS"); do
      TSAN_OPTIONS="halt_on_error=1" ./liboqs_shared_key || return 1
    done
    ! grep -q 'WARNING: ThreadSanitizer' "$OUT/liboqs.log"
  }
  stage "C liboqs ML-DSA-65 + ML-KEM-768 shared object+key (ThreadSanitizer)" liboqs.log oqs_run
  c_canary() {
    cd "$ROOT/c" && cc -fsanitize=thread -O1 -g tsan_canary.c -o tsan_canary -lpthread || return 1
    ./tsan_canary
    grep -q 'WARNING: ThreadSanitizer: data race' "$OUT/c-tsan-canary.log"
  }
  stage "C TSan positive control (canary must be caught)" c-tsan-canary.log c_canary
elif [ "$want_oqs" = 1 ]; then row "C liboqs" "**FAIL**" "liboqs not found under $LIBOQS_PREFIX"; FAILED=1
else row "C liboqs" SKIPPED "liboqs not found under $LIBOQS_PREFIX"; fi

# ---- C: OpenSSL 3.5+ native ML-DSA / ML-KEM under ThreadSanitizer ---------------------
want_ossl=${OPENSSL:-auto}
if [ "$want_ossl" != 0 ] && [ -f "$OPENSSL_PREFIX/include/openssl/evp.h" ] && command -v cc >/dev/null; then
  ossl_build() {
    cd "$ROOT/c" && cc -fsanitize=thread -O1 -g -I"$OPENSSL_PREFIX/include" openssl_shared.c -o openssl_shared \
      "$OPENSSL_PREFIX/lib/libcrypto.a" -lpthread -ldl
  }
  ossl_key() {
    ossl_build || return 1
    for _ in $(seq "$RUNS"); do TSAN_OPTIONS="halt_on_error=1" ./openssl_shared shared-key || return 1; done
    ! grep -q 'WARNING: ThreadSanitizer' "$OUT/openssl-shared-key.log"
  }
  stage "C OpenSSL ML-DSA-65 + ML-KEM-768 shared EVP_PKEY, private ctx (ThreadSanitizer)" openssl-shared-key.log ossl_key
  ossl_locked() {
    cd "$ROOT/c" || return 1
    for _ in $(seq "$RUNS"); do TSAN_OPTIONS="halt_on_error=1" ./openssl_shared locked-ctx || return 1; done
    ! grep -q 'WARNING: ThreadSanitizer' "$OUT/openssl-locked-ctx.log"
  }
  stage "C OpenSSL shared signing ctx under a mutex (misuse control, must be all ok, no races)" openssl-locked-ctx.log ossl_locked
  ossl_misuse() {
    cd "$ROOT/c" || return 1
    for _ in $(seq "$RUNS"); do TSAN_OPTIONS="halt_on_error=0 exitcode=0" ./openssl_shared shared-ctx || return 1; done
    echo "RESULT openssl shared-ctx tsan_reports=$(grep -c 'WARNING: ThreadSanitizer' "$OUT/openssl-shared-ctx.log")"
  }
  stage "C OpenSSL ONE signing ctx shared without lock (misuse characterization)" openssl-shared-ctx.log ossl_misuse
elif [ "$want_ossl" = 1 ]; then row "C OpenSSL" "**FAIL**" "OpenSSL not found under $OPENSSL_PREFIX"; FAILED=1
else row "C OpenSSL" SKIPPED "OpenSSL 3.5+ not found under $OPENSSL_PREFIX"; fi

# ---- Scanner (pqc-share-scan) unit tests -----------------------------------------
if command -v python3 >/dev/null; then
  scan_tests() { cd "$ROOT" && python3 -m unittest discover -s scanner/tests -v; }
  stage "pqc-share-scan unit tests" scanner-tests.log scan_tests
else row "pqc-share-scan tests" SKIPPED "python3 not installed"; fi

# ---- Rust --------------------------------------------------------------------
if command -v cargo >/dev/null; then
  rust_run() {
    cd "$ROOT/rust" && rustc --version && cargo build --release -q || return 1
    for _ in $(seq "$RUNS"); do ./target/release/rust_mlkem_race || return 1; done
  }
  stage "Rust $(rustc --version | cut -d' ' -f2) ml-kem ML-KEM-768 (invariant)" rust.log rust_run

  want_tsan=${RUST_TSAN:-auto}
  if [ "$want_tsan" != 0 ] && rustup run "$NIGHTLY" rustc --version >/dev/null 2>&1; then
    rust_tsan() {
      cd "$ROOT/rust" && rustup run "$NIGHTLY" rustc --version
      local tgt; tgt=$(rustc -vV | sed -n 's/^host: //p')
      RUSTFLAGS="-Zsanitizer=thread" cargo "+$NIGHTLY" build --release -q -Zbuild-std \
        --target "$tgt" --target-dir target/tsan || return 1
      for _ in $(seq "$RUNS"); do
        TSAN_OPTIONS="halt_on_error=1" "target/tsan/$tgt/release/rust_mlkem_race" || return 1
      done
      ! grep -q 'WARNING: ThreadSanitizer' "$OUT/rust-tsan.log"
    }
    stage "Rust ml-kem ML-KEM-768 (ThreadSanitizer, nightly)" rust-tsan.log rust_tsan
    rust_canary() {
      cd "$ROOT/rust" || return 1; local tgt; tgt=$(rustc -vV | sed -n 's/^host: //p')
      RUSTFLAGS="-Zsanitizer=thread" cargo "+$NIGHTLY" build --release -q -Zbuild-std \
        --target "$tgt" --target-dir target/tsan --example canary || return 1
      "target/tsan/$tgt/release/examples/canary"
      grep -q 'WARNING: ThreadSanitizer: data race' "$OUT/rust-tsan-canary.log"
    }
    stage "Rust TSan positive control (canary must be caught)" rust-tsan-canary.log rust_canary
  elif [ "$want_tsan" = 1 ]; then row "Rust TSan" "**FAIL**" "nightly toolchain missing"; FAILED=1
  else row "Rust TSan" SKIPPED "nightly toolchain not installed"; fi
else row "Rust" SKIPPED "cargo not installed"; fi

# ---- Java --------------------------------------------------------------------
CP=$(ls "$ROOT"/java/lib/*.jar "$ROOT"/java/bcprov-*.jar 2>/dev/null | tr '\n' ':')
if command -v javac >/dev/null && [ -n "$CP" ]; then
  BCJAR=$(ls "$ROOT"/java/lib/bcprov-*.jar "$ROOT"/java/bcprov-*.jar 2>/dev/null | head -1)
  mkdir -p "$ROOT/java/build"
  javac -nowarn -d "$ROOT/java/build" -cp "$CP" "$ROOT/java/BcSharedKeyTest.java" >"$OUT/javac.log" 2>&1 \
    || { row "Java compile" "**FAIL**" javac.log; FAILED=1; }
  for alg in $JAVA_ALGS; do
    java_run() {
      java -version; echo "bcprov: $(basename "$BCJAR")"
      for _ in $(seq "$RUNS"); do java -cp "$ROOT/java/build:$CP" BcSharedKeyTest "$alg" || return 1; done
    }
    stage "Java BC $(basename "$BCJAR" .jar | sed 's/.*-//') $alg (invariant)" "java-$alg.log" java_run
  done

  # Misuse study: ONE Signature object shared without a lock, for Bouncy Castle and for the JDK's
  # own provider. "shared" stages record HOW the implementation fails (PASS = harness ran and
  # classified every operation); "locked" is the control and must show only ok.
  mkdir -p "$ROOT/java/misuse-build"
  if javac --release 21 -nowarn -d "$ROOT/java/misuse-build" "$ROOT/java/misuse/SharedSignatureMisuse.java" >"$OUT/javac-misuse.log" 2>&1; then
    targets=("BC|java|$ROOT/java/misuse-build:$CP|BC|${MISUSE_BC_KPG:-ML-DSA-65,ML-DSA}|${MISUSE_BC_SIG:-ML-DSA}")
    want_jdk=${JDK25:-auto}
    if [ "$want_jdk" != 0 ] && [ -x "$JDK25_HOME/bin/java" ]; then
      targets+=("JDK|$JDK25_HOME/bin/java|$ROOT/java/misuse-build|SUN|ML-DSA-65|ML-DSA")
    elif [ "$want_jdk" = 1 ]; then row "JDK 25 provider" "**FAIL**" "no java under $JDK25_HOME"; FAILED=1
    else row "JDK 25 provider" SKIPPED "no java under $JDK25_HOME"; fi
    for tg in "${targets[@]}"; do
      IFS='|' read -r label jbin jcp prov kpg salg <<<"$tg"
      misuse() { # mode size threads runs
        for _ in $(seq "$4"); do
          MISUSE_MSG_BYTES=$2 MISUSE_THREADS=$3 "$jbin" -cp "$jcp" SharedSignatureMisuse "$kpg" "$salg" "$prov" "$1" || return 1
        done
      }
      for size in $MISUSE_SIZES; do
        stage "Java $label $salg shared Signature object, ${size}-byte msgs (misuse characterization)" "misuse-$label-shared-$size.log" misuse shared "$size" 8 "$RUNS"
      done
      stage "Java $label $salg locked Signature object (misuse control, must be all ok)" "misuse-$label-locked.log" misuse locked 65536 8 "$RUNS"
      sweep() {
        for th in $SWEEP_THREADS; do for sz in $SWEEP_SIZES; do misuse shared "$sz" "$th" "$SWEEP_RUNS" || return 1; done; done
      }
      stage "Java $label $salg misuse sweep, threads {$SWEEP_THREADS} x sizes {$SWEEP_SIZES}" "sweep-$label.log" sweep
    done
  else row "Java misuse compile" "**FAIL**" javac-misuse.log; FAILED=1; fi

  # Bank-facing live demo: the same payment-signing service, vulnerable vs fixed, audited.
  mkdir -p "$ROOT/demo/build"
  if javac --release 21 -nowarn -d "$ROOT/demo/build" "$ROOT/demo/BankSigningDemo.java" >"$OUT/javac-demo.log" 2>&1; then
    demo_bc() { DEMO_JSON="$OUT/demo-BC.json" java -cp "$ROOT/demo/build:$CP" BankSigningDemo ML-DSA BC; }
    stage "Bank demo: payment signing service, BC ML-DSA (vulnerable vs fixed)" demo-BC.log demo_bc
    if [ -x "$JDK25_HOME/bin/java" ]; then
      demo_jdk() { DEMO_JSON="$OUT/demo-JDK.json" "$JDK25_HOME/bin/java" -cp "$ROOT/demo/build" BankSigningDemo ML-DSA SUN; }
      stage "Bank demo: payment signing service, JDK ML-DSA (vulnerable vs fixed)" demo-JDK.log demo_jdk
    fi
  else row "Bank demo compile" "**FAIL**" javac-demo.log; FAILED=1; fi

  want_jcs=${JCSTRESS:-auto}
  JCS=$(ls "$ROOT"/java/lib/jcstress-core-*.jar 2>/dev/null | head -1)
  if [ "$want_jcs" != 0 ] && [ -n "$JCS" ]; then
    jcs_run() {
      local b="$ROOT/java/jcstress-build"; rm -rf "$b"; mkdir -p "$b"
      javac -proc:full -nowarn -d "$b" -cp "$CP" "$ROOT"/java/jcstress/*.java || return 1
      cd "$b" && java -cp "$b:$CP" org.openjdk.jcstress.Main -m "$JCSTRESS_MODE" -t BcSharedKey -r "$OUT/jcstress-report" || return 1
      # do not trust the exit code alone: require the summary line to show >=1 passed and nothing else
      grep -qE '[1-9][0-9]* passed, 0 failed, 0 soft errs, 0 hard errs' "$OUT/jcstress.log"
    }
    stage "Java BC ML-DSA shared key (JCStress)" jcstress.log jcs_run
  elif [ "$want_jcs" = 1 ]; then row "JCStress" "**FAIL**" "java/lib/jcstress-core-*.jar missing"; FAILED=1
  else row "JCStress" SKIPPED "jcstress-core jar not in java/lib"; fi
else row "Java" SKIPPED "javac or Bouncy Castle jar missing"; fi

{ echo; echo '## Measured numbers'; echo; echo '```'; cat "$DETAILS"; echo '```'; } >> "$SUMMARY"
echo; echo "Summary: $SUMMARY"
exit $FAILED
