#!/usr/bin/env bash
# Runs every harness, writes logs to results/<timestamp>/ and prints a summary table.
# Env: THREADS (16) OPS (500) RUNS (3) JAVA_ALGS ("ML-DSA") RUST_TSAN (auto|0|1) JCSTRESS (auto|0|1)
#      RUST_NIGHTLY (toolchain name, default "nightly") JCSTRESS_MODE (sanity|quick|default|tough; default "default")
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
OUT="$ROOT/results/$(date -u +%Y%m%dT%H%M%SZ)"; mkdir -p "$OUT"
SUMMARY="$OUT/summary.md"; FAILED=0
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
  if ( "$@" ) >"$OUT/$log" 2>&1; then row "$name" PASS "$log"
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

echo; echo "Summary: $SUMMARY"
exit $FAILED
