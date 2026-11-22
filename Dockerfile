# Reproducible environment for the shared-PQC-key concurrency harnesses.
#   docker build -t pqc-harness .
#   docker run --rm -v "$PWD/results:/harness/results" pqc-harness
# Every toolchain and library version is pinned below; change them only via --build-arg.
FROM --platform=linux/amd64 ubuntu:24.04

ARG GO_VERSION=1.24.7
ARG RUST_STABLE=1.97.0
ARG RUST_NIGHTLY=nightly-2026-05-01

ENV DEBIAN_FRONTEND=noninteractive \
    PATH=/usr/local/go/bin:/root/.cargo/bin:$PATH \
    RUST_NIGHTLY=${RUST_NIGHTLY} \
    RUST_TSAN=1 \
    JCSTRESS=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl build-essential openjdk-21-jdk-headless maven \
 && rm -rf /var/lib/apt/lists/*

# Go (stdlib crypto/mlkem needs 1.24+)
RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" | tar -C /usr/local -xz \
 && go version

# Rust stable for the invariant run, pinned nightly + rust-src for -Zsanitizer=thread -Zbuild-std
RUN curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain "${RUST_STABLE}" \
 && rustup toolchain install "${RUST_NIGHTLY}" --profile minimal --component rust-src \
 && rustc --version && rustup run "${RUST_NIGHTLY}" rustc --version

WORKDIR /harness
COPY . .

# Fetch and build everything at image-build time so `docker run` needs no network.
RUN cd java && mvn -q dependency:copy-dependencies -DoutputDirectory=lib && ls lib
RUN cd rust && cargo build --release --locked \
 && RUSTFLAGS="-Zsanitizer=thread" cargo "+${RUST_NIGHTLY}" build --release --locked -Zbuild-std \
      --target x86_64-unknown-linux-gnu --target-dir target/tsan --bins --examples
RUN cd go && go vet ./... && go test -race -count=1 -run '^$' ./...

CMD ["bash", "./run-all.sh"]
