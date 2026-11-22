# Reproducible environment for the shared-PQC-key concurrency harnesses.
#   docker build -t pqc-harness .
#   docker run --rm -v "$PWD/results:/harness/results" pqc-harness
# Every toolchain and library version is pinned below; change them only via --build-arg.
FROM --platform=linux/amd64 ubuntu:24.04

ARG GO_VERSION=1.24.7
ARG RUST_STABLE=1.97.0
ARG RUST_NIGHTLY=nightly-2026-05-01
ARG LIBOQS_VERSION=0.14.0
ARG OPENSSL_VERSION=3.5.4
# Newest Bouncy Castle release, run beside the pinned 1.81 (java/pom.xml) to show whether the behaviour persists.
ARG BC_LATEST=1.87
# JDK 25 (LTS) supplies the JDK's own ML-DSA provider (JEP 497); "latest" GA build of 25,
# the exact build is printed in every result line (java=...).
ARG JDK25_URL=https://api.adoptium.net/v3/binary/latest/25/ga/linux/x64/jdk/hotspot/normal/eclipse

ENV DEBIAN_FRONTEND=noninteractive \
    PATH=/usr/local/go/bin:/root/.cargo/bin:$PATH \
    RUST_NIGHTLY=${RUST_NIGHTLY} \
    RUST_TSAN=1 \
    JCSTRESS=1 \
    LIBOQS=1 \
    OPENSSL=1 \
    JDK25=1 \
    CIRCL=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl git build-essential cmake ninja-build openjdk-21-jdk-headless maven python3 \
 && rm -rf /var/lib/apt/lists/*

# Go (stdlib crypto/mlkem needs 1.24+)
RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" | tar -C /usr/local -xz \
 && go version

# Rust stable for the invariant run, pinned nightly + rust-src for -Zsanitizer=thread -Zbuild-std
RUN curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain "${RUST_STABLE}" \
 && rustup toolchain install "${RUST_NIGHTLY}" --profile minimal --component rust-src \
 && rustc --version && rustup run "${RUST_NIGHTLY}" rustc --version

# liboqs (pinned tag), built WITH ThreadSanitizer so its internals are instrumented too.
RUN git clone --depth 1 --branch "${LIBOQS_VERSION}" https://github.com/open-quantum-safe/liboqs /tmp/liboqs \
 && cmake -S /tmp/liboqs -B /tmp/liboqs/build -GNinja -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DCMAKE_C_FLAGS="-fsanitize=thread -g" -DOQS_USE_OPENSSL=OFF -DOQS_BUILD_ONLY_LIB=ON \
      -DBUILD_SHARED_LIBS=OFF -DOQS_MINIMAL_BUILD="KEM_ml_kem_768;SIG_ml_dsa_65" \
      -DCMAKE_INSTALL_PREFIX=/opt/liboqs-tsan -DCMAKE_INSTALL_LIBDIR=lib \
 && cmake --build /tmp/liboqs/build && cmake --install /tmp/liboqs/build \
 && rm -rf /tmp/liboqs && ls /opt/liboqs-tsan/lib

# OpenSSL 3.5 (native ML-DSA / ML-KEM), libcrypto only, built WITH ThreadSanitizer.
RUN git clone --depth 1 --branch "openssl-${OPENSSL_VERSION}" https://github.com/openssl/openssl /tmp/openssl \
 && cd /tmp/openssl \
 && ./Configure linux-x86_64 --prefix=/opt/openssl-tsan --libdir=lib no-shared no-tests no-docs \
      -fsanitize=thread -g \
 && make -j"$(nproc)" build_libs && make install_dev \
 && cd / && rm -rf /tmp/openssl && ls /opt/openssl-tsan/lib

RUN mkdir -p /opt/jdk25 \
 && curl -fsSL "${JDK25_URL}" | tar -xz -C /opt/jdk25 --strip-components=1 \
 && /opt/jdk25/bin/java -version

WORKDIR /harness
COPY . .

# Fetch and build everything at image-build time so `docker run` needs no network.
RUN cd java && mvn -q dependency:copy-dependencies -DoutputDirectory=lib && ls lib
RUN cd java && (mvn -q dependency:copy -Dartifact="org.bouncycastle:bcprov-jdk18on:${BC_LATEST}" -DoutputDirectory=lib-bc-latest \
      || echo "bcprov ${BC_LATEST} not available: BC-latest stages will be skipped") && ls lib-bc-latest || true
RUN cd rust && cargo build --release --locked \
 && RUSTFLAGS="-Zsanitizer=thread" cargo "+${RUST_NIGHTLY}" build --release --locked -Zbuild-std \
      --target x86_64-unknown-linux-gnu --target-dir target/tsan --bins --examples
RUN cd go && go vet ./... && go test -race -count=1 -run '^$' ./...
RUN cd go-circl && go mod tidy && go vet ./... && go test -race -count=1 -run '^$' ./...

CMD ["bash", "./run-all.sh"]
