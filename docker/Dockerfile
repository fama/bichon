# ── Stage 1: builder ─────────────────────────────────────────────────────────
FROM rust:slim-bookworm AS builder

RUN apt-get update && apt-get install -y \
    curl \
    git \
    pkg-config \
    && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y nodejs \
    && npm install -g pnpm@9.14 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Cache frontend dependencies separately from source
COPY web/package.json web/pnpm-lock.yaml web/
RUN cd web && pnpm install --frozen-lockfile

# Build frontend first (embedded into Rust binary via rust-embed)
COPY web/ web/
RUN cd web && pnpm run build

# Build Rust
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY about.hbs about.toml ./
RUN cargo build --release

# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM debian:bookworm-slim

ARG CRATE_VERSION
LABEL maintainer="rustmailer <rustmailer.git@gmail.com>"
LABEL version="${CRATE_VERSION}"
LABEL description="Dockerized Bichon service"

RUN apt-get update && apt-get install -y ca-certificates curl && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/bichon-server  /opt/bichon/bichon-server
COPY --from=builder /build/target/release/bichon-cli     /usr/local/bin/bichon-cli
COPY --from=builder /build/target/release/bichon-admin   /usr/local/bin/bichon-admin

RUN chmod +x /opt/bichon/bichon-server \
    && chmod +x /usr/local/bin/bichon-cli \
    && chmod +x /usr/local/bin/bichon-admin \
    && mkdir -p /data

WORKDIR /data
EXPOSE 15630

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -fs http://localhost:15630/api/status || exit 1

CMD ["/opt/bichon/bichon-server"]
