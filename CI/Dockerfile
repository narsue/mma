# ---- Stage 1: Build ----
FROM docker.io/rust:1.87-slim AS builder

# Install required tools and create workdir
RUN apt-get update && apt-get install -y pkg-config libssl-dev

WORKDIR /app

# Pre-cache dependencies
# COPY Cargo.toml Cargo.lock ./
# COPY benches benches
# RUN mkdir src && echo "fn main() {}" > src/main.rs
# RUN cargo build --release
# RUN rm -r src

# Copy actual source code
COPY Cargo.toml Cargo.toml
COPY Cargo.lock Cargo.lock
COPY src src
COPY benches benches

RUN sed -i 's/ mma/ ci_mma/g' src/db.rs
RUN sed -i 's/127.0.0.1:9042/rustpod:9042/g' src/main.rs


# Build your actual project
RUN cargo build --release

RUN cp /app/target/release/mma /usr/local/bin/app

# ---- Stage 2: Runtime ----
FROM debian:bookworm-slim

# Install SSL certs
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

# Copy built binary from builder
COPY --from=builder /usr/local/bin/app /usr/local/bin/app
COPY templates templates
COPY auth auth
RUN echo "DEV_MODE=1" > .env

EXPOSE 1227

CMD ["/usr/local/bin/app"]
