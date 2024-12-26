# Builder stage
FROM rust:1.75-slim-bookworm as builder

WORKDIR /usr/src/yara-forge
COPY . .

RUN apt-get update && \
    apt-get install -y pkg-config libssl-dev && \
    cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install YARA
RUN apt-get update && \
    apt-get install -y yara && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the built binary
COPY --from=builder /usr/src/yara-forge/target/release/yara-forge /app/
COPY --from=builder /usr/src/yara-forge/examples /app/examples

# Set environment variables
ENV RUST_LOG=info

# Create a non-root user
RUN useradd -m -u 1000 -U yara
USER yara

ENTRYPOINT ["/app/yara-forge"]
