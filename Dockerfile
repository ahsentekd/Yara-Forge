# Builder stage
FROM rust:1.75-slim-bookworm AS builder

WORKDIR /usr/src/yara-forge
COPY . .

# Install build dependencies and build the binary
RUN apt-get update && \
    apt-get install -y pkg-config libssl-dev && \
    cargo build --release && \
    ls -la target/release/

# Runtime stage
FROM debian:bookworm-slim

# Install YARA and runtime dependencies
RUN apt-get update && \
    apt-get install -y yara && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Create directories
RUN mkdir -p /app/examples

# Copy the built binary and examples
COPY --from=builder /usr/src/yara-forge/target/release/yara-forge /app/
COPY --from=builder /usr/src/yara-forge/examples /app/examples/

# Set environment variables
ENV RUST_LOG=info

# Create a non-root user and set permissions
RUN useradd -m -u 1000 -U yara && \
    chown -R yara:yara /app

USER yara

# Set the entry point
ENTRYPOINT ["/app/yara-forge"]
