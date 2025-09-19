# Multi-stage Dockerfile for signal-auditor
FROM rust:1-slim-bookworm@sha256:0a694b60da1de10034671091330d628c88af06f9ea0cc87c654d5bc4b6c7e538 AS rust
FROM gcr.io/distroless/cc-debian12@sha256:620d8b11ae800f0dbd7995f89ddc5344ad603269ea98770588b1b07a4a0a6872 AS distroless

# Stage 1: Build environment
FROM rust AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /usr/src/app

# Copy all source files
COPY . ./

# Build the application
RUN cargo build --release --features gcp

# Create runtime directories
RUN mkdir -p /tmp/app/data /tmp/app/certs

# Stage 2: Runtime environment
FROM distroless AS runtime

# Create directories for application data
COPY --from=builder --chown=65532:65532 /tmp/app /app

# Copy the built binary from builder stage
COPY --from=builder /usr/src/app/target/release/signal-auditor /usr/local/bin/signal-auditor

# Copy default configuration
COPY --chown=65532:65532 config.yaml /app/config/config.yaml

# Set working directory
WORKDIR /app

# Switch to non-root user (distroless nonroot)
USER 65532


# Set environment variables
ENV RUST_LOG=info
ENV RUST_BACKTRACE=1

# Health check (adjust based on your application's health endpoint)
# HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
#   CMD curl -f http://localhost:8080/health || exit 1

# Default command
ENTRYPOINT ["/usr/local/bin/signal-auditor", "--config", "/app/config/config.yaml"]
