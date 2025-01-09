# Build stage
FROM rust:latest AS builder
WORKDIR /app

# Copy Cargo files
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src/ src/
COPY static/ static/

# Build the actual application
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim
WORKDIR /app

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/cf-survey /app/cf-survey

EXPOSE 8080

CMD ["./cf-survey"]
