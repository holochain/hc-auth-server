FROM rust:1.93-trixie AS builder

# Pick a directory to work in
WORKDIR /usr/src/hc-auth-server

# Copy the package's source code into the container
COPY ["Cargo.toml", "Cargo.lock", "./"]
COPY src ./src
COPY templates ./templates

# Build the auth server
RUN cargo install --path . --bin hc-auth-server

FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

EXPOSE 3000

# Copy the built binary into the runtime container
COPY --from=builder /usr/local/cargo/bin/hc-auth-server /usr/local/bin/

# Run as a dedicated non-root user
RUN useradd --system --no-create-home --shell /bin/false hc-auth-server
USER hc-auth-server

# Run the auth server
CMD ["hc-auth-server"]
