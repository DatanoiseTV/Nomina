# Multi-stage build. The release binary embeds the web UI (rust-embed), so the
# runtime image needs only the binary + CA certificates (for ACME, blocklist
# downloads, and the public-IP lookup).
FROM rust:1-bookworm AS builder
WORKDIR /build
COPY . .
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/nomina /usr/local/bin/nomina
# Minimal default config; mount your own over /etc/nomina or a volume at /data.
RUN mkdir -p /etc/nomina /data \
    && printf 'data_dir = "/data"\nlog = "info"\n\n[dns]\nlisten = ["0.0.0.0:53"]\n\n[web]\nlisten = "0.0.0.0:8053"\n' \
       > /etc/nomina/nomina.toml
VOLUME ["/data"]
# DNS (53), DHCPv4 (67), DHCPv6 server (547), DoT (853), DoH/HTTP3 (443), UI (8053).
EXPOSE 53/udp 53/tcp 67/udp 547/udp 853/tcp 443/tcp 443/udp 8053/tcp
ENTRYPOINT ["/usr/local/bin/nomina"]
CMD ["--config", "/etc/nomina/nomina.toml"]
