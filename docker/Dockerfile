FROM rust:1.82-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
COPY data/ data/
RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl unzip dnsutils python3 && \
    rm -rf /var/lib/apt/lists/*

RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "amd64" ]; then XRAY_ARCH="64"; \
    elif [ "$ARCH" = "arm64" ]; then XRAY_ARCH="arm64-v8a"; \
    else echo "unsupported arch: $ARCH" && exit 1; fi && \
    curl -sL "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-${XRAY_ARCH}.zip" -o /tmp/xray.zip && \
    cd /tmp && unzip -o xray.zip xray && chmod +x xray && mv xray /usr/local/bin/ && \
    rm -f /tmp/xray.zip /tmp/*.dat /tmp/LICENSE /tmp/README.md

COPY --from=builder /build/target/release/sni-spoof-rs /usr/local/bin/sni-spoof-rs

RUN mkdir -p /etc/sni-spoof-rs /etc/xray

COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV FAKE_SNI=security.vercel.com
ENV PROXY_PORT=1080

EXPOSE 1080

ENTRYPOINT ["/entrypoint.sh"]
