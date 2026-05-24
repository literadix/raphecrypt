FROM rust:1-slim AS builder

WORKDIR /app

RUN rustup target add wasm32-unknown-unknown

COPY Cargo.toml Cargo.lock ./
COPY scripts ./scripts
COPY src ./src
COPY web ./web

RUN cargo build --release --bin webserver
RUN sh scripts/build-web.sh

FROM debian:bookworm-slim

WORKDIR /app

COPY --from=builder /app/target/release/webserver /usr/local/bin/webserver
COPY --from=builder /app/dist ./dist

EXPOSE 8000

USER 65532:65532

CMD ["webserver", "--addr", "0.0.0.0:8000", "--root", "/app/dist"]
