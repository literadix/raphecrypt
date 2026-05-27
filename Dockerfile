FROM rust:1-alpine AS builder

WORKDIR /app

RUN apk add --no-cache musl-dev
RUN rustup target add wasm32-unknown-unknown x86_64-unknown-linux-musl

COPY Cargo.toml Cargo.lock ./
COPY scripts ./scripts
COPY src ./src
COPY web ./web

RUN cargo build --release --target x86_64-unknown-linux-musl --bin webserver
RUN sh scripts/build-web.sh

FROM scratch

WORKDIR /app

COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/webserver /webserver
COPY --from=builder /app/dist ./dist

EXPOSE 8000

USER 65532:65532

CMD ["/webserver", "--addr", "0.0.0.0:8000", "--root", "/app/dist"]
