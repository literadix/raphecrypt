#!/usr/bin/env sh
set -eu

cargo build --release --target wasm32-unknown-unknown --lib

rm -rf dist
mkdir -p dist
cp web/index.html web/styles.css web/app.js dist/
cp target/wasm32-unknown-unknown/release/raphecrypt.wasm dist/
