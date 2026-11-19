#!/bin/sh
# Build static musl binary, tarball (keeps +x) and .deb. Usage: ./build.sh
set -eu
cd "$(dirname "$0")"
rustup target add x86_64-unknown-linux-musl
cargo build --release
BIN=target/x86_64-unknown-linux-musl/release/paranoia
mkdir -p dist
cp "$BIN" dist/paranoia && chmod 755 dist/paranoia
tar -C dist -czf dist/paranoia.tar.gz paranoia      # tar keeps mode bits: tar xzf && sudo ./paranoia
(cd dist && sha256sum paranoia paranoia.tar.gz > SHA256SUMS)
command -v cargo-deb >/dev/null || cargo install cargo-deb
cargo deb --no-build --target x86_64-unknown-linux-musl --output dist/
echo "Artifacts in dist/. Host dist/paranoia + SHA256SUMS, then edit URL/SHA in packaging/install.sh"
