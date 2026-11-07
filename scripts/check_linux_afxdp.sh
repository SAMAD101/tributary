#!/usr/bin/env sh
# Compile-check the Linux-only AF_XDP backend from macOS using Docker.
# libxdp-sys builds libbpf + libxdp from source, so the container needs clang/llvm/libelf.
set -eu
cd "$(dirname "$0")/.."
docker run --rm -v "$PWD":/w -v tributary-cargo-registry:/usr/local/cargo/registry -v tributary-target:/w/target-linux -w /w rust:1-bookworm sh -c '
  apt-get update -qq && apt-get install -yqq --no-install-recommends clang llvm libelf-dev zlib1g-dev pkg-config m4 make libpcap-dev >/dev/null &&
  CARGO_TARGET_DIR=/w/target-linux cargo check -p capture -p tributary --features afxdp,libpcap "$@" 2>&1 | tail -30'
